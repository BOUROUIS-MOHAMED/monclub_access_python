import threading
import sys
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from app.core.device_discovery import (
    PULLSDK_ITEMS, normalize_standalone_identity, parse_pullsdk_identity,
    read_pullsdk_identity, read_serial_only,
)
from app.sdk.zk_standalone import ZKStandaloneDevice
from app.core.device_discovery import DiscoveryScheduler, post_discovery_report
from app.core.v2 import lease_gate


@pytest.fixture
def scheduled(monkeypatch):
    from app.core import db
    previous = lease_gate.install(lease_gate.LeaseSnapshot())
    payload = {'id': 14, 'discoveryDue': True, 'serialNumber': None, 'deviceProtocol': 'ZK_PULLSDK'}
    raw = SimpleNamespace(
        get_device_param=Mock(return_value='~SerialNumber=NEW,~DeviceName=C3-400'),
        get_device_data_count=Mock(return_value=7))
    sdk = SimpleNamespace(_sdk=raw)
    worker = SimpleNamespace(request_run_sdk=Mock(side_effect=lambda fn, **kw: {'ok': True, 'result': fn(sdk)}))
    app = SimpleNamespace(_ultra_engine=SimpleNamespace(_workers={14: worker}),
        _log_context=lambda: {'appVersion': '2.4.1', 'pcUuid': 'pc-12345678'})
    kv, posts = {}, []
    clock, day = [600.0], ['2026-11-16']
    monkeypatch.setattr(db, 'get_sync_device_payload', lambda did: dict(payload))
    scheduler = DiscoveryScheduler(app, post_report=lambda did, body: posts.append((did, body)),
        kv_get=kv.get, kv_put=lambda k, v: kv.__setitem__(k, v),
        monotonic=lambda: clock[0], today=lambda: day[0], started_at=0.0)
    yield SimpleNamespace(scheduler=scheduler, app=app, payload=payload, worker=worker,
        sdk=sdk, raw=raw, kv=kv, posts=posts, clock=clock, day=day)
    scheduler.stop()
    lease_gate.install(previous)


def test_waits_10_minutes(scheduled):
    s = scheduled
    s.clock[0] = 599
    assert s.scheduler.tick() == []
    s.worker.request_run_sdk.assert_not_called()
    assert s.kv == {}


def test_due_posts_once_per_day(scheduled):
    s = scheduled
    assert s.scheduler.tick() == [14]
    assert s.scheduler.tick() == []
    body = s.posts[0][1]
    assert body['ok'] is True
    assert body['trigger'] == 'DUE'
    assert body['values']['serialNumber'] == 'NEW'
    assert body['protocol'] == 'ZK_PULLSDK'
    assert body['appVersion'] == '2.4.1'
    assert body['pcUuid'] == 'pc-12345678'
    assert s.worker.request_run_sdk.call_args.kwargs == {'label': 'device_discovery', 'timeout': 20.0}
    s.day[0] = '2026-11-17'
    assert s.scheduler.tick() == [14]


def test_not_due_same_serial_no_post(scheduled):
    s = scheduled
    s.payload.update(discoveryDue=False, serialNumber=' new ')
    assert s.scheduler.tick() == []
    assert not s.posts
    s.raw.get_device_param.assert_called_once_with(items='~SerialNumber', initial_size=65536)
    assert s.kv == {'discovery:last:14': '2026-11-16'}


def test_serial_changed_posts_full_read(scheduled):
    s = scheduled
    s.payload.update(discoveryDue=False, serialNumber='OLD')
    assert s.scheduler.tick() == [14]
    assert s.posts[0][1]['trigger'] == 'SERIAL_CHANGED'
    assert s.posts[0][1]['values']['hwModelName'] == 'C3-400'
    assert s.raw.get_device_param.call_count == 2


def test_no_worker_no_post_no_kv(scheduled):
    s = scheduled
    s.app._ultra_engine._workers.clear()
    lease_gate.install(lease_gate.LeaseSnapshot(mode='LEASED', drive={14: lease_gate.DriveEntry(14, 1, 'DRIVE')}))
    assert s.scheduler.tick() == []
    assert not s.posts and not s.kv


@pytest.mark.parametrize('error,code,text', [
    ('timeout', 'NO_ANSWER', "L'appareil ne répond pas (pas de réponse en 20 secondes)."),
    ('device not connected', 'NOT_CONNECTED', "MonClub Access n'est pas connecté à l'appareil."),
    ('bad SDK', 'SDK_ERROR', "Erreur de l'appareil : bad SDK"),
])
def test_failure_posts_ok_false_with_code(scheduled, error, code, text):
    s = scheduled
    s.worker.request_run_sdk.side_effect = None
    s.worker.request_run_sdk.return_value = {'ok': False, 'error': error}
    assert s.scheduler.tick() == [14]
    body = s.posts[0][1]
    assert body['ok'] is False
    assert body['errorCode'] == code and body['error'] == text
    assert 'values' not in body and 'raw' not in body


def test_reader_never_reads(scheduled):
    lease_gate.install(lease_gate.LeaseSnapshot(mode='LEASED', role='READER'))
    assert scheduled.scheduler.tick() == []
    scheduled.worker.request_run_sdk.assert_not_called()
    assert not scheduled.kv


def test_waiting_lease_never_reads(scheduled):
    lease_gate.install(lease_gate.LeaseSnapshot(mode='LEASED', drive={
        14: lease_gate.DriveEntry(14, 1, 'WAIT_FOR_RELEASE')}))
    assert scheduled.scheduler.tick() == []
    scheduled.worker.request_run_sdk.assert_not_called()


def test_standalone_scheduler_uses_worker(scheduled):
    s = scheduled
    s.payload['deviceProtocol'] = 'ZK_STANDALONE'
    s.sdk.owns_event_source = True
    s.sdk.read_identity = Mock(return_value={'ok': True, 'values': {'serialNumber': 'S'}})
    assert s.scheduler.tick() == [14]
    assert s.posts[0][1]['values'] == {'serialNumber': 'S'}
    assert s.posts[0][1]['raw'] == ''
    s.raw.get_device_param.assert_not_called()


def test_discovery_post_contract_and_network_error():
    response = Mock()
    response.json.return_value = {'accepted': True, 'state': 'SUGGESTION'}
    body = {'ok': True, 'values': {'serialNumber': 'S'}}
    with patch('requests.post', return_value=response) as post:
        assert post_discovery_report('https://example.test', 'gym-token', 14, body) == response.json.return_value
    post.assert_called_once_with('https://example.test/api/v1/gym/access/devices/14/discovery',
        json=body, headers={'Authorization': 'Bearer gym-token'}, timeout=20)
    with patch('requests.post', side_effect=RuntimeError('offline')):
        assert post_discovery_report('https://example.test', 'token', 14, body) == {}


def test_discovery_fields_survive_local_store(tmp_path, monkeypatch):
    from app.core import db
    from app.core.device_sync import DeviceSyncEngine
    monkeypatch.setattr(db, '_DB_PATH', str(tmp_path / 'discovery.db'))
    db.init_db()
    device = {'id': 14, 'discoveryDue': True, 'serialNumber': ' SN1 ', 'accessDataMode': 'ULTRA'}
    with db.get_conn() as conn:
        db._insert_device_row(conn.cursor(), device)
        conn.commit()
    payload = db.get_sync_device_payload(14)
    assert payload['discoveryDue'] is True
    assert payload['serialNumber'] == 'SN1'
    normalized = DeviceSyncEngine(cfg=SimpleNamespace(), logger=None)._normalize_device(payload)
    assert normalized['discoveryDue'] is True
    assert normalized['serialNumber'] == 'SN1'
    normalized = DeviceSyncEngine(cfg=SimpleNamespace(), logger=None)._normalize_device({'id': 15})
    assert normalized['discoveryDue'] is False and normalized['serialNumber'] is None


def test_device_info_standalone_uses_identity(monkeypatch):
    from app.api import local_access_api_v2 as api
    monkeypatch.setattr(api, '_device_protocol_of', lambda did: 'ZK_STANDALONE')
    monkeypatch.setattr(api, '_connect_device', lambda *a: pytest.fail('second connection'))
    sdk = SimpleNamespace(read_identity=Mock(return_value={
        'ok': True, 'values': {'serialNumber': 'S', 'userCapacity': 30000}}))
    worker = SimpleNamespace(request_run_sdk=Mock(side_effect=lambda fn, **kw: {'ok': True, 'result': fn(sdk)}))
    app = SimpleNamespace(_ultra_engine=SimpleNamespace(running=True, _workers={14: worker}))
    sent = []
    ctx = SimpleNamespace(app=app, param_int=lambda name: 14,
        send_json=lambda status, body: sent.append((status, body)))
    api._handle_device_info(ctx)
    assert sent == [(200, {'ok': True, 'params': {'serialNumber': 'S', 'userCapacity': '30000'},
        'counts': {}, 'raw': ''})]
    sdk.read_identity.assert_called_once_with()
    assert worker.request_run_sdk.call_args.kwargs == {'label': 'device_info', 'timeout': 15.0}


def test_device_info_standalone_without_worker_never_connects(monkeypatch):
    from app.api import local_access_api_v2 as api
    monkeypatch.setattr(api, '_device_protocol_of', lambda did: 'ZK_STANDALONE')
    monkeypatch.setattr(api, '_connect_device', lambda *a: pytest.fail('second connection'))
    sent = []
    ctx = SimpleNamespace(app=SimpleNamespace(), param_int=lambda name: 14,
        send_json=lambda status, body: sent.append((status, body)))
    api._handle_device_info(ctx)
    assert sent == [(503, {'ok': False, 'error': 'device not connected'})]


def test_parse_pullsdk_full():
    raw = ('~DeviceName= C3-400 ,~SerialNumber= SN1 ,FirmVer=4.7,~ZKFPVersion=10,'
           'LockCount=4,ReaderCount=8,MAC=00:17:61:12:34:56,~MaxUserCount=30000,'
           '~MaxAttLogCount=100000,~MaxUserFingerCount=3000')
    assert parse_pullsdk_identity(raw, {'user': 412, 'templatev10': 286}) == {
        'hwModelName': 'C3-400', 'serialNumber': 'SN1', 'firmwareVersion': '4.7',
        'fpAlgoVersion': '10', 'lockCount': 4, 'readerCount': 8,
        'macAddress': '00:17:61:12:34:56', 'userCapacity': 30000, 'logCapacity': 100000,
        'fingerprintCapacity': 3000, 'usersUsed': 412, 'fingerprintsUsed': 286,
    }


def test_parse_pullsdk_missing_items_absent():
    assert parse_pullsdk_identity('~DeviceName= ,~MaxUserCount=0,ReaderCount=nope', {}) == {}
    assert parse_pullsdk_identity('', {'user': 0}) == {'usersUsed': 0}
    assert normalize_standalone_identity({'ok': True, 'values': {'faceCapacity': 0,
        'faceAlgoVersion': '', 'serialNumber': ' S ', 'unknown': 1}}) == {'serialNumber': 'S'}


def test_pullsdk_counts_are_independent():
    class Raw:
        def get_device_param(self, **kwargs):
            assert kwargs == dict(items=PULLSDK_ITEMS, initial_size=65536)
            return '~SerialNumber=S'

        def get_device_data_count(self, *, table):
            if table == 'user':
                raise RuntimeError('unsupported')
            return 7

    assert read_pullsdk_identity(Raw()) == {
        'values': {'serialNumber': 'S', 'fingerprintsUsed': 7}, 'raw': '~SerialNumber=S'}


class IdentityTerminal:
    def __init__(self):
        self.thread_ids = []

    def _answer(self, value):
        self.thread_ids.append(threading.get_ident())
        return True, value

    def GetSerialNumber(self, machine, out):
        return self._answer(' SN1 ')

    def GetFirmwareVersion(self, machine, out):
        return self._answer(' 4.7 ')

    def GetProductCode(self, machine, out):
        raise RuntimeError('unsupported')

    def GetSysOption(self, machine, key, out):
        if key == 'ZKFaceVersion':
            raise RuntimeError('unsupported')
        return self._answer({'~DeviceName': 'MB2000', '~ZKFPVersion': '10'}[key])

    def GetPlatform(self, machine, out):
        return self._answer('ZMM')

    def GetDeviceMAC(self, machine, out):
        return self._answer('00:17:61:12:34:56')

    def GetDeviceStatus(self, machine, index, out):
        return self._answer({2: 412, 3: 286, 7: 3000, 8: 30000, 9: 100000,
                             21: 5, 22: 500}[index])


def _driver(fake):
    driver = ZKStandaloneDevice({'id': 14, 'ipAddress': '192.0.2.1'})
    driver._com_factory = lambda: fake
    driver._co_init = lambda: None
    driver._co_uninit = lambda: None
    driver._pump = lambda: None
    driver._do_connect = lambda zk: True
    driver._pump_events_once = lambda zk: None
    return driver


def test_standalone_identity_partial():
    fake = IdentityTerminal()
    driver = _driver(fake)
    try:
        assert driver.connect()
        values = driver.read_identity()['values']
        assert values == {'serialNumber': 'SN1', 'firmwareVersion': '4.7', 'hwModelName': 'MB2000',
            'hwPlatform': 'ZMM', 'fpAlgoVersion': '10', 'macAddress': '00:17:61:12:34:56',
            'usersUsed': 412, 'fingerprintsUsed': 286, 'facesUsed': 5,
            'userCapacity': 30000, 'fingerprintCapacity': 3000, 'logCapacity': 100000, 'faceCapacity': 500}
        assert set(fake.thread_ids) == {driver._sta_thread.ident}
        assert threading.get_ident() not in fake.thread_ids
    finally:
        driver.disconnect()


def test_standalone_not_connected():
    driver = _driver(IdentityTerminal())
    try:
        assert driver.read_identity() == {'ok': False, 'error': 'not connected'}
    finally:
        driver.disconnect()


def test_standalone_identity_byref_shape(monkeypatch):
    monkeypatch.setitem(sys.modules, 'pythoncom', SimpleNamespace(VT_BYREF=0x4000, VT_BSTR=8, VT_I4=3))
    monkeypatch.setitem(sys.modules, 'pywintypes', SimpleNamespace())
    monkeypatch.setitem(sys.modules, 'win32com', SimpleNamespace())
    monkeypatch.setitem(sys.modules, 'win32com.client', SimpleNamespace(
        VARIANT=lambda kind, value: SimpleNamespace(value=value)))

    class ByrefTerminal(IdentityTerminal):
        def _set(self, out, value):
            out.value = value
            return True

        def GetSerialNumber(self, machine, out):
            return self._set(out, 'SN2')

        def GetFirmwareVersion(self, machine, out):
            return self._set(out, '5.0')

        def GetSysOption(self, machine, key, out):
            return self._set(out, {'~DeviceName': 'MB2000', '~ZKFPVersion': '10', 'ZKFaceVersion': '7'}[key])

        def GetPlatform(self, machine, out):
            return self._set(out, 'ZMM')

        def GetDeviceMAC(self, machine, out):
            return self._set(out, 'AA:BB:CC:DD:EE:FF')

        def GetDeviceStatus(self, machine, index, out):
            return self._set(out, 10)

    driver = _driver(ByrefTerminal())
    try:
        assert driver.connect()
        values = driver.read_identity()['values']
        assert values['serialNumber'] == 'SN2'
        assert values['hwPlatform'] == 'ZMM'
        assert values['fpAlgoVersion'] == '10'
        # Status counters keep the field-proven _read_status_index unchanged (tuple shape);
        # a terminal that only answers the ByRef shape gives no capacity, never a guess.
        assert 'userCapacity' not in values
    finally:
        driver.disconnect()


@pytest.mark.parametrize('answer,expected', [((True, 30000), 30000), ((False, 0), None)])
def test_status_tuple_return_with_byref_argument(monkeypatch, answer, expected):
    monkeypatch.setitem(sys.modules, 'pythoncom', SimpleNamespace(VT_BYREF=0x4000, VT_I4=3))
    monkeypatch.setitem(sys.modules, 'win32com', SimpleNamespace())
    monkeypatch.setitem(sys.modules, 'win32com.client', SimpleNamespace(
        VARIANT=lambda kind, value: SimpleNamespace(value=value)))
    fake = SimpleNamespace(GetDeviceStatus=lambda *args: answer)
    assert ZKStandaloneDevice._read_status_index(fake, 8) == expected
