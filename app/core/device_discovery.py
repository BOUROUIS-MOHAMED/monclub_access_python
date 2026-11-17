"""Read device identity through an existing worker connection."""
from __future__ import annotations

import re
import logging
import threading
import time
from datetime import date, datetime

_log = logging.getLogger(__name__)

PULLSDK_ITEMS = "~DeviceName,~SerialNumber,FirmVer,~ZKFPVersion,LockCount,ReaderCount,MAC,~MaxUserCount,~MaxAttLogCount,~MaxUserFingerCount"

_PULL_FIELDS = dict(zip(PULLSDK_ITEMS.split(','), (
    'hwModelName', 'serialNumber', 'firmwareVersion', 'fpAlgoVersion', 'lockCount',
    'readerCount', 'macAddress', 'userCapacity', 'logCapacity', 'fingerprintCapacity',
)))
_STRING_FIELDS = ('hwModelName', 'serialNumber', 'firmwareVersion', 'hwPlatform',
                  'fpAlgoVersion', 'faceAlgoVersion', 'macAddress')
_NUMBER_FIELDS = ('userCapacity', 'fingerprintCapacity', 'faceCapacity', 'logCapacity',
                  'lockCount', 'readerCount', 'usersUsed', 'fingerprintsUsed', 'facesUsed')


def _normalize_values(values: dict) -> dict:
    out = {}
    for key in _STRING_FIELDS:
        value = values.get(key)
        if value is not None and str(value).strip():
            out[key] = str(value).strip()
    for key in _NUMBER_FIELDS:
        value = values.get(key)
        if value is None or isinstance(value, bool):
            continue
        try:
            number = int(value)
        except (TypeError, ValueError):
            continue
        if number > 0 or (key.endswith('Used') and number == 0):
            out[key] = number
    return out


def parse_pullsdk_identity(raw: str, counts: dict) -> dict:
    values = {}
    for item in re.split(r'[,\r\n]+', raw):
        key, sep, value = item.partition('=')
        field = _PULL_FIELDS.get(key.strip())
        if sep and field:
            values[field] = value.strip()
    values.update(usersUsed=counts.get('user'), fingerprintsUsed=counts.get('templatev10'))
    return _normalize_values(values)


def read_pullsdk_identity(raw_sdk) -> dict:
    raw = raw_sdk.get_device_param(items=PULLSDK_ITEMS, initial_size=65536)
    counts = {}
    for table in ('user', 'templatev10'):
        try:
            counts[table] = raw_sdk.get_device_data_count(table=table)
        except Exception:
            pass
    return {'values': parse_pullsdk_identity(raw, counts), 'raw': raw[:8000]}


def normalize_standalone_identity(d: dict) -> dict:
    return _normalize_values(d.get('values') or {})


def read_serial_only(sdk) -> str | None:
    if getattr(sdk, 'owns_event_source', False):
        result = sdk.read_identity()
        if not result.get('ok'):
            raise RuntimeError(result.get('error') or 'identity read failed')
        return normalize_standalone_identity(result).get('serialNumber')
    raw_sdk = getattr(sdk, '_sdk', sdk)
    raw = raw_sdk.get_device_param(items='~SerialNumber', initial_size=65536)
    return parse_pullsdk_identity(raw, {}).get('serialNumber')


def post_discovery_report(base_url, token, device_id, body) -> dict:
    try:
        import requests
        response = requests.post(
            f'{base_url}/api/v1/gym/access/devices/{device_id}/discovery',
            json=body, headers={'Authorization': f'Bearer {token}'}, timeout=20)
        response.raise_for_status()
        return response.json()
    except Exception as exc:
        _log.warning('Device discovery report failed for %s: %s', device_id, exc)
        return {}


class DiscoveryScheduler:
    def __init__(self, app, *, post_report, kv_get, kv_put, monotonic=time.monotonic,
                 today=lambda: date.today().isoformat(), started_at=None):
        self.app = app
        self.post_report = post_report
        self.kv_get = kv_get
        self.kv_put = kv_put
        self.monotonic = monotonic
        self.today = today
        self.started_at = monotonic() if started_at is None else started_at
        self._stop = threading.Event()
        self._thread = None

    def start(self):
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name='device-discovery', daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _run(self):
        while not self._stop.is_set():
            try:
                self.tick()
            except Exception as exc:
                _log.warning('Device discovery tick failed: %s', exc)
            self._stop.wait(60)

    @staticmethod
    def _on_worker(worker, fn):
        result = worker.request_run_sdk(fn, label='device_discovery', timeout=20.0)
        if not result.get('ok'):
            raise RuntimeError(result.get('error') or 'read failed')
        result = result.get('result')
        if isinstance(result, dict) and result.get('ok') is False:
            raise RuntimeError(result.get('error') or 'read failed')
        return result

    @staticmethod
    def _read_identity(sdk):
        if getattr(sdk, 'owns_event_source', False):
            return sdk.read_identity()
        return read_pullsdk_identity(getattr(sdk, '_sdk', sdk))

    def _body(self, payload, trigger):
        context = {}
        try:
            context = self.app._log_context()
        except Exception:
            pass
        from app.sdk.device_driver import resolve_device_protocol
        return {
            'readAt': datetime.now().isoformat(timespec='seconds'),
            'appVersion': context.get('appVersion') or getattr(self.app, '_boot_version', 'unknown'),
            'pcUuid': context.get('pcUuid'),
            'protocol': resolve_device_protocol(payload).value,
            'trigger': trigger,
        }

    @staticmethod
    def _failure(error):
        text = str(error)
        lowered = text.lower()
        if 'timeout' in lowered or 'timed out' in lowered:
            return {'ok': False, 'errorCode': 'NO_ANSWER',
                    'error': "L'appareil ne répond pas (pas de réponse en 20 secondes)."}
        if 'not connected' in lowered:
            return {'ok': False, 'errorCode': 'NOT_CONNECTED',
                    'error': "MonClub Access n'est pas connecté à l'appareil."}
        return {'ok': False, 'errorCode': 'SDK_ERROR', 'error': f"Erreur de l'appareil : {text[:200]}"}

    def tick(self) -> list[int]:
        if self.monotonic() - self.started_at < 600 or self._stop.is_set():
            return []
        from app.core.db import get_sync_device_payload
        from app.core.v2 import lease_gate

        day = self.today()
        engine = getattr(self.app, '_ultra_engine', None)
        workers = dict(getattr(engine, '_workers', {}) or {})
        snapshot = lease_gate.current()
        ids = (sorted(d for d, entry in snapshot.drive.items() if entry.state == 'DRIVE')
               if snapshot.mode == lease_gate.MODE_LEASED else sorted(workers))
        reported = []
        for did in ids:
            if self._stop.is_set():
                break
            key = f'discovery:last:{did}'
            if self.kv_get(key) == day:
                continue
            worker = workers.get(did)
            if worker is None:
                continue
            payload = get_sync_device_payload(did) or {}
            trigger = 'DUE' if payload.get('discoveryDue') else 'SERIAL_CHANGED'
            try:
                if not payload.get('discoveryDue'):
                    serial = str(payload.get('serialNumber') or '').strip()
                    if not serial:
                        continue
                    try:
                        read = self._on_worker(worker, read_serial_only)
                    except Exception as exc:
                        _log.warning('Device discovery serial read failed for %s: %s', did, exc)
                        continue
                    if not read or str(read).strip().casefold() == serial.casefold():
                        continue
                body = self._body(payload, trigger)
                try:
                    result = self._on_worker(worker, self._read_identity)
                    body.update(ok=True, values=_normalize_values(result.get('values') or {}),
                                raw=str(result.get('raw') or '')[:8000])
                except Exception as exc:
                    body.update(self._failure(exc))
                self.post_report(did, body)
                reported.append(did)
            finally:
                self.kv_put(key, day)
        return reported
