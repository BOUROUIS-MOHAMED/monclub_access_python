import datetime as dt
import logging

from app.core.log_meta import build_header_text, scan_log_text
from app.core.logger import HalfDaySizeRotatingFileHandler, set_log_header_provider


def test_scan_counts_levels_and_span():
    result = scan_log_text('2026-11-16 08:00:01,002 | INFO | start\n'
                           '2026-11-16 08:20:01,000 | ERROR | bad\n'
                           '2026-11-16 08:30:01,000 | CRITICAL | bad\n'
                           '2026-11-16 08:59:58,999 | WARNING | late\n')
    assert result == dict(lines=4, errors=2, warnings=1, firstLineAt='2026-11-16T08:00:01',
                          lastLineAt='2026-11-16T08:59:58', appVersions=[])


def test_scan_two_versions_in_order():
    text = '\n'.join(f'2026-11-16 08:00:00,000 | INFO | === MonClub Access {v} · PC ==='
                     for v in ['2.4.0', '2.4.1', '2.4.0', '3', '4', '5', '6'])
    assert scan_log_text(text)['appVersions'] == ['2.4.0', '2.4.1', '3', '4', '5']


def test_scan_ignores_unparsable_lines():
    result = scan_log_text('traceback\n2026-99-99 88:00:00,000 | INFO | invalid\n')
    assert result['lines'] == 2
    assert result['firstLineAt'] is None
    assert result['lastLineAt'] is None


def test_build_header_text():
    assert build_header_text('2.4.1', 'PC Accueil', 'Windows 11 10.0.26100', '64-bit') == (
        'MonClub Access 2.4.1 · PC Accueil · Windows 11 10.0.26100 · 64-bit')
    assert build_header_text('2.4.1', None, 'Windows 11', '32-bit') == 'MonClub Access 2.4.1 · Windows 11 · 32-bit'


def test_header_written_on_new_window(tmp_path):
    now = [dt.datetime(2026, 11, 16, 8, 15)]
    handler = HalfDaySizeRotatingFileHandler(tmp_path, now_func=lambda: now[0])
    handler.setFormatter(logging.Formatter('%(asctime)s | %(levelname)s | %(message)s'))
    logger = logging.getLogger('zkapp')
    logger.addHandler(handler)
    try:
        set_log_header_provider(lambda: 'MonClub Access 2.4.1 · PC Accueil')
        now[0] = now[0].replace(hour=9)
        handler.emit(logging.makeLogRecord({'msg': 'next'}))
        handler._rotate_active_file()
        handler.emit(logging.makeLogRecord({'msg': 'after size rotation'}))
        for path in tmp_path.glob('*.log'):
            assert '| INFO | === MonClub Access 2.4.1 · PC Accueil ===' in path.read_text(encoding='utf-8').splitlines()[0]
        assert len(list(tmp_path.glob('*.log'))) == 3
    finally:
        set_log_header_provider(None)
        logger.removeHandler(handler)
        handler.close()


def test_raising_header_provider_is_ignored(tmp_path):
    handler = HalfDaySizeRotatingFileHandler(tmp_path)
    logger = logging.getLogger('zkapp')
    logger.addHandler(handler)
    try:
        set_log_header_provider(lambda: 1 / 0)
        handler.emit(logging.makeLogRecord({'msg': 'still logged'}))
        assert 'still logged' in next(tmp_path.glob('*.log')).read_text()
    finally:
        set_log_header_provider(None)
        logger.removeHandler(handler)
        handler.close()
