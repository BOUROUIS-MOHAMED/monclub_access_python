import importlib
import json
import os
import shutil
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


_TEST_DATA_ROOT = Path(tempfile.mkdtemp(prefix='monclub_tv_hardening_'))
os.environ['MONCLUB_ACCESS_DATA_ROOT'] = str(_TEST_DATA_ROOT)

import app.core.utils as _utils_mod
import app.core.db as _db_mod
import app.core.tv_local_cache as _tv_mod

utils = importlib.reload(_utils_mod)
db = importlib.reload(_db_mod)
tv = importlib.reload(_tv_mod)


class TvHardeningBaseTest(unittest.TestCase):
    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(_TEST_DATA_ROOT, ignore_errors=True)

    def setUp(self) -> None:
        try:
            if utils.DB_PATH.exists():
                utils.DB_PATH.unlink()
        except Exception:
            pass
        try:
            if utils.CONFIG_PATH.exists():
                utils.CONFIG_PATH.unlink()
        except Exception:
            pass
        try:
            shutil.rmtree(utils.DATA_ROOT / 'tv', ignore_errors=True)
        except Exception:
            pass
        tv._schema_ready = False
        tv.ensure_tv_local_schema()


class TvInvariantEnforcementTests(TvHardeningBaseTest):
    def test_inv_s1_activation_prerequisites(self) -> None:
        tv.assert_tv_inv_s1_activation_prerequisites(
            readiness_state=tv.READINESS_READY,
            manifest_status=tv.MANIFEST_STATUS_COMPLETE,
        )
        with self.assertRaises(AssertionError):
            tv.assert_tv_inv_s1_activation_prerequisites(
                readiness_state=tv.READINESS_NOT_READY,
                manifest_status=tv.MANIFEST_STATUS_COMPLETE,
            )

    def test_inv_s2_failed_activation_preserves_active(self) -> None:
        tv.assert_tv_inv_s2_failed_activation_preserves_active(
            result=tv.ACTIVATION_RESULT_FAILED,
            before_active_id='snap-10',
            before_active_version=10,
            after_active_id='snap-10',
            after_active_version=10,
        )
        with self.assertRaises(AssertionError):
            tv.assert_tv_inv_s2_failed_activation_preserves_active(
                result=tv.ACTIVATION_RESULT_FAILED,
                before_active_id='snap-10',
                before_active_version=10,
                after_active_id='snap-11',
                after_active_version=11,
            )

    def test_inv_d1_valid_file_protection(self) -> None:
        tv.assert_tv_inv_d1_valid_file_protection(
            had_valid_file_before=True,
            replacement_succeeded=False,
            final_asset_state=tv.ASSET_STATE_VALID,
        )
        with self.assertRaises(AssertionError):
            tv.assert_tv_inv_d1_valid_file_protection(
                had_valid_file_before=True,
                replacement_succeeded=False,
                final_asset_state=tv.ASSET_STATE_INVALID_CHECKSUM,
            )

    def test_inv_d2_atomic_promotion(self) -> None:
        tv.assert_tv_inv_d2_atomic_promotion(
            temp_exists_after=False,
            replacement_succeeded=True,
            final_file_exists=True,
        )
        with self.assertRaises(AssertionError):
            tv.assert_tv_inv_d2_atomic_promotion(
                temp_exists_after=True,
                replacement_succeeded=True,
                final_file_exists=True,
            )

    def test_inv_c1_single_flight(self) -> None:
        tv.assert_tv_inv_c1_single_flight(lock_acquired=True)
        with self.assertRaises(AssertionError):
            tv.assert_tv_inv_c1_single_flight(lock_acquired=False)

    def test_inv_o1_deterministic_health_derivation(self) -> None:
        tv.assert_tv_inv_o1_health_derivation(
            health=tv.SCREEN_HEALTH_HEALTHY,
            has_any_signal=True,
            heartbeat_age_sec=30,
            runtime_state=tv.BINDING_RUNTIME_RUNNING,
            player_state=tv.PLAYER_STATE_RENDERING,
            readiness_state=tv.READINESS_READY,
            activation_state=tv.ACTIVATION_STATE_ACTIVE_CURRENT,
            runtime_error_15m=0,
            runtime_warn_15m=0,
            failed_downloads=0,
            proof_expected=False,
            proof_age_sec=None,
        )
        with self.assertRaises(AssertionError):
            tv.assert_tv_inv_o1_health_derivation(
                health=tv.SCREEN_HEALTH_HEALTHY,
                has_any_signal=True,
                heartbeat_age_sec=999,
                runtime_state=tv.BINDING_RUNTIME_RUNNING,
                player_state=tv.PLAYER_STATE_RENDERING,
                readiness_state=tv.READINESS_READY,
                activation_state=tv.ACTIVATION_STATE_ACTIVE_CURRENT,
                runtime_error_15m=0,
                runtime_warn_15m=0,
                failed_downloads=0,
                proof_expected=False,
                proof_age_sec=None,
            )


class TvStartupAndHardeningFlowTests(TvHardeningBaseTest):
    def _create_binding(self, screen_id: int = 1001) -> dict:
        return tv.create_tv_screen_binding(
            screen_id=screen_id,
            screen_name=f'Screen {screen_id}',
            monitor_id=f'monitor-{screen_id}',
            monitor_label=f'Monitor {screen_id}',
            monitor_index=screen_id,
            enabled=True,
            autostart=False,
            fullscreen=True,
        )

    def test_startup_reconciliation_logs_explicit_phases_in_order(self) -> None:
        out = tv.run_tv_startup_reconciliation(
            trigger_source='TEST_SUITE',
            monitors=[],
            correlation_id='corr-startup-phases',
        )
        self.assertTrue(out.get('ok'))

        latest = tv.load_tv_startup_reconciliation_latest()
        self.assertTrue(latest.get('ok'))
        phases = latest.get('phases') or []
        names = [str(p.get('phase_name')) for p in phases]
        self.assertEqual(names, list(tv.STARTUP_PHASES))


    def test_deployment_preflight_returns_structured_result(self) -> None:
        out = tv.run_tv_deployment_preflight(include_query_checks=True)
        self.assertIn(out.get("status"), ("PASS", "WARN", "FAIL"))
        self.assertIn("checks", out)
        checks = out.get("checks") or {}
        self.assertIn("dataRoot", checks)
        self.assertIn("dbOpen", checks)
        self.assertIn("tvSchema", checks)
        self.assertIn("queryChecks", checks)
        blockers = out.get("blockers") or []
        self.assertEqual(len(blockers), 0)

    def test_deployment_preflight_invalid_config_url_blocks(self) -> None:
        bad_cfg = {
            "api_login_url": "http://example.test/login",
            "api_tv_snapshot_latest_url": "not-a-url",
            "api_tv_snapshot_manifest_url": "http://example.test/manifest/{snapshotId}",
        }
        utils.CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        utils.CONFIG_PATH.write_text(json.dumps(bad_cfg), encoding="utf-8")

        out = tv.run_tv_deployment_preflight(include_query_checks=False)
        blockers = out.get("blockers") or []
        blocker_codes = {str(b.get("code")) for b in blockers}
        self.assertIn("TV_PREFLIGHT_CONFIG_URL_INVALID", blocker_codes)

    def test_weak_validation_visibility_in_binding_support_summary(self) -> None:
        binding = self._create_binding(screen_id=1201)
        sid = int(binding['screen_id'])
        snapshot_id = 'snap-weak-1'
        snapshot_version = 1
        media_root = utils.DATA_ROOT / 'tv' / 'media' / str(sid)
        media_root.mkdir(parents=True, exist_ok=True)

        strong_path = media_root / 'asset-strong.mp4'
        weak_path = media_root / 'asset-weak.mp4'
        strong_path.write_bytes(b'strong')
        weak_path.write_bytes(b'weak')

        rows = [
            {
                'mediaAssetId': 'asset-strong',
                'title': 'Strong Asset',
                'mediaType': 'VIDEO',
                'downloadLink': 'https://cdn.example/strong.mp4',
                'checksumSha256': 'abc123',
                'sizeBytes': 6,
                'mimeType': 'video/mp4',
                'durationInSeconds': 10,
                'requiredInTimelines': ['VISUAL'],
                'sourcePresetItemIds': ['item-1'],
                'expectedLocalPath': str(strong_path),
                'localFilePath': str(strong_path),
                'fileExists': True,
                'localSizeBytes': 6,
                'localChecksumSha256': 'abc123',
                'assetState': tv.ASSET_STATE_VALID,
                'stateReason': 'VALID',
                'validationMode': tv.VALIDATION_STRONG,
                'lastCheckedAt': tv.now_iso(),
            },
            {
                'mediaAssetId': 'asset-weak',
                'title': 'Weak Asset',
                'mediaType': 'IMAGE',
                'downloadLink': 'https://cdn.example/weak.jpg',
                'checksumSha256': '',
                'sizeBytes': 0,
                'mimeType': 'image/jpeg',
                'durationInSeconds': 0,
                'requiredInTimelines': ['VISUAL'],
                'sourcePresetItemIds': ['item-2'],
                'expectedLocalPath': str(weak_path),
                'localFilePath': str(weak_path),
                'fileExists': True,
                'localSizeBytes': 4,
                'localChecksumSha256': '',
                'assetState': tv.ASSET_STATE_VALID,
                'stateReason': 'VALID_WEAK_NO_SIZE_OR_CHECKSUM',
                'validationMode': tv.VALIDATION_WEAK,
                'lastCheckedAt': tv.now_iso(),
            },
        ]

        readiness = {
            'readinessState': tv.READINESS_READY,
            'isFullyReady': 1,
            'totalRequiredAssets': 2,
            'readyAssetCount': 2,
            'missingAssetCount': 0,
            'invalidAssetCount': 0,
            'staleAssetCount': 0,
            'computedAt': tv.now_iso(),
        }

        tv._save_snapshot(
            sid,
            snapshot_id,
            snapshot_version,
            {'id': snapshot_id, 'version': snapshot_version},
            {'snapshot': {'id': snapshot_id, 'version': snapshot_version}},
            {'items': []},
            tv.MANIFEST_STATUS_COMPLETE,
            tv.SYNC_STATUS_COMPLETED,
            0,
            None,
            rows,
            readiness,
        )

        summary = tv.load_tv_binding_support_summary(binding_id=int(binding['id']))
        self.assertTrue(summary.get('ok'))
        self.assertEqual(int(summary.get('strongValidatedAssetCount') or 0), 1)
        self.assertEqual(int(summary.get('weakValidatedAssetCount') or 0), 1)
        self.assertEqual(int(summary.get('unknownValidatedAssetCount') or 0), 0)

    def test_retention_and_query_boundary_checks(self) -> None:
        now_dt = datetime(2026, 3, 12, 10, 0, 0, tzinfo=timezone.utc)
        old_dt = now_dt - timedelta(days=45)
        old_iso = old_dt.strftime('%Y-%m-%dT%H:%M:%SZ')
        now_iso = now_dt.strftime('%Y-%m-%dT%H:%M:%SZ')

        with db.get_conn() as conn:
            conn.execute(
                'INSERT INTO tv_proof_event (screen_id, binding_id, snapshot_id, snapshot_version, media_asset_id, timeline_type, item_id, proof_type, status, correlation_id, message, metadata_json, proof_at_utc, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                (1, 1, 'snap-old', 1, 'asset-old', 'VISUAL', 'item-old', 'PLAYED', 'OK', 'corr-retention', 'old proof', '{}', old_iso, old_iso),
            )
            conn.execute(
                'INSERT INTO tv_proof_event (screen_id, binding_id, snapshot_id, snapshot_version, media_asset_id, timeline_type, item_id, proof_type, status, correlation_id, message, metadata_json, proof_at_utc, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                (1, 1, 'snap-now', 2, 'asset-now', 'VISUAL', 'item-now', 'PLAYED', 'OK', 'corr-retention', 'new proof', '{}', now_iso, now_iso),
            )
            conn.execute(
                'INSERT INTO tv_runtime_event (screen_id, binding_id, source, event_type, severity, error_code, message, correlation_id, metadata_json, occurred_at_utc, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                (1, 1, 'SYSTEM', 'TEST_RUNTIME', 'ERROR', 'E1', 'old runtime', 'corr-retention', '{}', old_iso, old_iso),
            )
            conn.execute(
                'INSERT INTO tv_runtime_event (screen_id, binding_id, source, event_type, severity, error_code, message, correlation_id, metadata_json, occurred_at_utc, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                (1, 1, 'SYSTEM', 'TEST_RUNTIME', 'INFO', None, 'new runtime', 'corr-retention', '{}', now_iso, now_iso),
            )
            conn.execute(
                'INSERT INTO tv_support_action_log (binding_id, screen_id, correlation_id, action_type, result, triggered_by, requires_confirmation, message, error_code, metadata_json, started_at, finished_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                (1, 1, 'corr-retention', 'RUN_SYNC', 'SUCCEEDED', 'TEST', 0, 'old support', None, '{}', old_iso, old_iso, old_iso),
            )
            conn.execute(
                'INSERT INTO tv_support_action_log (binding_id, screen_id, correlation_id, action_type, result, triggered_by, requires_confirmation, message, error_code, metadata_json, started_at, finished_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                (1, 1, 'corr-retention', 'RUN_SYNC', 'SUCCEEDED', 'TEST', 0, 'new support', None, '{}', now_iso, now_iso, now_iso),
            )
            conn.execute(
                'INSERT INTO tv_player_event (binding_id, event_type, severity, message, payload_json, created_at) VALUES (?, ?, ?, ?, ?, ?)',
                (1, 'PLAYER_RELOADED', 'INFO', 'old player', '{}', old_iso),
            )
            conn.execute(
                'INSERT INTO tv_player_event (binding_id, event_type, severity, message, payload_json, created_at) VALUES (?, ?, ?, ?, ?, ?)',
                (1, 'PLAYER_RELOADED', 'INFO', 'new player', '{}', now_iso),
            )
            conn.execute(
                'INSERT INTO tv_download_job (batch_id, screen_id, snapshot_id, snapshot_version, media_asset_id, expected_local_path, download_link, state, failure_reason, failure_message, retriable, http_status, attempt_no, max_attempts, bytes_downloaded, bytes_total, trigger_source, queued_at, started_at, finished_at, next_retry_at, updated_at, correlation_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                ('batch-old', 1, 'snap-old', 1, 'asset-old', 'C:/tmp/old.bin', 'https://x/old', 'FAILED', 'TIMEOUT', 'old dl', 1, 504, 1, 1, 1, 1, 'MANUAL', old_iso, old_iso, old_iso, None, old_iso, 'corr-retention'),
            )
            conn.execute(
                'INSERT INTO tv_download_job (batch_id, screen_id, snapshot_id, snapshot_version, media_asset_id, expected_local_path, download_link, state, failure_reason, failure_message, retriable, http_status, attempt_no, max_attempts, bytes_downloaded, bytes_total, trigger_source, queued_at, started_at, finished_at, next_retry_at, updated_at, correlation_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                ('batch-new', 1, 'snap-new', 2, 'asset-new', 'C:/tmp/new.bin', 'https://x/new', 'SUCCEEDED', None, None, 0, 200, 1, 1, 1, 1, 'MANUAL', now_iso, now_iso, now_iso, None, now_iso, 'corr-retention'),
            )
            conn.commit()

        dry = tv.run_tv_retention_maintenance(now_dt=now_dt, dry_run=True, include_query_checks=False)
        self.assertTrue(dry.get('ok'))
        self.assertGreater(int((dry.get('deletedRows') or {}).get('tv_proof_event', 0)), 0)

        live = tv.run_tv_retention_maintenance(now_dt=now_dt, dry_run=False, include_query_checks=True)
        self.assertTrue(live.get('ok'))
        checks = (live.get('queryChecks') or {}).get('checksMs') or {}
        self.assertIn('proof_events', checks)
        self.assertIn('runtime_events', checks)
        self.assertIn('support_logs', checks)
        self.assertIn('player_events', checks)
        self.assertIn('download_jobs', checks)

    def test_correlation_propagation_and_screen_diagnostics(self) -> None:
        binding = self._create_binding(screen_id=1301)
        sid = int(binding['screen_id'])
        bid = int(binding['id'])
        cid = 'corr-audit-1'
        now = tv.now_iso()

        with db.get_conn() as conn:
            conn.execute(
                'INSERT INTO tv_support_action_log (binding_id, screen_id, correlation_id, action_type, result, triggered_by, requires_confirmation, message, error_code, metadata_json, started_at, finished_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                (bid, sid, cid, 'RUN_SYNC', 'SUCCEEDED', 'TEST', 0, 'support action', None, '{}', now, now, now),
            )
            conn.execute(
                'INSERT INTO tv_sync_run_log (screen_id, target_snapshot_version, started_at, finished_at, result, warning_count, error_message, correlation_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                (sid, 1, now, now, 'COMPLETED', 0, None, cid),
            )
            conn.execute(
                'INSERT INTO tv_download_job (batch_id, screen_id, snapshot_id, snapshot_version, media_asset_id, expected_local_path, download_link, state, failure_reason, failure_message, retriable, http_status, attempt_no, max_attempts, bytes_downloaded, bytes_total, trigger_source, queued_at, started_at, finished_at, next_retry_at, updated_at, correlation_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                ('batch-corr', sid, 'snap-corr', 1, 'asset-corr', 'C:/tmp/corr.bin', 'https://x/corr', 'FAILED', 'TIMEOUT', 'dl failed', 1, 504, 1, 1, 1, 1, 'MANUAL', now, now, now, None, now, cid),
            )
            conn.execute(
                'INSERT INTO tv_activation_attempt (screen_id, trigger_source, target_snapshot_id, target_snapshot_version, result, failure_reason, failure_message, precheck_readiness_state, precheck_manifest_status, active_snapshot_id_before, active_snapshot_version_before, started_at, finished_at, correlation_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                (sid, 'MANUAL', 'snap-corr', 1, 'FAILED', 'SNAPSHOT_NOT_READY', 'not ready', 'NOT_READY', 'INCOMPLETE', None, None, now, now, cid),
            )
            conn.execute(
                'INSERT INTO tv_runtime_event (screen_id, binding_id, source, event_type, severity, error_code, message, correlation_id, metadata_json, occurred_at_utc, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                (sid, bid, 'SYSTEM', 'TEST_RUNTIME', 'ERROR', 'E_RUNTIME', 'runtime issue', cid, '{}', now, now),
            )
            conn.execute(
                'INSERT INTO tv_proof_event (screen_id, binding_id, snapshot_id, snapshot_version, media_asset_id, timeline_type, item_id, proof_type, status, correlation_id, message, metadata_json, proof_at_utc, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                (sid, bid, 'snap-corr', 1, 'asset-corr', 'VISUAL', 'item-corr', 'PLAYED', 'OK', cid, 'proof', '{}', now, now),
            )
            conn.commit()

        audit = tv.audit_tv_correlation_propagation(correlation_id=cid)
        self.assertTrue(audit.get('ok'))
        counts = audit.get('counts') or {}
        self.assertGreaterEqual(int(counts.get('supportActions') or 0), 1)
        self.assertGreaterEqual(int(counts.get('downloadJobs') or 0), 1)
        self.assertGreaterEqual(int(counts.get('activationAttempts') or 0), 1)
        self.assertGreaterEqual(int(counts.get('runtimeEvents') or 0), 1)
        self.assertGreaterEqual(int(counts.get('proofEvents') or 0), 1)

        timeline = tv.get_tv_observability_screen_timeline(screen_id=sid, limit=200, offset=0)
        rows = timeline.get('rows') or []
        sources_for_corr = {str(r.get('source')) for r in rows if str(r.get('correlationId') or '') == cid}
        self.assertIn('SUPPORT_ACTION', sources_for_corr)
        self.assertIn('RUNTIME_EVENT', sources_for_corr)
        self.assertIn('ACTIVATION_ATTEMPT', sources_for_corr)
        self.assertIn('PROOF_EVENT', sources_for_corr)


if __name__ == '__main__':
    unittest.main()
