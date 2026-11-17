import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

import monitor


class SecurityMonitorTests(unittest.TestCase):
    def test_synthetic_logs_fire_each_alert_rule_once(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            flask_log = directory / "backend.log"
            audit_log = directory / "vendor_audit_log.jsonl"
            alerts_log = directory / "alerts.jsonl"
            now = datetime(2026, 11, 17, 16, 20, tzinfo=timezone.utc)
            email = "staff@example.test"
            ip = "198.51.100.17"

            log_lines = []
            for offset in range(5):
                timestamp = (now - timedelta(seconds=offset * 10)).isoformat()
                log_lines.append(
                    f'{timestamp} WARNING AUTH_FAILURE email={json.dumps(email)}'
                )
            for offset in range(20):
                timestamp = (now - timedelta(seconds=offset * 2)).isoformat()
                log_lines.append(
                    f"{timestamp} WARNING HTTP_429 ip={ip} method=GET"
                )
            log_lines.append(
                '198.51.100.23 - - [17/Nov/2026:16:19:30 +0000] '
                '"GET /search?q=%27%20UNION%20SELECT HTTP/1.1" 200 -'
            )
            flask_log.write_text("\n".join(log_lines) + "\n", encoding="utf-8")

            audit_records = [
                {
                    "timestamp": (now - timedelta(minutes=offset)).isoformat(),
                    "vendor_id": "MSP_Admin_01",
                    "action": "Access Patient Database",
                    "decision": "Denied",
                }
                for offset in range(4)
            ]
            audit_log.write_text(
                "".join(
                    json.dumps(record) + "\n" for record in audit_records
                ),
                encoding="utf-8",
            )

            alerts = monitor.monitor_files(
                flask_log, audit_log, alerts_log, now=now
            )

            expected_rules = {
                "failed_login_burst",
                "http_429_burst",
                "sql_metacharacter_url",
                "repeated_denied_privileged_action",
            }
            self.assertEqual(
                [alert["rule"] for alert in alerts].count(
                    "failed_login_burst"
                ),
                1,
            )
            self.assertEqual(
                [alert["rule"] for alert in alerts].count("http_429_burst"),
                1,
            )
            self.assertEqual(
                [alert["rule"] for alert in alerts].count(
                    "sql_metacharacter_url"
                ),
                1,
            )
            self.assertEqual(
                [alert["rule"] for alert in alerts].count(
                    "repeated_denied_privileged_action"
                ),
                1,
            )
            self.assertEqual({alert["rule"] for alert in alerts}, expected_rules)

            saved_alerts = [
                json.loads(line)
                for line in alerts_log.read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(saved_alerts, alerts)
            for alert in alerts:
                self.assertEqual(
                    set(alert), {"timestamp", "rule", "source", "detail"}
                )
                self.assertNotIn("password", alert["detail"].lower())
                self.assertNotIn("token", alert["detail"].lower())


if __name__ == "__main__":
    unittest.main()
