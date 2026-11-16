from __future__ import annotations

import unittest
from risk_exchange.reports.incident import DomainRecord
from risk_exchange.corroboration.lateness import alert_level, delivery_risk, event_lateness, station_signal


class WatermarkTests(unittest.TestCase):
    def record(self, key, water=5, age=5):
        return DomainRecord(key, {"incident_code": key, "severity_score": 120, "impact_scope": water, "cross_border_link": 900,
            "containment_progress": .4, "report_delay_h": 24, "evidence_age_h": age, "evidence_quality": .9,
            "corroboration_delay": 2, "affected_population": 20000, "notification_channels": 3, "ack_rate": .8})

    def test_lateness_and_hysteresis(self):
        result = event_lateness([self.record("a"), self.record("b", water=12)])
        self.assertGreater(result["risk"], 0.0)
        self.assertIn(alert_level(result), {"reported", "triaged", "corroborated", "coordinated"})
        self.assertGreater(station_signal(self.record("a")).freshness, station_signal(self.record("b", age=170)).freshness)

    def test_delivery_risk_is_bounded(self):
        self.assertTrue(0.0 <= delivery_risk(self.record("a")) <= 1.0)
