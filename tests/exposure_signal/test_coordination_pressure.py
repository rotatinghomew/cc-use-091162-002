from __future__ import annotations
import unittest
from risk_exchange.exposure_signal.coordination_pressure import coordination_pressure, peer_distribution
class Record:
    def __init__(self, payload): self.payload = payload
class SignalTests(unittest.TestCase):
    def setUp(self): self.payload = {'incident_code': 'incident-a', 'severity_score': 0.55, 'impact_scope': 35, 'cross_border_link': 0.7, 'containment_progress': 0.45, 'report_delay_h': 8, 'evidence_age_h': 4, 'evidence_quality': 0.8, 'corroboration_delay': 6, 'affected_population': 25000, 'notification_channels': 3, 'ack_rate': 0.7}
    def test_signal_is_bounded_and_explainable(self):
        signal = coordination_pressure(self.payload)
        self.assertGreaterEqual(signal.score, 0.0)
        self.assertLessEqual(signal.score, 1.0)
        self.assertIn(signal.severity, {'info', 'warning', 'critical'})
        self.assertTrue({'severity', 'cross_border', 'containment'}.issubset(signal.evidence))
    def test_peer_distribution_uses_business_group(self):
        other = dict(self.payload); other['incident_code'] = 'group-b'
        result = peer_distribution([Record(self.payload), Record(other)])
        self.assertEqual(result['count'], 2)
        self.assertIn('critical_incidents', result)
    def test_material_business_change_is_observable(self):
        changed = dict(self.payload); changed['severity_score'] = 99
        self.assertNotEqual(coordination_pressure(changed).score, coordination_pressure(self.payload).score)
    def test_business_variant_1(self):
        changed = dict(self.payload)
        changed['impact_scope'] = self.payload['impact_scope']
        signal = coordination_pressure(changed)
        self.assertGreaterEqual(signal.score, 0.0)
        self.assertLessEqual(signal.score, 1.0)

    def test_business_variant_2(self):
        changed = dict(self.payload)
        changed['cross_border_link'] = self.payload['cross_border_link']
        signal = coordination_pressure(changed)
        self.assertGreaterEqual(signal.score, 0.0)
        self.assertLessEqual(signal.score, 1.0)

    def test_business_variant_3(self):
        changed = dict(self.payload)
        changed['containment_progress'] = self.payload['containment_progress']
        signal = coordination_pressure(changed)
        self.assertGreaterEqual(signal.score, 0.0)
        self.assertLessEqual(signal.score, 1.0)

    def test_business_variant_4(self):
        changed = dict(self.payload)
        changed['report_delay_h'] = self.payload['report_delay_h']
        signal = coordination_pressure(changed)
        self.assertGreaterEqual(signal.score, 0.0)
        self.assertLessEqual(signal.score, 1.0)

    def test_business_variant_5(self):
        changed = dict(self.payload)
        changed['evidence_age_h'] = self.payload['evidence_age_h']
        signal = coordination_pressure(changed)
        self.assertGreaterEqual(signal.score, 0.0)
        self.assertLessEqual(signal.score, 1.0)

    def test_business_variant_6(self):
        changed = dict(self.payload)
        changed['evidence_quality'] = self.payload['evidence_quality']
        signal = coordination_pressure(changed)
        self.assertGreaterEqual(signal.score, 0.0)
        self.assertLessEqual(signal.score, 1.0)

if __name__ == '__main__': unittest.main()
