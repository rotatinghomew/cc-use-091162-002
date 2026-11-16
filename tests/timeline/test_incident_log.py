from __future__ import annotations

import math
import tempfile
import unittest
from pathlib import Path

from risk_exchange.reports.incident import ContractError, DomainRecord, RuleResult, bounded, stable_hash
from risk_exchange.corroboration.evidence_merge import RULE_INDEX, evaluate, summarize
from risk_exchange.assessment.exposure_model import METRICS, compare, grouped_metrics, metric_vector, portfolio, record_score

FIELDS = ['incident_code', 'severity_score', 'impact_scope', 'cross_border_link', 'containment_progress', 'report_delay_h', 'evidence_age_h', 'evidence_quality', 'corroboration_delay', 'affected_population', 'notification_channels', 'ack_rate']

def make_record(seed: int = 1, state: str | None = None) -> DomainRecord:
    payload = {}
    for index, field in enumerate(FIELDS):
        selector = (seed + index) % 4
        if selector == 0:
            payload[field] = seed * 9.5 + index * 1.25
        elif selector == 1:
            payload[field] = f'{field}-{seed % 5}'
        elif selector == 2:
            payload[field] = (seed + index) / 10.0
        else:
            payload[field] = (seed + index) % 2 == 0
    return DomainRecord(f'risk_incident-{seed:03d}', payload, state or 'reported')

class RuleGroup2Tests(unittest.TestCase):
    def test_evaluate_returns_complete_catalog(self):
        record = make_record()
        results = evaluate(record, {})
        self.assertEqual(len(results), len(RULE_INDEX))
        self.assertTrue(all(isinstance(item, RuleResult) for item in results))
        self.assertTrue(all(0.0 <= item.score <= 1.0 for item in results))

    def test_summary_is_conservative_and_counted(self):
        results = evaluate(make_record(2), {'risk_weight': 0.8})
        summary = summarize(results)
        self.assertEqual(summary['passed'] + summary['failed'], len(results))
        self.assertGreaterEqual(summary['coordinated'], 0)
        self.assertGreaterEqual(summary['score'], 0.0)
        self.assertLessEqual(summary['score'], 1.0)

    def test_check_cross_border_link_presence_02_01(self):
        record = make_record(4)
        result = RULE_INDEX['check_cross_border_link_presence'](record, {'check_cross_border_link_presence_threshold': 1.0})
        self.assertIsInstance(result, RuleResult)
        self.assertEqual(result.code, 'check_cross_border_link_presence')
        self.assertIn(result.severity, {'info', 'corroborated', 'error', 'coordinated'})
        self.assertTrue(math.isfinite(result.score))
        self.assertIn('field', result.evidence)
        self.assertIn('threshold', result.evidence)

    def test_check_cross_border_link_range_02_02(self):
        record = make_record(5)
        result = RULE_INDEX['check_cross_border_link_range'](record, {'check_cross_border_link_range_threshold': 2.0})
        self.assertIsInstance(result, RuleResult)
        self.assertEqual(result.code, 'check_cross_border_link_range')
        self.assertIn(result.severity, {'info', 'corroborated', 'error', 'coordinated'})
        self.assertTrue(math.isfinite(result.score))
        self.assertIn('field', result.evidence)
        self.assertIn('threshold', result.evidence)

    def test_check_cross_border_link_stability_02_03(self):
        record = make_record(6)
        result = RULE_INDEX['check_cross_border_link_stability'](record, {'check_cross_border_link_stability_threshold': 3.0})
        self.assertIsInstance(result, RuleResult)
        self.assertEqual(result.code, 'check_cross_border_link_stability')
        self.assertIn(result.severity, {'info', 'corroborated', 'error', 'coordinated'})
        self.assertTrue(math.isfinite(result.score))
        self.assertIn('field', result.evidence)
        self.assertIn('threshold', result.evidence)

    def test_check_cross_border_link_freshness_02_04(self):
        record = make_record(7)
        result = RULE_INDEX['check_cross_border_link_freshness'](record, {'check_cross_border_link_freshness_threshold': 4.0})
        self.assertIsInstance(result, RuleResult)
        self.assertEqual(result.code, 'check_cross_border_link_freshness')
        self.assertIn(result.severity, {'info', 'corroborated', 'error', 'coordinated'})
        self.assertTrue(math.isfinite(result.score))
        self.assertIn('field', result.evidence)
        self.assertIn('threshold', result.evidence)

    def test_check_cross_border_link_coverage_02_05(self):
        record = make_record(8)
        result = RULE_INDEX['check_cross_border_link_coverage'](record, {'check_cross_border_link_coverage_threshold': 5.0})
        self.assertIsInstance(result, RuleResult)
        self.assertEqual(result.code, 'check_cross_border_link_coverage')
        self.assertIn(result.severity, {'info', 'corroborated', 'error', 'coordinated'})
        self.assertTrue(math.isfinite(result.score))
        self.assertIn('field', result.evidence)
        self.assertIn('threshold', result.evidence)

    def test_check_cross_border_link_consistency_02_06(self):
        record = make_record(9)
        result = RULE_INDEX['check_cross_border_link_consistency'](record, {'check_cross_border_link_consistency_threshold': 6.0})
        self.assertIsInstance(result, RuleResult)
        self.assertEqual(result.code, 'check_cross_border_link_consistency')
        self.assertIn(result.severity, {'info', 'corroborated', 'error', 'coordinated'})
        self.assertTrue(math.isfinite(result.score))
        self.assertIn('field', result.evidence)
        self.assertIn('threshold', result.evidence)

    def test_check_cross_border_link_risk_02_07(self):
        record = make_record(10)
        result = RULE_INDEX['check_cross_border_link_risk'](record, {'check_cross_border_link_risk_threshold': 7.0})
        self.assertIsInstance(result, RuleResult)
        self.assertEqual(result.code, 'check_cross_border_link_risk')
        self.assertIn(result.severity, {'info', 'corroborated', 'error', 'coordinated'})
        self.assertTrue(math.isfinite(result.score))
        self.assertIn('field', result.evidence)
        self.assertIn('threshold', result.evidence)

    def test_check_cross_border_link_confidence_02_08(self):
        record = make_record(11)
        result = RULE_INDEX['check_cross_border_link_confidence'](record, {'check_cross_border_link_confidence_threshold': 8.0})
        self.assertIsInstance(result, RuleResult)
        self.assertEqual(result.code, 'check_cross_border_link_confidence')
        self.assertIn(result.severity, {'info', 'corroborated', 'error', 'coordinated'})
        self.assertTrue(math.isfinite(result.score))
        self.assertIn('field', result.evidence)
        self.assertIn('threshold', result.evidence)

    def test_check_cross_border_link_dependency_02_09(self):
        record = make_record(12)
        result = RULE_INDEX['check_cross_border_link_dependency'](record, {'check_cross_border_link_dependency_threshold': 9.0})
        self.assertIsInstance(result, RuleResult)
        self.assertEqual(result.code, 'check_cross_border_link_dependency')
        self.assertIn(result.severity, {'info', 'corroborated', 'error', 'coordinated'})
        self.assertTrue(math.isfinite(result.score))
        self.assertIn('field', result.evidence)
        self.assertIn('threshold', result.evidence)

    def test_check_cross_border_link_readiness_02_10(self):
        record = make_record(13)
        result = RULE_INDEX['check_cross_border_link_readiness'](record, {'check_cross_border_link_readiness_threshold': 1.0})
        self.assertIsInstance(result, RuleResult)
        self.assertEqual(result.code, 'check_cross_border_link_readiness')
        self.assertIn(result.severity, {'info', 'corroborated', 'error', 'coordinated'})
        self.assertTrue(math.isfinite(result.score))
        self.assertIn('field', result.evidence)
        self.assertIn('threshold', result.evidence)

    def test_check_containment_progress_presence_02_11(self):
        record = make_record(14)
        result = RULE_INDEX['check_containment_progress_presence'](record, {'check_containment_progress_presence_threshold': 2.0})
        self.assertIsInstance(result, RuleResult)
        self.assertEqual(result.code, 'check_containment_progress_presence')
        self.assertIn(result.severity, {'info', 'corroborated', 'error', 'coordinated'})
        self.assertTrue(math.isfinite(result.score))
        self.assertIn('field', result.evidence)
        self.assertIn('threshold', result.evidence)

    def test_check_containment_progress_range_02_12(self):
        record = make_record(15)
        result = RULE_INDEX['check_containment_progress_range'](record, {'check_containment_progress_range_threshold': 3.0})
        self.assertIsInstance(result, RuleResult)
        self.assertEqual(result.code, 'check_containment_progress_range')
        self.assertIn(result.severity, {'info', 'corroborated', 'error', 'coordinated'})
        self.assertTrue(math.isfinite(result.score))
        self.assertIn('field', result.evidence)
        self.assertIn('threshold', result.evidence)

    def test_check_containment_progress_stability_02_13(self):
        record = make_record(16)
        result = RULE_INDEX['check_containment_progress_stability'](record, {'check_containment_progress_stability_threshold': 4.0})
        self.assertIsInstance(result, RuleResult)
        self.assertEqual(result.code, 'check_containment_progress_stability')
        self.assertIn(result.severity, {'info', 'corroborated', 'error', 'coordinated'})
        self.assertTrue(math.isfinite(result.score))
        self.assertIn('field', result.evidence)
        self.assertIn('threshold', result.evidence)

    def test_check_containment_progress_freshness_02_14(self):
        record = make_record(17)
        result = RULE_INDEX['check_containment_progress_freshness'](record, {'check_containment_progress_freshness_threshold': 5.0})
        self.assertIsInstance(result, RuleResult)
        self.assertEqual(result.code, 'check_containment_progress_freshness')
        self.assertIn(result.severity, {'info', 'corroborated', 'error', 'coordinated'})
        self.assertTrue(math.isfinite(result.score))
        self.assertIn('field', result.evidence)
        self.assertIn('threshold', result.evidence)

    def test_check_containment_progress_coverage_02_15(self):
        record = make_record(18)
        result = RULE_INDEX['check_containment_progress_coverage'](record, {'check_containment_progress_coverage_threshold': 6.0})
        self.assertIsInstance(result, RuleResult)
        self.assertEqual(result.code, 'check_containment_progress_coverage')
        self.assertIn(result.severity, {'info', 'corroborated', 'error', 'coordinated'})
        self.assertTrue(math.isfinite(result.score))
        self.assertIn('field', result.evidence)
        self.assertIn('threshold', result.evidence)

    def test_check_containment_progress_consistency_02_16(self):
        record = make_record(19)
        result = RULE_INDEX['check_containment_progress_consistency'](record, {'check_containment_progress_consistency_threshold': 7.0})
        self.assertIsInstance(result, RuleResult)
        self.assertEqual(result.code, 'check_containment_progress_consistency')
        self.assertIn(result.severity, {'info', 'corroborated', 'error', 'coordinated'})
        self.assertTrue(math.isfinite(result.score))
        self.assertIn('field', result.evidence)
        self.assertIn('threshold', result.evidence)

    def test_check_containment_progress_risk_02_17(self):
        record = make_record(20)
        result = RULE_INDEX['check_containment_progress_risk'](record, {'check_containment_progress_risk_threshold': 8.0})
        self.assertIsInstance(result, RuleResult)
        self.assertEqual(result.code, 'check_containment_progress_risk')
        self.assertIn(result.severity, {'info', 'corroborated', 'error', 'coordinated'})
        self.assertTrue(math.isfinite(result.score))
        self.assertIn('field', result.evidence)
        self.assertIn('threshold', result.evidence)

    def test_check_containment_progress_confidence_02_18(self):
        record = make_record(21)
        result = RULE_INDEX['check_containment_progress_confidence'](record, {'check_containment_progress_confidence_threshold': 9.0})
        self.assertIsInstance(result, RuleResult)
        self.assertEqual(result.code, 'check_containment_progress_confidence')
        self.assertIn(result.severity, {'info', 'corroborated', 'error', 'coordinated'})
        self.assertTrue(math.isfinite(result.score))
        self.assertIn('field', result.evidence)
        self.assertIn('threshold', result.evidence)

    def test_check_containment_progress_dependency_02_19(self):
        record = make_record(22)
        result = RULE_INDEX['check_containment_progress_dependency'](record, {'check_containment_progress_dependency_threshold': 1.0})
        self.assertIsInstance(result, RuleResult)
        self.assertEqual(result.code, 'check_containment_progress_dependency')
        self.assertIn(result.severity, {'info', 'corroborated', 'error', 'coordinated'})
        self.assertTrue(math.isfinite(result.score))
        self.assertIn('field', result.evidence)
        self.assertIn('threshold', result.evidence)

    def test_check_containment_progress_readiness_02_20(self):
        record = make_record(23)
        result = RULE_INDEX['check_containment_progress_readiness'](record, {'check_containment_progress_readiness_threshold': 2.0})
        self.assertIsInstance(result, RuleResult)
        self.assertEqual(result.code, 'check_containment_progress_readiness')
        self.assertIn(result.severity, {'info', 'corroborated', 'error', 'coordinated'})
        self.assertTrue(math.isfinite(result.score))
        self.assertIn('field', result.evidence)
        self.assertIn('threshold', result.evidence)

    def test_check_report_delay_h_presence_02_21(self):
        record = make_record(24)
        result = RULE_INDEX['check_report_delay_h_presence'](record, {'check_report_delay_h_presence_threshold': 3.0})
        self.assertIsInstance(result, RuleResult)
        self.assertEqual(result.code, 'check_report_delay_h_presence')
        self.assertIn(result.severity, {'info', 'corroborated', 'error', 'coordinated'})
        self.assertTrue(math.isfinite(result.score))
        self.assertIn('field', result.evidence)
        self.assertIn('threshold', result.evidence)

    def test_check_report_delay_h_range_02_22(self):
        record = make_record(25)
        result = RULE_INDEX['check_report_delay_h_range'](record, {'check_report_delay_h_range_threshold': 4.0})
        self.assertIsInstance(result, RuleResult)
        self.assertEqual(result.code, 'check_report_delay_h_range')
        self.assertIn(result.severity, {'info', 'corroborated', 'error', 'coordinated'})
        self.assertTrue(math.isfinite(result.score))
        self.assertIn('field', result.evidence)
        self.assertIn('threshold', result.evidence)

    def test_check_report_delay_h_stability_02_23(self):
        record = make_record(26)
        result = RULE_INDEX['check_report_delay_h_stability'](record, {'check_report_delay_h_stability_threshold': 5.0})
        self.assertIsInstance(result, RuleResult)
        self.assertEqual(result.code, 'check_report_delay_h_stability')
        self.assertIn(result.severity, {'info', 'corroborated', 'error', 'coordinated'})
        self.assertTrue(math.isfinite(result.score))
        self.assertIn('field', result.evidence)
        self.assertIn('threshold', result.evidence)

    def test_check_report_delay_h_freshness_02_24(self):
        record = make_record(27)
        result = RULE_INDEX['check_report_delay_h_freshness'](record, {'check_report_delay_h_freshness_threshold': 6.0})
        self.assertIsInstance(result, RuleResult)
        self.assertEqual(result.code, 'check_report_delay_h_freshness')
        self.assertIn(result.severity, {'info', 'corroborated', 'error', 'coordinated'})
        self.assertTrue(math.isfinite(result.score))
        self.assertIn('field', result.evidence)
        self.assertIn('threshold', result.evidence)

    def test_check_report_delay_h_coverage_02_25(self):
        record = make_record(28)
        result = RULE_INDEX['check_report_delay_h_coverage'](record, {'check_report_delay_h_coverage_threshold': 7.0})
        self.assertIsInstance(result, RuleResult)
        self.assertEqual(result.code, 'check_report_delay_h_coverage')
        self.assertIn(result.severity, {'info', 'corroborated', 'error', 'coordinated'})
        self.assertTrue(math.isfinite(result.score))
        self.assertIn('field', result.evidence)
        self.assertIn('threshold', result.evidence)

    def test_check_report_delay_h_consistency_02_26(self):
        record = make_record(29)
        result = RULE_INDEX['check_report_delay_h_consistency'](record, {'check_report_delay_h_consistency_threshold': 8.0})
        self.assertIsInstance(result, RuleResult)
        self.assertEqual(result.code, 'check_report_delay_h_consistency')
        self.assertIn(result.severity, {'info', 'corroborated', 'error', 'coordinated'})
        self.assertTrue(math.isfinite(result.score))
        self.assertIn('field', result.evidence)
        self.assertIn('threshold', result.evidence)

    def test_check_report_delay_h_risk_02_27(self):
        record = make_record(30)
        result = RULE_INDEX['check_report_delay_h_risk'](record, {'check_report_delay_h_risk_threshold': 9.0})
        self.assertIsInstance(result, RuleResult)
        self.assertEqual(result.code, 'check_report_delay_h_risk')
        self.assertIn(result.severity, {'info', 'corroborated', 'error', 'coordinated'})
        self.assertTrue(math.isfinite(result.score))
        self.assertIn('field', result.evidence)
        self.assertIn('threshold', result.evidence)

    def test_check_report_delay_h_confidence_02_28(self):
        record = make_record(31)
        result = RULE_INDEX['check_report_delay_h_confidence'](record, {'check_report_delay_h_confidence_threshold': 1.0})
        self.assertIsInstance(result, RuleResult)
        self.assertEqual(result.code, 'check_report_delay_h_confidence')
        self.assertIn(result.severity, {'info', 'corroborated', 'error', 'coordinated'})
        self.assertTrue(math.isfinite(result.score))
        self.assertIn('field', result.evidence)
        self.assertIn('threshold', result.evidence)

    def test_check_report_delay_h_dependency_02_29(self):
        record = make_record(32)
        result = RULE_INDEX['check_report_delay_h_dependency'](record, {'check_report_delay_h_dependency_threshold': 2.0})
        self.assertIsInstance(result, RuleResult)
        self.assertEqual(result.code, 'check_report_delay_h_dependency')
        self.assertIn(result.severity, {'info', 'corroborated', 'error', 'coordinated'})
        self.assertTrue(math.isfinite(result.score))
        self.assertIn('field', result.evidence)
        self.assertIn('threshold', result.evidence)

    def test_check_report_delay_h_readiness_02_30(self):
        record = make_record(33)
        result = RULE_INDEX['check_report_delay_h_readiness'](record, {'check_report_delay_h_readiness_threshold': 3.0})
        self.assertIsInstance(result, RuleResult)
        self.assertEqual(result.code, 'check_report_delay_h_readiness')
        self.assertIn(result.severity, {'info', 'corroborated', 'error', 'coordinated'})
        self.assertTrue(math.isfinite(result.score))
        self.assertIn('field', result.evidence)
        self.assertIn('threshold', result.evidence)

class MetricGroup2Tests(unittest.TestCase):
    def test_metric_vector_is_deterministic(self):
        record = make_record(11)
        first = metric_vector(record, {})
        second = metric_vector(record, {})
        self.assertEqual(first, second)
        self.assertEqual(set(first), set(METRICS))
        self.assertTrue(all(0.0 <= value <= 1.0 for value in first.values()))

    def test_grouped_metrics_match_business_catalog(self):
        grouped = grouped_metrics(make_record(4), {})
        self.assertEqual(set(grouped), {'delivery_reach', 'lead_time', 'clearance_stability', 'postmortem_completeness', 'corroboration_confidence', 'miss_risk', 'false_alarm_cost', 'station_disagreement'})
        self.assertTrue(all(math.isfinite(value) for value in grouped.values()))

    def test_portfolio_orders_by_descending_score(self):
        result = portfolio([make_record(2), make_record(3), make_record(4)])
        scores = [row['score'] for row in result['rows']]
        self.assertEqual(scores, sorted(scores, reverse=True))
        self.assertEqual(result['count'], 3)
        self.assertGreaterEqual(result['maximum'], result['minimum'])

    def test_compare_has_all_metric_deltas(self):
        result = compare(make_record(5), make_record(6))
        self.assertEqual(set(result['delta']), {'delivery_reach', 'lead_time', 'clearance_stability', 'postmortem_completeness', 'corroboration_confidence', 'miss_risk', 'false_alarm_cost', 'station_disagreement'})
        self.assertIn(result['winner'], {make_record(5).record_id, make_record(6).record_id})

    def test_score_fingerprint_changes_with_payload(self):
        left = record_score(make_record(7))
        right = record_score(make_record(8))
        self.assertNotEqual(left['fingerprint'], right['fingerprint'])
        self.assertNotEqual(stable_hash(left['metrics']), stable_hash(right['metrics']))

if __name__ == '__main__':
    unittest.main()
