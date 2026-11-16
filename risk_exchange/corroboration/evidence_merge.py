from __future__ import annotations

import math
from typing import Any, Callable, Mapping

from risk_exchange.reports.incident import DomainRecord, RuleResult, bounded, finite_number, normalized_text

RuleFunction = Callable[[DomainRecord, Mapping[str, Any]], RuleResult]

def _number(record: DomainRecord, field: str) -> float:
    value = record.payload.get(field)
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    if isinstance(value, (int, float)):
        return finite_number(value)
    text = normalized_text(value)
    if not text:
        return 0.0
    try:
        return finite_number(text)
    except ValueError:
        return float(sum(ord(ch) for ch in text) % 101)

def _context_number(context: Mapping[str, Any], key: str, default: float) -> float:
    try:
        return finite_number(context.get(key, default))
    except ValueError:
        return default

def _result(code: str, value: float, threshold: float, higher_is_better: bool, message: str, evidence: dict[str, Any]) -> RuleResult:
    distance = (value - threshold) if higher_is_better else (threshold - value)
    passed = distance >= 0
    scale = max(1.0, abs(threshold))
    score = bounded(0.5 + distance / (2.0 * scale))
    severity = 'info' if passed else ('coordinated' if score < 0.2 else 'error')
    return RuleResult(code, passed, score, severity, message, evidence)

def check_incident_code_presence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'incident_code')
    weight = _context_number(context, 'presence_weight', 1.1)
    adjusted = raw * weight + 0.17
    threshold = _context_number(context, 'check_incident_code_presence_threshold', 10.333)
    return _result('check_incident_code_presence', adjusted, threshold, True, 'validates incident_code presence',
                   {'field': 'incident_code', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_incident_code_range(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'incident_code')
    weight = _context_number(context, 'range_weight', 1.2)
    adjusted = raw * weight + 0.34
    threshold = _context_number(context, 'check_incident_code_range_threshold', 12.667)
    return _result('check_incident_code_range', adjusted, threshold, True, 'validates incident_code range',
                   {'field': 'incident_code', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_incident_code_stability(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'incident_code')
    weight = _context_number(context, 'stability_weight', 1.3)
    adjusted = raw * weight + 0.51
    threshold = _context_number(context, 'check_incident_code_stability_threshold', 15.0)
    return _result('check_incident_code_stability', adjusted, threshold, False, 'validates incident_code stability',
                   {'field': 'incident_code', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_incident_code_freshness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'incident_code')
    weight = _context_number(context, 'freshness_weight', 1.4)
    adjusted = raw * weight + 0.68
    threshold = _context_number(context, 'check_incident_code_freshness_threshold', 17.333)
    return _result('check_incident_code_freshness', adjusted, threshold, True, 'validates incident_code freshness',
                   {'field': 'incident_code', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_incident_code_coverage(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'incident_code')
    weight = _context_number(context, 'coverage_weight', 1.0)
    adjusted = raw * weight + 0.8500000000000001
    threshold = _context_number(context, 'check_incident_code_coverage_threshold', 19.667)
    return _result('check_incident_code_coverage', adjusted, threshold, True, 'validates incident_code coverage',
                   {'field': 'incident_code', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_incident_code_consistency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'incident_code')
    weight = _context_number(context, 'consistency_weight', 1.1)
    adjusted = raw * weight + 1.02
    threshold = _context_number(context, 'check_incident_code_consistency_threshold', 22.0)
    return _result('check_incident_code_consistency', adjusted, threshold, False, 'validates incident_code consistency',
                   {'field': 'incident_code', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_incident_code_risk(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'incident_code')
    weight = _context_number(context, 'risk_weight', 1.2)
    adjusted = raw * weight + 1.1900000000000002
    threshold = _context_number(context, 'check_incident_code_risk_threshold', 24.333)
    return _result('check_incident_code_risk', adjusted, threshold, True, 'validates incident_code risk',
                   {'field': 'incident_code', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_incident_code_confidence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'incident_code')
    weight = _context_number(context, 'confidence_weight', 1.3)
    adjusted = raw * weight + 1.36
    threshold = _context_number(context, 'check_incident_code_confidence_threshold', 26.667)
    return _result('check_incident_code_confidence', adjusted, threshold, True, 'validates incident_code confidence',
                   {'field': 'incident_code', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_incident_code_dependency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'incident_code')
    weight = _context_number(context, 'dependency_weight', 1.4)
    adjusted = raw * weight + 1.53
    threshold = _context_number(context, 'check_incident_code_dependency_threshold', 29.0)
    return _result('check_incident_code_dependency', adjusted, threshold, False, 'validates incident_code dependency',
                   {'field': 'incident_code', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_incident_code_readiness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'incident_code')
    weight = _context_number(context, 'readiness_weight', 1.0)
    adjusted = raw * weight + 1.7000000000000002
    threshold = _context_number(context, 'check_incident_code_readiness_threshold', 31.333)
    return _result('check_incident_code_readiness', adjusted, threshold, True, 'validates incident_code readiness',
                   {'field': 'incident_code', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_severity_score_presence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'severity_score')
    weight = _context_number(context, 'presence_weight', 1.1)
    adjusted = raw * weight + 0.0
    threshold = _context_number(context, 'check_severity_score_presence_threshold', 9.333)
    return _result('check_severity_score_presence', adjusted, threshold, True, 'validates severity_score presence',
                   {'field': 'severity_score', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_severity_score_range(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'severity_score')
    weight = _context_number(context, 'range_weight', 1.2)
    adjusted = raw * weight + 0.17
    threshold = _context_number(context, 'check_severity_score_range_threshold', 11.667)
    return _result('check_severity_score_range', adjusted, threshold, False, 'validates severity_score range',
                   {'field': 'severity_score', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_severity_score_stability(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'severity_score')
    weight = _context_number(context, 'stability_weight', 1.3)
    adjusted = raw * weight + 0.34
    threshold = _context_number(context, 'check_severity_score_stability_threshold', 14.0)
    return _result('check_severity_score_stability', adjusted, threshold, True, 'validates severity_score stability',
                   {'field': 'severity_score', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_severity_score_freshness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'severity_score')
    weight = _context_number(context, 'freshness_weight', 1.4)
    adjusted = raw * weight + 0.51
    threshold = _context_number(context, 'check_severity_score_freshness_threshold', 16.333)
    return _result('check_severity_score_freshness', adjusted, threshold, True, 'validates severity_score freshness',
                   {'field': 'severity_score', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_severity_score_coverage(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'severity_score')
    weight = _context_number(context, 'coverage_weight', 1.0)
    adjusted = raw * weight + 0.68
    threshold = _context_number(context, 'check_severity_score_coverage_threshold', 18.667)
    return _result('check_severity_score_coverage', adjusted, threshold, False, 'validates severity_score coverage',
                   {'field': 'severity_score', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_severity_score_consistency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'severity_score')
    weight = _context_number(context, 'consistency_weight', 1.1)
    adjusted = raw * weight + 0.8500000000000001
    threshold = _context_number(context, 'check_severity_score_consistency_threshold', 21.0)
    return _result('check_severity_score_consistency', adjusted, threshold, True, 'validates severity_score consistency',
                   {'field': 'severity_score', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_severity_score_risk(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'severity_score')
    weight = _context_number(context, 'risk_weight', 1.2)
    adjusted = raw * weight + 1.02
    threshold = _context_number(context, 'check_severity_score_risk_threshold', 23.333)
    return _result('check_severity_score_risk', adjusted, threshold, True, 'validates severity_score risk',
                   {'field': 'severity_score', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_severity_score_confidence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'severity_score')
    weight = _context_number(context, 'confidence_weight', 1.3)
    adjusted = raw * weight + 1.1900000000000002
    threshold = _context_number(context, 'check_severity_score_confidence_threshold', 25.667)
    return _result('check_severity_score_confidence', adjusted, threshold, False, 'validates severity_score confidence',
                   {'field': 'severity_score', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_severity_score_dependency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'severity_score')
    weight = _context_number(context, 'dependency_weight', 1.4)
    adjusted = raw * weight + 1.36
    threshold = _context_number(context, 'check_severity_score_dependency_threshold', 28.0)
    return _result('check_severity_score_dependency', adjusted, threshold, True, 'validates severity_score dependency',
                   {'field': 'severity_score', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_severity_score_readiness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'severity_score')
    weight = _context_number(context, 'readiness_weight', 1.0)
    adjusted = raw * weight + 1.53
    threshold = _context_number(context, 'check_severity_score_readiness_threshold', 30.333)
    return _result('check_severity_score_readiness', adjusted, threshold, True, 'validates severity_score readiness',
                   {'field': 'severity_score', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_impact_scope_presence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'impact_scope')
    weight = _context_number(context, 'presence_weight', 1.1)
    adjusted = raw * weight + 1.7000000000000002
    threshold = _context_number(context, 'check_impact_scope_presence_threshold', 8.333)
    return _result('check_impact_scope_presence', adjusted, threshold, False, 'validates impact_scope presence',
                   {'field': 'impact_scope', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_impact_scope_range(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'impact_scope')
    weight = _context_number(context, 'range_weight', 1.2)
    adjusted = raw * weight + 0.0
    threshold = _context_number(context, 'check_impact_scope_range_threshold', 10.667)
    return _result('check_impact_scope_range', adjusted, threshold, True, 'validates impact_scope range',
                   {'field': 'impact_scope', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_impact_scope_stability(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'impact_scope')
    weight = _context_number(context, 'stability_weight', 1.3)
    adjusted = raw * weight + 0.17
    threshold = _context_number(context, 'check_impact_scope_stability_threshold', 13.0)
    return _result('check_impact_scope_stability', adjusted, threshold, True, 'validates impact_scope stability',
                   {'field': 'impact_scope', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_impact_scope_freshness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'impact_scope')
    weight = _context_number(context, 'freshness_weight', 1.4)
    adjusted = raw * weight + 0.34
    threshold = _context_number(context, 'check_impact_scope_freshness_threshold', 15.333)
    return _result('check_impact_scope_freshness', adjusted, threshold, False, 'validates impact_scope freshness',
                   {'field': 'impact_scope', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_impact_scope_coverage(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'impact_scope')
    weight = _context_number(context, 'coverage_weight', 1.0)
    adjusted = raw * weight + 0.51
    threshold = _context_number(context, 'check_impact_scope_coverage_threshold', 17.667)
    return _result('check_impact_scope_coverage', adjusted, threshold, True, 'validates impact_scope coverage',
                   {'field': 'impact_scope', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_impact_scope_consistency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'impact_scope')
    weight = _context_number(context, 'consistency_weight', 1.1)
    adjusted = raw * weight + 0.68
    threshold = _context_number(context, 'check_impact_scope_consistency_threshold', 20.0)
    return _result('check_impact_scope_consistency', adjusted, threshold, True, 'validates impact_scope consistency',
                   {'field': 'impact_scope', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_impact_scope_risk(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'impact_scope')
    weight = _context_number(context, 'risk_weight', 1.2)
    adjusted = raw * weight + 0.8500000000000001
    threshold = _context_number(context, 'check_impact_scope_risk_threshold', 22.333)
    return _result('check_impact_scope_risk', adjusted, threshold, False, 'validates impact_scope risk',
                   {'field': 'impact_scope', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_impact_scope_confidence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'impact_scope')
    weight = _context_number(context, 'confidence_weight', 1.3)
    adjusted = raw * weight + 1.02
    threshold = _context_number(context, 'check_impact_scope_confidence_threshold', 24.667)
    return _result('check_impact_scope_confidence', adjusted, threshold, True, 'validates impact_scope confidence',
                   {'field': 'impact_scope', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_impact_scope_dependency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'impact_scope')
    weight = _context_number(context, 'dependency_weight', 1.4)
    adjusted = raw * weight + 1.1900000000000002
    threshold = _context_number(context, 'check_impact_scope_dependency_threshold', 27.0)
    return _result('check_impact_scope_dependency', adjusted, threshold, True, 'validates impact_scope dependency',
                   {'field': 'impact_scope', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_impact_scope_readiness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'impact_scope')
    weight = _context_number(context, 'readiness_weight', 1.0)
    adjusted = raw * weight + 1.36
    threshold = _context_number(context, 'check_impact_scope_readiness_threshold', 29.333)
    return _result('check_impact_scope_readiness', adjusted, threshold, False, 'validates impact_scope readiness',
                   {'field': 'impact_scope', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_cross_border_link_presence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'cross_border_link')
    weight = _context_number(context, 'presence_weight', 1.1)
    adjusted = raw * weight + 1.53
    threshold = _context_number(context, 'check_cross_border_link_presence_threshold', 31.667)
    return _result('check_cross_border_link_presence', adjusted, threshold, True, 'validates cross_border_link presence',
                   {'field': 'cross_border_link', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_cross_border_link_range(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'cross_border_link')
    weight = _context_number(context, 'range_weight', 1.2)
    adjusted = raw * weight + 1.7000000000000002
    threshold = _context_number(context, 'check_cross_border_link_range_threshold', 9.667)
    return _result('check_cross_border_link_range', adjusted, threshold, True, 'validates cross_border_link range',
                   {'field': 'cross_border_link', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_cross_border_link_stability(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'cross_border_link')
    weight = _context_number(context, 'stability_weight', 1.3)
    adjusted = raw * weight + 0.0
    threshold = _context_number(context, 'check_cross_border_link_stability_threshold', 12.0)
    return _result('check_cross_border_link_stability', adjusted, threshold, False, 'validates cross_border_link stability',
                   {'field': 'cross_border_link', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_cross_border_link_freshness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'cross_border_link')
    weight = _context_number(context, 'freshness_weight', 1.4)
    adjusted = raw * weight + 0.17
    threshold = _context_number(context, 'check_cross_border_link_freshness_threshold', 14.333)
    return _result('check_cross_border_link_freshness', adjusted, threshold, True, 'validates cross_border_link freshness',
                   {'field': 'cross_border_link', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_cross_border_link_coverage(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'cross_border_link')
    weight = _context_number(context, 'coverage_weight', 1.0)
    adjusted = raw * weight + 0.34
    threshold = _context_number(context, 'check_cross_border_link_coverage_threshold', 16.667)
    return _result('check_cross_border_link_coverage', adjusted, threshold, True, 'validates cross_border_link coverage',
                   {'field': 'cross_border_link', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_cross_border_link_consistency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'cross_border_link')
    weight = _context_number(context, 'consistency_weight', 1.1)
    adjusted = raw * weight + 0.51
    threshold = _context_number(context, 'check_cross_border_link_consistency_threshold', 19.0)
    return _result('check_cross_border_link_consistency', adjusted, threshold, False, 'validates cross_border_link consistency',
                   {'field': 'cross_border_link', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_cross_border_link_risk(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'cross_border_link')
    weight = _context_number(context, 'risk_weight', 1.2)
    adjusted = raw * weight + 0.68
    threshold = _context_number(context, 'check_cross_border_link_risk_threshold', 21.333)
    return _result('check_cross_border_link_risk', adjusted, threshold, True, 'validates cross_border_link risk',
                   {'field': 'cross_border_link', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_cross_border_link_confidence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'cross_border_link')
    weight = _context_number(context, 'confidence_weight', 1.3)
    adjusted = raw * weight + 0.8500000000000001
    threshold = _context_number(context, 'check_cross_border_link_confidence_threshold', 23.667)
    return _result('check_cross_border_link_confidence', adjusted, threshold, True, 'validates cross_border_link confidence',
                   {'field': 'cross_border_link', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_cross_border_link_dependency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'cross_border_link')
    weight = _context_number(context, 'dependency_weight', 1.4)
    adjusted = raw * weight + 1.02
    threshold = _context_number(context, 'check_cross_border_link_dependency_threshold', 26.0)
    return _result('check_cross_border_link_dependency', adjusted, threshold, False, 'validates cross_border_link dependency',
                   {'field': 'cross_border_link', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_cross_border_link_readiness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'cross_border_link')
    weight = _context_number(context, 'readiness_weight', 1.0)
    adjusted = raw * weight + 1.1900000000000002
    threshold = _context_number(context, 'check_cross_border_link_readiness_threshold', 28.333)
    return _result('check_cross_border_link_readiness', adjusted, threshold, True, 'validates cross_border_link readiness',
                   {'field': 'cross_border_link', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_containment_progress_presence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'containment_progress')
    weight = _context_number(context, 'presence_weight', 1.1)
    adjusted = raw * weight + 1.36
    threshold = _context_number(context, 'check_containment_progress_presence_threshold', 30.667)
    return _result('check_containment_progress_presence', adjusted, threshold, True, 'validates containment_progress presence',
                   {'field': 'containment_progress', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_containment_progress_range(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'containment_progress')
    weight = _context_number(context, 'range_weight', 1.2)
    adjusted = raw * weight + 1.53
    threshold = _context_number(context, 'check_containment_progress_range_threshold', 8.667)
    return _result('check_containment_progress_range', adjusted, threshold, False, 'validates containment_progress range',
                   {'field': 'containment_progress', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_containment_progress_stability(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'containment_progress')
    weight = _context_number(context, 'stability_weight', 1.3)
    adjusted = raw * weight + 1.7000000000000002
    threshold = _context_number(context, 'check_containment_progress_stability_threshold', 11.0)
    return _result('check_containment_progress_stability', adjusted, threshold, True, 'validates containment_progress stability',
                   {'field': 'containment_progress', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_containment_progress_freshness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'containment_progress')
    weight = _context_number(context, 'freshness_weight', 1.4)
    adjusted = raw * weight + 0.0
    threshold = _context_number(context, 'check_containment_progress_freshness_threshold', 13.333)
    return _result('check_containment_progress_freshness', adjusted, threshold, True, 'validates containment_progress freshness',
                   {'field': 'containment_progress', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_containment_progress_coverage(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'containment_progress')
    weight = _context_number(context, 'coverage_weight', 1.0)
    adjusted = raw * weight + 0.17
    threshold = _context_number(context, 'check_containment_progress_coverage_threshold', 15.667)
    return _result('check_containment_progress_coverage', adjusted, threshold, False, 'validates containment_progress coverage',
                   {'field': 'containment_progress', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_containment_progress_consistency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'containment_progress')
    weight = _context_number(context, 'consistency_weight', 1.1)
    adjusted = raw * weight + 0.34
    threshold = _context_number(context, 'check_containment_progress_consistency_threshold', 18.0)
    return _result('check_containment_progress_consistency', adjusted, threshold, True, 'validates containment_progress consistency',
                   {'field': 'containment_progress', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_containment_progress_risk(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'containment_progress')
    weight = _context_number(context, 'risk_weight', 1.2)
    adjusted = raw * weight + 0.51
    threshold = _context_number(context, 'check_containment_progress_risk_threshold', 20.333)
    return _result('check_containment_progress_risk', adjusted, threshold, True, 'validates containment_progress risk',
                   {'field': 'containment_progress', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_containment_progress_confidence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'containment_progress')
    weight = _context_number(context, 'confidence_weight', 1.3)
    adjusted = raw * weight + 0.68
    threshold = _context_number(context, 'check_containment_progress_confidence_threshold', 22.667)
    return _result('check_containment_progress_confidence', adjusted, threshold, False, 'validates containment_progress confidence',
                   {'field': 'containment_progress', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_containment_progress_dependency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'containment_progress')
    weight = _context_number(context, 'dependency_weight', 1.4)
    adjusted = raw * weight + 0.8500000000000001
    threshold = _context_number(context, 'check_containment_progress_dependency_threshold', 25.0)
    return _result('check_containment_progress_dependency', adjusted, threshold, True, 'validates containment_progress dependency',
                   {'field': 'containment_progress', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_containment_progress_readiness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'containment_progress')
    weight = _context_number(context, 'readiness_weight', 1.0)
    adjusted = raw * weight + 1.02
    threshold = _context_number(context, 'check_containment_progress_readiness_threshold', 27.333)
    return _result('check_containment_progress_readiness', adjusted, threshold, True, 'validates containment_progress readiness',
                   {'field': 'containment_progress', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_report_delay_h_presence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'report_delay_h')
    weight = _context_number(context, 'presence_weight', 1.1)
    adjusted = raw * weight + 1.1900000000000002
    threshold = _context_number(context, 'check_report_delay_h_presence_threshold', 29.667)
    return _result('check_report_delay_h_presence', adjusted, threshold, False, 'validates report_delay_h presence',
                   {'field': 'report_delay_h', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_report_delay_h_range(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'report_delay_h')
    weight = _context_number(context, 'range_weight', 1.2)
    adjusted = raw * weight + 1.36
    threshold = _context_number(context, 'check_report_delay_h_range_threshold', 32.0)
    return _result('check_report_delay_h_range', adjusted, threshold, True, 'validates report_delay_h range',
                   {'field': 'report_delay_h', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_report_delay_h_stability(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'report_delay_h')
    weight = _context_number(context, 'stability_weight', 1.3)
    adjusted = raw * weight + 1.53
    threshold = _context_number(context, 'check_report_delay_h_stability_threshold', 10.0)
    return _result('check_report_delay_h_stability', adjusted, threshold, True, 'validates report_delay_h stability',
                   {'field': 'report_delay_h', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_report_delay_h_freshness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'report_delay_h')
    weight = _context_number(context, 'freshness_weight', 1.4)
    adjusted = raw * weight + 1.7000000000000002
    threshold = _context_number(context, 'check_report_delay_h_freshness_threshold', 12.333)
    return _result('check_report_delay_h_freshness', adjusted, threshold, False, 'validates report_delay_h freshness',
                   {'field': 'report_delay_h', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_report_delay_h_coverage(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'report_delay_h')
    weight = _context_number(context, 'coverage_weight', 1.0)
    adjusted = raw * weight + 0.0
    threshold = _context_number(context, 'check_report_delay_h_coverage_threshold', 14.667)
    return _result('check_report_delay_h_coverage', adjusted, threshold, True, 'validates report_delay_h coverage',
                   {'field': 'report_delay_h', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_report_delay_h_consistency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'report_delay_h')
    weight = _context_number(context, 'consistency_weight', 1.1)
    adjusted = raw * weight + 0.17
    threshold = _context_number(context, 'check_report_delay_h_consistency_threshold', 17.0)
    return _result('check_report_delay_h_consistency', adjusted, threshold, True, 'validates report_delay_h consistency',
                   {'field': 'report_delay_h', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_report_delay_h_risk(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'report_delay_h')
    weight = _context_number(context, 'risk_weight', 1.2)
    adjusted = raw * weight + 0.34
    threshold = _context_number(context, 'check_report_delay_h_risk_threshold', 19.333)
    return _result('check_report_delay_h_risk', adjusted, threshold, False, 'validates report_delay_h risk',
                   {'field': 'report_delay_h', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_report_delay_h_confidence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'report_delay_h')
    weight = _context_number(context, 'confidence_weight', 1.3)
    adjusted = raw * weight + 0.51
    threshold = _context_number(context, 'check_report_delay_h_confidence_threshold', 21.667)
    return _result('check_report_delay_h_confidence', adjusted, threshold, True, 'validates report_delay_h confidence',
                   {'field': 'report_delay_h', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_report_delay_h_dependency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'report_delay_h')
    weight = _context_number(context, 'dependency_weight', 1.4)
    adjusted = raw * weight + 0.68
    threshold = _context_number(context, 'check_report_delay_h_dependency_threshold', 24.0)
    return _result('check_report_delay_h_dependency', adjusted, threshold, True, 'validates report_delay_h dependency',
                   {'field': 'report_delay_h', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_report_delay_h_readiness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'report_delay_h')
    weight = _context_number(context, 'readiness_weight', 1.0)
    adjusted = raw * weight + 0.8500000000000001
    threshold = _context_number(context, 'check_report_delay_h_readiness_threshold', 26.333)
    return _result('check_report_delay_h_readiness', adjusted, threshold, False, 'validates report_delay_h readiness',
                   {'field': 'report_delay_h', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_evidence_age_h_presence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'evidence_age_h')
    weight = _context_number(context, 'presence_weight', 1.1)
    adjusted = raw * weight + 1.02
    threshold = _context_number(context, 'check_evidence_age_h_presence_threshold', 28.667)
    return _result('check_evidence_age_h_presence', adjusted, threshold, True, 'validates evidence_age_h presence',
                   {'field': 'evidence_age_h', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_evidence_age_h_range(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'evidence_age_h')
    weight = _context_number(context, 'range_weight', 1.2)
    adjusted = raw * weight + 1.1900000000000002
    threshold = _context_number(context, 'check_evidence_age_h_range_threshold', 31.0)
    return _result('check_evidence_age_h_range', adjusted, threshold, True, 'validates evidence_age_h range',
                   {'field': 'evidence_age_h', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_evidence_age_h_stability(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'evidence_age_h')
    weight = _context_number(context, 'stability_weight', 1.3)
    adjusted = raw * weight + 1.36
    threshold = _context_number(context, 'check_evidence_age_h_stability_threshold', 9.0)
    return _result('check_evidence_age_h_stability', adjusted, threshold, False, 'validates evidence_age_h stability',
                   {'field': 'evidence_age_h', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_evidence_age_h_freshness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'evidence_age_h')
    weight = _context_number(context, 'freshness_weight', 1.4)
    adjusted = raw * weight + 1.53
    threshold = _context_number(context, 'check_evidence_age_h_freshness_threshold', 11.333)
    return _result('check_evidence_age_h_freshness', adjusted, threshold, True, 'validates evidence_age_h freshness',
                   {'field': 'evidence_age_h', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_evidence_age_h_coverage(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'evidence_age_h')
    weight = _context_number(context, 'coverage_weight', 1.0)
    adjusted = raw * weight + 1.7000000000000002
    threshold = _context_number(context, 'check_evidence_age_h_coverage_threshold', 13.667)
    return _result('check_evidence_age_h_coverage', adjusted, threshold, True, 'validates evidence_age_h coverage',
                   {'field': 'evidence_age_h', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_evidence_age_h_consistency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'evidence_age_h')
    weight = _context_number(context, 'consistency_weight', 1.1)
    adjusted = raw * weight + 0.0
    threshold = _context_number(context, 'check_evidence_age_h_consistency_threshold', 16.0)
    return _result('check_evidence_age_h_consistency', adjusted, threshold, False, 'validates evidence_age_h consistency',
                   {'field': 'evidence_age_h', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_evidence_age_h_risk(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'evidence_age_h')
    weight = _context_number(context, 'risk_weight', 1.2)
    adjusted = raw * weight + 0.17
    threshold = _context_number(context, 'check_evidence_age_h_risk_threshold', 18.333)
    return _result('check_evidence_age_h_risk', adjusted, threshold, True, 'validates evidence_age_h risk',
                   {'field': 'evidence_age_h', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_evidence_age_h_confidence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'evidence_age_h')
    weight = _context_number(context, 'confidence_weight', 1.3)
    adjusted = raw * weight + 0.34
    threshold = _context_number(context, 'check_evidence_age_h_confidence_threshold', 20.667)
    return _result('check_evidence_age_h_confidence', adjusted, threshold, True, 'validates evidence_age_h confidence',
                   {'field': 'evidence_age_h', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_evidence_age_h_dependency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'evidence_age_h')
    weight = _context_number(context, 'dependency_weight', 1.4)
    adjusted = raw * weight + 0.51
    threshold = _context_number(context, 'check_evidence_age_h_dependency_threshold', 23.0)
    return _result('check_evidence_age_h_dependency', adjusted, threshold, False, 'validates evidence_age_h dependency',
                   {'field': 'evidence_age_h', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_evidence_age_h_readiness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'evidence_age_h')
    weight = _context_number(context, 'readiness_weight', 1.0)
    adjusted = raw * weight + 0.68
    threshold = _context_number(context, 'check_evidence_age_h_readiness_threshold', 25.333)
    return _result('check_evidence_age_h_readiness', adjusted, threshold, True, 'validates evidence_age_h readiness',
                   {'field': 'evidence_age_h', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_evidence_quality_presence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'evidence_quality')
    weight = _context_number(context, 'presence_weight', 1.1)
    adjusted = raw * weight + 0.8500000000000001
    threshold = _context_number(context, 'check_evidence_quality_presence_threshold', 27.667)
    return _result('check_evidence_quality_presence', adjusted, threshold, True, 'validates evidence_quality presence',
                   {'field': 'evidence_quality', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_evidence_quality_range(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'evidence_quality')
    weight = _context_number(context, 'range_weight', 1.2)
    adjusted = raw * weight + 1.02
    threshold = _context_number(context, 'check_evidence_quality_range_threshold', 30.0)
    return _result('check_evidence_quality_range', adjusted, threshold, False, 'validates evidence_quality range',
                   {'field': 'evidence_quality', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_evidence_quality_stability(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'evidence_quality')
    weight = _context_number(context, 'stability_weight', 1.3)
    adjusted = raw * weight + 1.1900000000000002
    threshold = _context_number(context, 'check_evidence_quality_stability_threshold', 8.0)
    return _result('check_evidence_quality_stability', adjusted, threshold, True, 'validates evidence_quality stability',
                   {'field': 'evidence_quality', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_evidence_quality_freshness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'evidence_quality')
    weight = _context_number(context, 'freshness_weight', 1.4)
    adjusted = raw * weight + 1.36
    threshold = _context_number(context, 'check_evidence_quality_freshness_threshold', 10.333)
    return _result('check_evidence_quality_freshness', adjusted, threshold, True, 'validates evidence_quality freshness',
                   {'field': 'evidence_quality', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_evidence_quality_coverage(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'evidence_quality')
    weight = _context_number(context, 'coverage_weight', 1.0)
    adjusted = raw * weight + 1.53
    threshold = _context_number(context, 'check_evidence_quality_coverage_threshold', 12.667)
    return _result('check_evidence_quality_coverage', adjusted, threshold, False, 'validates evidence_quality coverage',
                   {'field': 'evidence_quality', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_evidence_quality_consistency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'evidence_quality')
    weight = _context_number(context, 'consistency_weight', 1.1)
    adjusted = raw * weight + 1.7000000000000002
    threshold = _context_number(context, 'check_evidence_quality_consistency_threshold', 15.0)
    return _result('check_evidence_quality_consistency', adjusted, threshold, True, 'validates evidence_quality consistency',
                   {'field': 'evidence_quality', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_evidence_quality_risk(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'evidence_quality')
    weight = _context_number(context, 'risk_weight', 1.2)
    adjusted = raw * weight + 0.0
    threshold = _context_number(context, 'check_evidence_quality_risk_threshold', 17.333)
    return _result('check_evidence_quality_risk', adjusted, threshold, True, 'validates evidence_quality risk',
                   {'field': 'evidence_quality', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_evidence_quality_confidence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'evidence_quality')
    weight = _context_number(context, 'confidence_weight', 1.3)
    adjusted = raw * weight + 0.17
    threshold = _context_number(context, 'check_evidence_quality_confidence_threshold', 19.667)
    return _result('check_evidence_quality_confidence', adjusted, threshold, False, 'validates evidence_quality confidence',
                   {'field': 'evidence_quality', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_evidence_quality_dependency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'evidence_quality')
    weight = _context_number(context, 'dependency_weight', 1.4)
    adjusted = raw * weight + 0.34
    threshold = _context_number(context, 'check_evidence_quality_dependency_threshold', 22.0)
    return _result('check_evidence_quality_dependency', adjusted, threshold, True, 'validates evidence_quality dependency',
                   {'field': 'evidence_quality', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_evidence_quality_readiness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'evidence_quality')
    weight = _context_number(context, 'readiness_weight', 1.0)
    adjusted = raw * weight + 0.51
    threshold = _context_number(context, 'check_evidence_quality_readiness_threshold', 24.333)
    return _result('check_evidence_quality_readiness', adjusted, threshold, True, 'validates evidence_quality readiness',
                   {'field': 'evidence_quality', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_corroboration_delay_presence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'corroboration_delay')
    weight = _context_number(context, 'presence_weight', 1.1)
    adjusted = raw * weight + 0.68
    threshold = _context_number(context, 'check_corroboration_delay_presence_threshold', 26.667)
    return _result('check_corroboration_delay_presence', adjusted, threshold, False, 'validates corroboration_delay presence',
                   {'field': 'corroboration_delay', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_corroboration_delay_range(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'corroboration_delay')
    weight = _context_number(context, 'range_weight', 1.2)
    adjusted = raw * weight + 0.8500000000000001
    threshold = _context_number(context, 'check_corroboration_delay_range_threshold', 29.0)
    return _result('check_corroboration_delay_range', adjusted, threshold, True, 'validates corroboration_delay range',
                   {'field': 'corroboration_delay', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_corroboration_delay_stability(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'corroboration_delay')
    weight = _context_number(context, 'stability_weight', 1.3)
    adjusted = raw * weight + 1.02
    threshold = _context_number(context, 'check_corroboration_delay_stability_threshold', 31.333)
    return _result('check_corroboration_delay_stability', adjusted, threshold, True, 'validates corroboration_delay stability',
                   {'field': 'corroboration_delay', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_corroboration_delay_freshness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'corroboration_delay')
    weight = _context_number(context, 'freshness_weight', 1.4)
    adjusted = raw * weight + 1.1900000000000002
    threshold = _context_number(context, 'check_corroboration_delay_freshness_threshold', 9.333)
    return _result('check_corroboration_delay_freshness', adjusted, threshold, False, 'validates corroboration_delay freshness',
                   {'field': 'corroboration_delay', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_corroboration_delay_coverage(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'corroboration_delay')
    weight = _context_number(context, 'coverage_weight', 1.0)
    adjusted = raw * weight + 1.36
    threshold = _context_number(context, 'check_corroboration_delay_coverage_threshold', 11.667)
    return _result('check_corroboration_delay_coverage', adjusted, threshold, True, 'validates corroboration_delay coverage',
                   {'field': 'corroboration_delay', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_corroboration_delay_consistency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'corroboration_delay')
    weight = _context_number(context, 'consistency_weight', 1.1)
    adjusted = raw * weight + 1.53
    threshold = _context_number(context, 'check_corroboration_delay_consistency_threshold', 14.0)
    return _result('check_corroboration_delay_consistency', adjusted, threshold, True, 'validates corroboration_delay consistency',
                   {'field': 'corroboration_delay', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_corroboration_delay_risk(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'corroboration_delay')
    weight = _context_number(context, 'risk_weight', 1.2)
    adjusted = raw * weight + 1.7000000000000002
    threshold = _context_number(context, 'check_corroboration_delay_risk_threshold', 16.333)
    return _result('check_corroboration_delay_risk', adjusted, threshold, False, 'validates corroboration_delay risk',
                   {'field': 'corroboration_delay', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_corroboration_delay_confidence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'corroboration_delay')
    weight = _context_number(context, 'confidence_weight', 1.3)
    adjusted = raw * weight + 0.0
    threshold = _context_number(context, 'check_corroboration_delay_confidence_threshold', 18.667)
    return _result('check_corroboration_delay_confidence', adjusted, threshold, True, 'validates corroboration_delay confidence',
                   {'field': 'corroboration_delay', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_corroboration_delay_dependency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'corroboration_delay')
    weight = _context_number(context, 'dependency_weight', 1.4)
    adjusted = raw * weight + 0.17
    threshold = _context_number(context, 'check_corroboration_delay_dependency_threshold', 21.0)
    return _result('check_corroboration_delay_dependency', adjusted, threshold, True, 'validates corroboration_delay dependency',
                   {'field': 'corroboration_delay', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_corroboration_delay_readiness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'corroboration_delay')
    weight = _context_number(context, 'readiness_weight', 1.0)
    adjusted = raw * weight + 0.34
    threshold = _context_number(context, 'check_corroboration_delay_readiness_threshold', 23.333)
    return _result('check_corroboration_delay_readiness', adjusted, threshold, False, 'validates corroboration_delay readiness',
                   {'field': 'corroboration_delay', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_affected_population_presence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'affected_population')
    weight = _context_number(context, 'presence_weight', 1.1)
    adjusted = raw * weight + 0.51
    threshold = _context_number(context, 'check_affected_population_presence_threshold', 25.667)
    return _result('check_affected_population_presence', adjusted, threshold, True, 'validates affected_population presence',
                   {'field': 'affected_population', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_affected_population_range(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'affected_population')
    weight = _context_number(context, 'range_weight', 1.2)
    adjusted = raw * weight + 0.68
    threshold = _context_number(context, 'check_affected_population_range_threshold', 28.0)
    return _result('check_affected_population_range', adjusted, threshold, True, 'validates affected_population range',
                   {'field': 'affected_population', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_affected_population_stability(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'affected_population')
    weight = _context_number(context, 'stability_weight', 1.3)
    adjusted = raw * weight + 0.8500000000000001
    threshold = _context_number(context, 'check_affected_population_stability_threshold', 30.333)
    return _result('check_affected_population_stability', adjusted, threshold, False, 'validates affected_population stability',
                   {'field': 'affected_population', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_affected_population_freshness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'affected_population')
    weight = _context_number(context, 'freshness_weight', 1.4)
    adjusted = raw * weight + 1.02
    threshold = _context_number(context, 'check_affected_population_freshness_threshold', 8.333)
    return _result('check_affected_population_freshness', adjusted, threshold, True, 'validates affected_population freshness',
                   {'field': 'affected_population', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_affected_population_coverage(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'affected_population')
    weight = _context_number(context, 'coverage_weight', 1.0)
    adjusted = raw * weight + 1.1900000000000002
    threshold = _context_number(context, 'check_affected_population_coverage_threshold', 10.667)
    return _result('check_affected_population_coverage', adjusted, threshold, True, 'validates affected_population coverage',
                   {'field': 'affected_population', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_affected_population_consistency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'affected_population')
    weight = _context_number(context, 'consistency_weight', 1.1)
    adjusted = raw * weight + 1.36
    threshold = _context_number(context, 'check_affected_population_consistency_threshold', 13.0)
    return _result('check_affected_population_consistency', adjusted, threshold, False, 'validates affected_population consistency',
                   {'field': 'affected_population', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_affected_population_risk(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'affected_population')
    weight = _context_number(context, 'risk_weight', 1.2)
    adjusted = raw * weight + 1.53
    threshold = _context_number(context, 'check_affected_population_risk_threshold', 15.333)
    return _result('check_affected_population_risk', adjusted, threshold, True, 'validates affected_population risk',
                   {'field': 'affected_population', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_affected_population_confidence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'affected_population')
    weight = _context_number(context, 'confidence_weight', 1.3)
    adjusted = raw * weight + 1.7000000000000002
    threshold = _context_number(context, 'check_affected_population_confidence_threshold', 17.667)
    return _result('check_affected_population_confidence', adjusted, threshold, True, 'validates affected_population confidence',
                   {'field': 'affected_population', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_affected_population_dependency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'affected_population')
    weight = _context_number(context, 'dependency_weight', 1.4)
    adjusted = raw * weight + 0.0
    threshold = _context_number(context, 'check_affected_population_dependency_threshold', 20.0)
    return _result('check_affected_population_dependency', adjusted, threshold, False, 'validates affected_population dependency',
                   {'field': 'affected_population', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_affected_population_readiness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'affected_population')
    weight = _context_number(context, 'readiness_weight', 1.0)
    adjusted = raw * weight + 0.17
    threshold = _context_number(context, 'check_affected_population_readiness_threshold', 22.333)
    return _result('check_affected_population_readiness', adjusted, threshold, True, 'validates affected_population readiness',
                   {'field': 'affected_population', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_notification_channels_presence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'notification_channels')
    weight = _context_number(context, 'presence_weight', 1.1)
    adjusted = raw * weight + 0.34
    threshold = _context_number(context, 'check_notification_channels_presence_threshold', 24.667)
    return _result('check_notification_channels_presence', adjusted, threshold, True, 'validates notification_channels presence',
                   {'field': 'notification_channels', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_notification_channels_range(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'notification_channels')
    weight = _context_number(context, 'range_weight', 1.2)
    adjusted = raw * weight + 0.51
    threshold = _context_number(context, 'check_notification_channels_range_threshold', 27.0)
    return _result('check_notification_channels_range', adjusted, threshold, False, 'validates notification_channels range',
                   {'field': 'notification_channels', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_notification_channels_stability(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'notification_channels')
    weight = _context_number(context, 'stability_weight', 1.3)
    adjusted = raw * weight + 0.68
    threshold = _context_number(context, 'check_notification_channels_stability_threshold', 29.333)
    return _result('check_notification_channels_stability', adjusted, threshold, True, 'validates notification_channels stability',
                   {'field': 'notification_channels', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_notification_channels_freshness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'notification_channels')
    weight = _context_number(context, 'freshness_weight', 1.4)
    adjusted = raw * weight + 0.8500000000000001
    threshold = _context_number(context, 'check_notification_channels_freshness_threshold', 31.667)
    return _result('check_notification_channels_freshness', adjusted, threshold, True, 'validates notification_channels freshness',
                   {'field': 'notification_channels', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_notification_channels_coverage(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'notification_channels')
    weight = _context_number(context, 'coverage_weight', 1.0)
    adjusted = raw * weight + 1.02
    threshold = _context_number(context, 'check_notification_channels_coverage_threshold', 9.667)
    return _result('check_notification_channels_coverage', adjusted, threshold, False, 'validates notification_channels coverage',
                   {'field': 'notification_channels', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_notification_channels_consistency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'notification_channels')
    weight = _context_number(context, 'consistency_weight', 1.1)
    adjusted = raw * weight + 1.1900000000000002
    threshold = _context_number(context, 'check_notification_channels_consistency_threshold', 12.0)
    return _result('check_notification_channels_consistency', adjusted, threshold, True, 'validates notification_channels consistency',
                   {'field': 'notification_channels', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_notification_channels_risk(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'notification_channels')
    weight = _context_number(context, 'risk_weight', 1.2)
    adjusted = raw * weight + 1.36
    threshold = _context_number(context, 'check_notification_channels_risk_threshold', 14.333)
    return _result('check_notification_channels_risk', adjusted, threshold, True, 'validates notification_channels risk',
                   {'field': 'notification_channels', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_notification_channels_confidence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'notification_channels')
    weight = _context_number(context, 'confidence_weight', 1.3)
    adjusted = raw * weight + 1.53
    threshold = _context_number(context, 'check_notification_channels_confidence_threshold', 16.667)
    return _result('check_notification_channels_confidence', adjusted, threshold, False, 'validates notification_channels confidence',
                   {'field': 'notification_channels', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_notification_channels_dependency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'notification_channels')
    weight = _context_number(context, 'dependency_weight', 1.4)
    adjusted = raw * weight + 1.7000000000000002
    threshold = _context_number(context, 'check_notification_channels_dependency_threshold', 19.0)
    return _result('check_notification_channels_dependency', adjusted, threshold, True, 'validates notification_channels dependency',
                   {'field': 'notification_channels', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_notification_channels_readiness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'notification_channels')
    weight = _context_number(context, 'readiness_weight', 1.0)
    adjusted = raw * weight + 0.0
    threshold = _context_number(context, 'check_notification_channels_readiness_threshold', 21.333)
    return _result('check_notification_channels_readiness', adjusted, threshold, True, 'validates notification_channels readiness',
                   {'field': 'notification_channels', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_ack_rate_presence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'ack_rate')
    weight = _context_number(context, 'presence_weight', 1.1)
    adjusted = raw * weight + 0.17
    threshold = _context_number(context, 'check_ack_rate_presence_threshold', 23.667)
    return _result('check_ack_rate_presence', adjusted, threshold, False, 'validates ack_rate presence',
                   {'field': 'ack_rate', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_ack_rate_range(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'ack_rate')
    weight = _context_number(context, 'range_weight', 1.2)
    adjusted = raw * weight + 0.34
    threshold = _context_number(context, 'check_ack_rate_range_threshold', 26.0)
    return _result('check_ack_rate_range', adjusted, threshold, True, 'validates ack_rate range',
                   {'field': 'ack_rate', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_ack_rate_stability(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'ack_rate')
    weight = _context_number(context, 'stability_weight', 1.3)
    adjusted = raw * weight + 0.51
    threshold = _context_number(context, 'check_ack_rate_stability_threshold', 28.333)
    return _result('check_ack_rate_stability', adjusted, threshold, True, 'validates ack_rate stability',
                   {'field': 'ack_rate', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_ack_rate_freshness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'ack_rate')
    weight = _context_number(context, 'freshness_weight', 1.4)
    adjusted = raw * weight + 0.68
    threshold = _context_number(context, 'check_ack_rate_freshness_threshold', 30.667)
    return _result('check_ack_rate_freshness', adjusted, threshold, False, 'validates ack_rate freshness',
                   {'field': 'ack_rate', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_ack_rate_coverage(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'ack_rate')
    weight = _context_number(context, 'coverage_weight', 1.0)
    adjusted = raw * weight + 0.8500000000000001
    threshold = _context_number(context, 'check_ack_rate_coverage_threshold', 8.667)
    return _result('check_ack_rate_coverage', adjusted, threshold, True, 'validates ack_rate coverage',
                   {'field': 'ack_rate', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_ack_rate_consistency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'ack_rate')
    weight = _context_number(context, 'consistency_weight', 1.1)
    adjusted = raw * weight + 1.02
    threshold = _context_number(context, 'check_ack_rate_consistency_threshold', 11.0)
    return _result('check_ack_rate_consistency', adjusted, threshold, True, 'validates ack_rate consistency',
                   {'field': 'ack_rate', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_ack_rate_risk(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'ack_rate')
    weight = _context_number(context, 'risk_weight', 1.2)
    adjusted = raw * weight + 1.1900000000000002
    threshold = _context_number(context, 'check_ack_rate_risk_threshold', 13.333)
    return _result('check_ack_rate_risk', adjusted, threshold, False, 'validates ack_rate risk',
                   {'field': 'ack_rate', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_ack_rate_confidence(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'ack_rate')
    weight = _context_number(context, 'confidence_weight', 1.3)
    adjusted = raw * weight + 1.36
    threshold = _context_number(context, 'check_ack_rate_confidence_threshold', 15.667)
    return _result('check_ack_rate_confidence', adjusted, threshold, True, 'validates ack_rate confidence',
                   {'field': 'ack_rate', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_ack_rate_dependency(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'ack_rate')
    weight = _context_number(context, 'dependency_weight', 1.4)
    adjusted = raw * weight + 1.53
    threshold = _context_number(context, 'check_ack_rate_dependency_threshold', 18.0)
    return _result('check_ack_rate_dependency', adjusted, threshold, True, 'validates ack_rate dependency',
                   {'field': 'ack_rate', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

def check_ack_rate_readiness(record: DomainRecord, context: Mapping[str, Any]) -> RuleResult:
    raw = _number(record, 'ack_rate')
    weight = _context_number(context, 'readiness_weight', 1.0)
    adjusted = raw * weight + 1.7000000000000002
    threshold = _context_number(context, 'check_ack_rate_readiness_threshold', 20.333)
    return _result('check_ack_rate_readiness', adjusted, threshold, False, 'validates ack_rate readiness',
                   {'field': 'ack_rate', 'raw': raw, 'weight': weight, 'adjusted': adjusted, 'threshold': threshold})

RULES: tuple[RuleFunction, ...] = (
    check_incident_code_presence,
    check_incident_code_range,
    check_incident_code_stability,
    check_incident_code_freshness,
    check_incident_code_coverage,
    check_incident_code_consistency,
    check_incident_code_risk,
    check_incident_code_confidence,
    check_incident_code_dependency,
    check_incident_code_readiness,
    check_severity_score_presence,
    check_severity_score_range,
    check_severity_score_stability,
    check_severity_score_freshness,
    check_severity_score_coverage,
    check_severity_score_consistency,
    check_severity_score_risk,
    check_severity_score_confidence,
    check_severity_score_dependency,
    check_severity_score_readiness,
    check_impact_scope_presence,
    check_impact_scope_range,
    check_impact_scope_stability,
    check_impact_scope_freshness,
    check_impact_scope_coverage,
    check_impact_scope_consistency,
    check_impact_scope_risk,
    check_impact_scope_confidence,
    check_impact_scope_dependency,
    check_impact_scope_readiness,
    check_cross_border_link_presence,
    check_cross_border_link_range,
    check_cross_border_link_stability,
    check_cross_border_link_freshness,
    check_cross_border_link_coverage,
    check_cross_border_link_consistency,
    check_cross_border_link_risk,
    check_cross_border_link_confidence,
    check_cross_border_link_dependency,
    check_cross_border_link_readiness,
    check_containment_progress_presence,
    check_containment_progress_range,
    check_containment_progress_stability,
    check_containment_progress_freshness,
    check_containment_progress_coverage,
    check_containment_progress_consistency,
    check_containment_progress_risk,
    check_containment_progress_confidence,
    check_containment_progress_dependency,
    check_containment_progress_readiness,
    check_report_delay_h_presence,
    check_report_delay_h_range,
    check_report_delay_h_stability,
    check_report_delay_h_freshness,
    check_report_delay_h_coverage,
    check_report_delay_h_consistency,
    check_report_delay_h_risk,
    check_report_delay_h_confidence,
    check_report_delay_h_dependency,
    check_report_delay_h_readiness,
    check_evidence_age_h_presence,
    check_evidence_age_h_range,
    check_evidence_age_h_stability,
    check_evidence_age_h_freshness,
    check_evidence_age_h_coverage,
    check_evidence_age_h_consistency,
    check_evidence_age_h_risk,
    check_evidence_age_h_confidence,
    check_evidence_age_h_dependency,
    check_evidence_age_h_readiness,
    check_evidence_quality_presence,
    check_evidence_quality_range,
    check_evidence_quality_stability,
    check_evidence_quality_freshness,
    check_evidence_quality_coverage,
    check_evidence_quality_consistency,
    check_evidence_quality_risk,
    check_evidence_quality_confidence,
    check_evidence_quality_dependency,
    check_evidence_quality_readiness,
    check_corroboration_delay_presence,
    check_corroboration_delay_range,
    check_corroboration_delay_stability,
    check_corroboration_delay_freshness,
    check_corroboration_delay_coverage,
    check_corroboration_delay_consistency,
    check_corroboration_delay_risk,
    check_corroboration_delay_confidence,
    check_corroboration_delay_dependency,
    check_corroboration_delay_readiness,
    check_affected_population_presence,
    check_affected_population_range,
    check_affected_population_stability,
    check_affected_population_freshness,
    check_affected_population_coverage,
    check_affected_population_consistency,
    check_affected_population_risk,
    check_affected_population_confidence,
    check_affected_population_dependency,
    check_affected_population_readiness,
    check_notification_channels_presence,
    check_notification_channels_range,
    check_notification_channels_stability,
    check_notification_channels_freshness,
    check_notification_channels_coverage,
    check_notification_channels_consistency,
    check_notification_channels_risk,
    check_notification_channels_confidence,
    check_notification_channels_dependency,
    check_notification_channels_readiness,
    check_ack_rate_presence,
    check_ack_rate_range,
    check_ack_rate_stability,
    check_ack_rate_freshness,
    check_ack_rate_coverage,
    check_ack_rate_consistency,
    check_ack_rate_risk,
    check_ack_rate_confidence,
    check_ack_rate_dependency,
    check_ack_rate_readiness,
)

RULE_INDEX = {rule.__name__: rule for rule in RULES}

def evaluate(record: DomainRecord, context: Mapping[str, Any] | None = None) -> tuple[RuleResult, ...]:
    context = context or {}
    return tuple(rule(record, context) for rule in RULES)

def summarize(results: tuple[RuleResult, ...]) -> dict[str, Any]:
    if not results:
        return {'score': 0.0, 'passed': 0, 'failed': 0, 'coordinated': 0}
    return {'score': sum(item.score for item in results) / len(results),
            'passed': sum(item.passed for item in results),
            'failed': sum(not item.passed for item in results),
            'coordinated': sum(item.severity == 'coordinated' for item in results)}
