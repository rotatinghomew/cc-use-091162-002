from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping

@dataclass(frozen=True)
class DomainSignal:
    code: str
    score: float
    severity: str
    evidence: dict[str, Any]

def number(payload: Mapping[str, Any], key: str, default: float = 0.0) -> float:
    try:
        value = float(payload.get(key, default))
    except (TypeError, ValueError):
        return default
    return default if value != value or value in (float('inf'), float('-inf')) else value

def ratio(payload: Mapping[str, Any], key: str, default: float = 0.0) -> float:
    value = number(payload, key, default)
    if value > 1.0:
        value /= 100.0
    return max(0.0, min(1.0, value))

def clamp(value: float) -> float:
    return max(0.0, min(1.0, value))

def coordination_pressure(payload: Mapping[str, Any]) -> DomainSignal:
    severity = ratio(payload, 'severity_score')
    scope = min(1.0, number(payload, 'impact_scope') / 100.0)
    cross_border = ratio(payload, 'cross_border_link')
    population = min(1.0, number(payload, 'affected_population') / 100000.0)
    delay = min(1.0, number(payload, 'report_delay_h') / 72.0)
    corroboration = min(1.0, number(payload, 'corroboration_delay') / 72.0)
    quality = ratio(payload, 'evidence_quality')
    containment = ratio(payload, 'containment_progress')
    acknowledgement = ratio(payload, 'ack_rate')
    pressure = clamp(severity * 0.22 + scope * 0.13 + cross_border * 0.18 + population * 0.16 + delay * 0.1 + corroboration * 0.08 + (1-quality) * 0.07 + (1-containment) * 0.04 + (1-acknowledgement) * 0.02)
    level = 'critical' if pressure >= 0.72 else 'warning' if pressure >= 0.42 else 'info'
    return DomainSignal('coordination_pressure', pressure, level, {'severity': severity, 'cross_border': cross_border, 'population': population, 'delay': delay, 'containment': containment})

def peer_distribution(records: Iterable[Any], group_field: str = 'incident_code') -> dict[str, Any]:
    values = [coordination_pressure(getattr(r, 'payload', r)).score for r in records]
    return {'count': len(values), 'maximum_pressure': max(values) if values else 0.0, 'critical_incidents': sum(v >= 0.72 for v in values), 'average_pressure': sum(values)/len(values) if values else 0.0}

def augment_context(record: Any, repository: Any) -> dict[str, Any]:
    signal = coordination_pressure(record.payload); peers = peer_distribution(repository.list_records())
    return {'domain_signal': signal.score, 'domain_severity': signal.severity, 'critical_incidents': peers['critical_incidents'], 'maximum_pressure': peers['maximum_pressure']}
