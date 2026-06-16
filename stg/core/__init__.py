"""Nucleo do STG: modelos, contrato de conector, runner, autorizacao."""

from stg.core.audit import AuditLog
from stg.core.authorization import Authorization
from stg.core.config import Settings
from stg.core.connector import ApiConnector, BaseConnector, CommandConnector
from stg.core.models import (
    Category,
    Finding,
    ScanResult,
    ScanStatus,
    Severity,
    Target,
    TargetType,
)
from stg.core.pipeline import Pipeline
from stg.core.registry import ConnectorRegistry, get_registry
from stg.core.runner import Runner

__all__ = [
    "AuditLog",
    "Authorization",
    "Settings",
    "ApiConnector",
    "BaseConnector",
    "CommandConnector",
    "Category",
    "Finding",
    "ScanResult",
    "ScanStatus",
    "Severity",
    "Target",
    "TargetType",
    "Pipeline",
    "ConnectorRegistry",
    "get_registry",
    "Runner",
]
