"""Canonical normalizers transforming parsed events into SecurityEvent models."""

from backend.app.ingestion.normalizers.application import ApplicationLogNormalizer
from backend.app.ingestion.normalizers.authentication import AuthenticationLogNormalizer
from backend.app.ingestion.normalizers.base import BaseNormalizer
from backend.app.ingestion.normalizers.email_security import EmailSecurityNormalizer
from backend.app.ingestion.normalizers.json_event import JsonEventNormalizer
from backend.app.ingestion.normalizers.suricata import SuricataNormalizer
from backend.app.ingestion.normalizers.syslog import SyslogNormalizer

__all__ = [
    "ApplicationLogNormalizer",
    "AuthenticationLogNormalizer",
    "BaseNormalizer",
    "EmailSecurityNormalizer",
    "JsonEventNormalizer",
    "SuricataNormalizer",
    "SyslogNormalizer",
]
