"""Email security parser for gateway logs, SPF/DKIM/DMARC verdicts, and phishing telemetry."""

from typing import Any

from backend.app.ingestion.interfaces import EventParser, ParsedEvent, TelemetrySourceType
from backend.app.ingestion.parsers.base import (
    extract_ip,
    parse_datetime_safe,
    parse_json_safe,
)
from backend.app.schemas.events import EventSeverity


class EmailSecurityParser(EventParser):
    """Parser for email security telemetry, DMARC/SPF/DKIM auth results, and phishing indicators."""

    @property
    def source_type(self) -> TelemetrySourceType:
        return TelemetrySourceType.EMAIL

    @property
    def parser_name(self) -> str:
        return "email_security_parser"

    @property
    def parser_version(self) -> str:
        return "1.0.0"

    def can_parse(self, raw_data: Any) -> bool:
        """Check if payload is an email security record."""
        if isinstance(raw_data, dict):
            return bool(
                raw_data.get("source_type") == "email"
                or raw_data.get("source")
                in ("email_gateway", "proofpoint", "mimecast", "dmarc_report", "phishing_filter")
                or "spf_result" in raw_data
                or "dmarc_result" in raw_data
                or ("sender" in raw_data and "recipient" in raw_data)
                or ("from_address" in raw_data and "to_address" in raw_data)
            )
        if isinstance(raw_data, str):
            clean = raw_data.strip()
            return bool(
                "dmarc=" in clean
                or "spf=" in clean
                or "dkim=" in clean
                or "phishing" in clean.lower()
            )
        return False

    def parse(self, raw_data: Any) -> ParsedEvent:
        """Parse email security telemetry into canonical ParsedEvent."""
        data, err = parse_json_safe(raw_data)
        if err or not isinstance(data, dict):
            # Fallback for simple string format
            return self._parse_text_email(str(raw_data), raw_data)

        raw_ts = data.get("timestamp") or data.get("date") or data.get("@timestamp")
        event_time = parse_datetime_safe(raw_ts)

        sender = (
            data.get("sender")
            or data.get("from")
            or data.get("from_address")
            or data.get("envelope_from")
        )
        recipient = (
            data.get("recipient")
            or data.get("to")
            or data.get("to_address")
            or data.get("envelope_to")
        )
        subject = data.get("subject") or data.get("email_subject") or ""

        # Auth verdicts
        spf_res = str(data.get("spf_result") or data.get("spf") or "none").lower()
        dkim_res = str(data.get("dkim_result") or data.get("dkim") or "none").lower()
        dmarc_res = str(data.get("dmarc_result") or data.get("dmarc") or "none").lower()

        client_ip = extract_ip(
            data.get("client_ip")
            or data.get("src_ip")
            or data.get("sender_ip")
            or data.get("connecting_ip")
        )

        # Phishing risk score & verdict
        raw_score = data.get("phishing_score", data.get("spam_score", 0.0))
        try:
            phishing_score = float(str(raw_score)) if raw_score is not None else 0.0
        except (ValueError, TypeError):
            phishing_score = 0.0
        threat_verdict = str(
            data.get("threat_verdict") or data.get("verdict") or data.get("action") or "clean"
        ).lower()

        # Classification and Severity
        has_auth_failure = (
            (spf_res in ("fail", "softfail"))
            or (dkim_res == "fail")
            or (dmarc_res in ("fail", "reject", "quarantine"))
        )
        is_phishing = (
            threat_verdict in ("phishing", "malicious", "spam", "quarantined")
            or phishing_score >= 0.7
        )

        if is_phishing:
            event_type = "email_phishing_detected"
            severity = EventSeverity.HIGH
            action = "quarantined" if "quarantin" in threat_verdict else "blocked"
            status = "detected"
        elif has_auth_failure:
            event_type = "email_auth_failure"
            severity = EventSeverity.MEDIUM
            action = "flagged"
            status = "warning"
        else:
            event_type = "email_delivered"
            severity = EventSeverity.LOW
            action = "delivered"
            status = "success"

        # URLs and Attachment Hashes
        suspicious_urls = data.get("urls") or data.get("extracted_urls") or []
        first_url = (
            suspicious_urls[0] if isinstance(suspicious_urls, list) and suspicious_urls else None
        )

        attachment_hashes = data.get("attachment_hashes") or data.get("file_hashes") or []
        first_hash = (
            attachment_hashes[0]
            if isinstance(attachment_hashes, list) and attachment_hashes
            else data.get("attachment_hash")
        )

        # Domain extraction from sender
        domain = None
        if sender and "@" in str(sender):
            domain = str(sender).split("@")[-1].strip()

        metadata = dict(data)
        metadata.update(
            {
                "sender": sender,
                "recipient": recipient,
                "subject": subject,
                "spf_result": spf_res,
                "dkim_result": dkim_res,
                "dmarc_result": dmarc_res,
                "phishing_score": phishing_score,
                "threat_verdict": threat_verdict,
            }
        )

        return ParsedEvent(
            source_type=TelemetrySourceType.EMAIL,
            raw_payload=raw_data,
            extracted_fields=data,
            timestamp=event_time,
            event_type=event_type,
            severity=severity,
            source_ip=client_ip,
            username=str(sender) if sender else None,
            domain=domain,
            url=first_url,
            hash=str(first_hash) if first_hash else None,
            action=action,
            status=status,
            metadata=metadata,
            parser_name=self.parser_name,
            parser_version=self.parser_version,
        )

    def _parse_text_email(self, text: str, raw_payload: Any) -> ParsedEvent:
        """Fallback parse for text email headers or logs."""
        clean = text.strip()
        event_time = parse_datetime_safe(None)
        severity = EventSeverity.MEDIUM if "fail" in clean.lower() else EventSeverity.LOW
        event_type = "email_auth_log"

        return ParsedEvent(
            source_type=TelemetrySourceType.EMAIL,
            raw_payload=raw_payload,
            extracted_fields={"raw_line": clean},
            timestamp=event_time,
            event_type=event_type,
            severity=severity,
            action="logged",
            status="info",
            metadata={"message": clean},
            parser_name=self.parser_name,
            parser_version=self.parser_version,
        )
