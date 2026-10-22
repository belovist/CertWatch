"""Headless CertWatch scanner for GitHub Actions and Discord notifications."""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path
from typing import Any

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from api.index import inspect_domain_async  # noqa: E402

DEFAULT_DOMAINS = ["example.com", "openai.com"]
DISCORD_EMBED_LIMIT = 25


def targets() -> list[str]:
    """Read comma/newline-separated TARGET_DOMAINS, with a safe demo fallback."""
    source = os.environ.get("DOMAINS") or os.environ.get("TARGET_DOMAINS")
    if not source:
        return DEFAULT_DOMAINS
    return [domain.strip() for domain in source.replace("\n", ",").split(",") if domain.strip()]


def finding_text(result: dict[str, Any]) -> str:
    details = "; ".join(result["issues"]) or result.get("error") or "Review TLS configuration"
    days = result["days_remaining"]
    days_text = f" · {days} days remaining" if days is not None else ""
    latency = result.get("latency", {}).get("total_ms")
    latency_text = f" · {latency:.1f} ms" if isinstance(latency, (float, int)) else ""
    return f"Grade {result.get('security_grade', 'F')} · {details}{days_text}{latency_text}"[:1024]


def discord_payload(findings: list[dict[str, Any]]) -> dict[str, Any]:
    critical_count = sum(item["status"] == "Critical" or item.get("security_grade") in {"C", "F"} for item in findings)
    warning_count = len(findings) - critical_count
    color = 0xED4245 if critical_count else 0xFEE75C
    fields = [
        {
            "name": f"{'🔴' if item['status'] == 'Critical' or item.get('security_grade') in {'C', 'F'} else '🟡'} {item['domain']} — Grade {item.get('security_grade', 'F')}",
            "value": finding_text(item),
            "inline": False,
        }
        for item in findings[:DISCORD_EMBED_LIMIT]
    ]
    if len(findings) > DISCORD_EMBED_LIMIT:
        fields.append({"name": "Additional findings", "value": f"{len(findings) - DISCORD_EMBED_LIMIT} more findings are in the GitHub Actions log.", "inline": False})
    return {
        "username": "CertWatch",
        "embeds": [{
            "title": "CertWatch security findings",
            "description": f"**{critical_count} critical** and **{warning_count} warning** finding(s).",
            "color": color,
            "fields": fields,
            "footer": {"text": "CertWatch automated scan"},
        }],
    }


async def run() -> int:
    domain_list = targets()
    results = await asyncio.gather(*(inspect_domain_async(domain) for domain in domain_list))
    findings = [result for result in results if result["status"] in {"Critical", "Warning"} or result.get("security_grade") in {"C", "F"}]
    print(f"Scanned {len(results)} domain(s); {len(findings)} finding(s).")
    for finding in findings:
        print(f"[{finding['status']}] {finding['domain']}: {finding_text(finding)}")
    webhook_url = os.environ.get("DISCORD_WEBHOOK_URL")
    if findings and webhook_url:
        try:
            response = requests.post(webhook_url, json=discord_payload(findings), timeout=10)
            response.raise_for_status()
            print("Discord alert sent.")
        except requests.RequestException as exc:
            print(f"Discord alert failed: {exc}", file=sys.stderr)
            return 1
    elif findings:
        print("DISCORD_WEBHOOK_URL is not configured; findings were not sent to Discord.")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(run()))
