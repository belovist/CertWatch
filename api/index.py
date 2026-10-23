"""Concurrent TLS certificate and HTTPS observability API."""
from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import ssl
from datetime import datetime, timezone
from time import perf_counter
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="CertWatch", version="2.0.0")
CONNECT_TIMEOUT_SECONDS = 3.0
MAX_DOMAINS_PER_REQUEST = 50
DOMAIN_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
DEPRECATED_TLS = {"TLSv1", "TLSv1.1"}
WEAK_SIGNATURES = {"md5", "sha1"}


class ScanRequest(BaseModel):
    domains: list[str] = Field(min_length=1, max_length=MAX_DOMAINS_PER_REQUEST)


def milliseconds(start: float) -> float:
    return round((perf_counter() - start) * 1000, 1)


def normalize_domain(value: str) -> str:
    domain = re.sub(r"^https?://", "", value.strip().lower())
    domain = domain.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if domain.startswith("[") and domain.endswith("]"):
        domain = domain[1:-1]
    elif domain.count(":") == 1:
        host, port = domain.rsplit(":", 1)
        if port.isdigit():
            domain = host
    if not domain or any(char.isspace() for char in domain):
        raise ValueError("Enter a valid hostname, not an empty value")
    try:
        ipaddress.ip_address(domain)
        return domain
    except ValueError:
        pass
    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Hostname cannot be IDNA encoded") from exc
    if not DOMAIN_PATTERN.fullmatch(domain) or ".." in domain:
        raise ValueError("Enter a valid hostname")
    return domain


def certificate_name(certificate: x509.Certificate) -> str:
    attributes = certificate.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    return attributes[0].value if attributes else certificate.subject.rfc4514_string()


def base_result(domain: str) -> dict[str, Any]:
    return {"domain": domain, "status": "Critical", "security_grade": "F", "days_remaining": None,
            "tls_version": None, "hsts": False,
            "latency": {"dns_ms": None, "tcp_ms": None, "tls_ms": None, "total_ms": None},
            "certificate": {}, "issues": [], "recommendations": [], "error": None}


def add_issue(result: dict[str, Any], issue: str, recommendation: str) -> None:
    result["issues"].append(issue)
    result["recommendations"].append(recommendation)


async def resolve_address(domain: str) -> tuple[str, int, int]:
    """Resolve once, allowing DNS latency to be measured separately from TCP."""
    addresses = await asyncio.get_running_loop().getaddrinfo(domain, 443, type=socket.SOCK_STREAM)
    family, _, _, _, sockaddr = addresses[0]
    return sockaddr[0], sockaddr[1], family


async def fetch_hsts(domain: str) -> bool:
    context = ssl.create_default_context()
    reader, writer = await asyncio.wait_for(asyncio.open_connection(domain, 443, ssl=context, server_hostname=domain), timeout=CONNECT_TIMEOUT_SECONDS)
    try:
        writer.write((f"HEAD / HTTP/1.1\r\nHost: {domain}\r\nUser-Agent: CertWatch/2.0\r\nConnection: close\r\n\r\n").encode("ascii"))
        await writer.drain()
        headers = (await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=CONNECT_TIMEOUT_SECONDS)).decode("iso-8859-1", "replace").lower()
        return "\r\nstrict-transport-security:" in headers
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, ssl.SSLError):
            pass


def key_is_acceptable(public_key: Any | None) -> bool:
    if isinstance(public_key, rsa.RSAPublicKey):
        return public_key.key_size >= 2048
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return public_key.key_size >= 256
    return public_key is not None


def grade_result(result: dict[str, Any], public_key: Any | None) -> str:
    days, tls = result["days_remaining"], result["tls_version"]
    signature = str(result["certificate"].get("signature_algorithm", "")).lower()
    if result["error"] or (days is not None and days < 0) or not key_is_acceptable(public_key) or signature in WEAK_SIGNATURES:
        return "F"
    if tls in DEPRECATED_TLS:
        return "C"
    if not result["hsts"] or (days is not None and days <= 30):
        return "B"
    if tls == "TLSv1.3" and result["hsts"]:
        return "A+"
    if tls in {"TLSv1.2", "TLSv1.3"} and result["hsts"]:
        return "A"
    return "B"


async def inspect_domain_async(raw_domain: str) -> dict[str, Any]:
    """Inspect a domain with independently timed DNS, TCP, and TLS stages."""
    try:
        domain = normalize_domain(raw_domain)
    except ValueError as exc:
        result = base_result(raw_domain.strip() or "(empty)")
        result["error"] = str(exc)
        add_issue(result, "Invalid hostname", "Provide a bare DNS hostname, for example example.com.")
        return result

    result, public_key, writer = base_result(domain), None, None
    hsts_task = asyncio.create_task(fetch_hsts(domain))
    connection_start = perf_counter()
    try:
        start = perf_counter()
        address, port, family = await asyncio.wait_for(resolve_address(domain), timeout=2.5)
        result["latency"]["dns_ms"] = milliseconds(start)
        start = perf_counter()
        _, writer = await asyncio.wait_for(asyncio.open_connection(address, port, family=family), timeout=2.5)
        result["latency"]["tcp_ms"] = milliseconds(start)
        start = perf_counter()
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        await asyncio.wait_for(writer.start_tls(context, server_hostname=domain, ssl_handshake_timeout=2.5), timeout=2.5)
        result["latency"]["tls_ms"] = milliseconds(start)
        result["latency"]["total_ms"] = milliseconds(connection_start)
        ssl_object: ssl.SSLObject | None = writer.get_extra_info("ssl_object")
        certificate_der = ssl_object.getpeercert(binary_form=True) if ssl_object else None
        if not certificate_der:
            raise ssl.SSLError("The server did not provide a certificate")
        certificate = x509.load_der_x509_certificate(certificate_der)
        expires_at = certificate.not_valid_after_utc
        days = (expires_at - datetime.now(timezone.utc)).days
        public_key = certificate.public_key()
        key_size = getattr(public_key, "key_size", None)
        signature = certificate.signature_hash_algorithm.name.lower()
        result.update({"days_remaining": days, "tls_version": ssl_object.version() if ssl_object else None,
                       "certificate": {"subject": certificate_name(certificate), "issuer": certificate.issuer.rfc4514_string(),
                                       "expires_at": expires_at.isoformat(), "signature_algorithm": signature,
                                       "key_type": type(public_key).__name__.replace("PublicKey", ""), "key_size": key_size}})
        if days < 0:
            add_issue(result, "Certificate has expired", "Renew and deploy a valid certificate via ACME/Let's Encrypt immediately.")
        elif days < 7:
            add_issue(result, f"Certificate expires in {days} days", "Renew immediately and verify automated renewal.")
        elif days <= 30:
            add_issue(result, f"Certificate expires in {days} days", "Schedule certificate renewal before the 30-day window closes.")
        if result["tls_version"] in DEPRECATED_TLS:
            add_issue(result, f"Deprecated protocol negotiated: {result['tls_version']}", "Disable TLS 1.0/1.1 and require TLS 1.2 or TLS 1.3.")
        if not key_is_acceptable(public_key):
            add_issue(result, f"Weak key: {key_size} bits", "Replace with RSA 2048-bit+ or ECC 256-bit+ key material.")
        if signature in WEAK_SIGNATURES:
            add_issue(result, f"Weak certificate signature: {signature}", "Reissue the certificate using SHA-256 or a stronger signature algorithm.")
    except asyncio.TimeoutError:
        result["error"] = "DNS, TCP, or TLS connection timed out after 2.5 seconds"
        add_issue(result, "TLS connection timeout", "Check DNS, firewall rules, and port 443 reachability.")
    except ssl.SSLCertVerificationError as exc:
        result["error"] = f"Certificate chain is not trusted: {exc.verify_message}"
        add_issue(result, "Certificate chain is invalid or untrusted", "Deploy a certificate with its complete trusted intermediate chain.")
    except Exception as exc:
        result["status"] = "Critical"
        result["error"] = f"Inspection error: {str(exc)}"
        add_issue(result, "HTTPS/TLS inspection failed", "Verify DNS, port 443, and the TLS server configuration.")
    finally:
        if result["latency"]["total_ms"] is None:
            result["latency"]["total_ms"] = milliseconds(connection_start)
        if writer:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, ssl.SSLError):
                pass

    try:
        result["hsts"] = await hsts_task
        if not result["hsts"]:
            add_issue(result, "HSTS header is missing", "Enable Strict-Transport-Security in NGINX, your CDN, or Cloudflare.")
    except Exception:
        result["hsts"] = False
        if not result["error"]:
            add_issue(result, "Could not verify HSTS header", "Ensure HTTPS responds to HEAD requests and sets Strict-Transport-Security.")

    result["security_grade"] = grade_result(result, public_key)
    critical = bool(result["error"]) or (result["days_remaining"] is not None and result["days_remaining"] < 7) or result["security_grade"] == "F"
    result["status"] = "Critical" if critical else "Warning" if result["issues"] else "OK"
    return result


@app.get("/api/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/scan")
async def scan(request: ScanRequest) -> list[dict[str, Any]]:
    if len(request.domains) > MAX_DOMAINS_PER_REQUEST:
        raise HTTPException(status_code=422, detail=f"Maximum {MAX_DOMAINS_PER_REQUEST} domains per scan")
    return list(await asyncio.gather(*(inspect_domain_async(domain) for domain in request.domains)))
