# CertWatch

> Serverless, non-blocking TLS certificate observability and HTTPS health monitoring for every endpoint in your stack.

[![Python 3.12](https://img.shields.io/badge/python-3.12-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![License](https://img.shields.io/badge/license-not%20specified-lightgrey)](https://github.com/belovist/CertWatch)
[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/belovist/CertWatch)

CertWatch concurrently inspects HTTPS endpoints and reports certificate metadata, TLS posture, HSTS coverage, security grades, and network latency. The same inspection engine powers the web dashboard, the terminal CLI, and the scheduled GitHub Actions monitor.

## Highlights

- Inspect up to **50 domains per API request**.
- Run DNS, TCP, TLS, and HSTS checks concurrently with `asyncio`.
- Enforce a **2.5-second timeout** for each DNS, TCP, TLS, and HSTS network operation.
- Return failures at the individual-domain level instead of failing an entire batch.
- Analyze expired and self-signed certificates by collecting certificate data without trusting the remote chain during inspection.
- Export dashboard results as CSV.
- Run scheduled scans and optionally send findings to Discord through GitHub Actions.

## Core capabilities

### X.509 certificate inspection

For each endpoint, CertWatch reads the peer certificate and reports:

- `days_remaining`, calculated from the certificate's `not_valid_after_utc` timestamp.
- Subject common name, with the full subject as a fallback.
- Issuer distinguished name.
- Expiry timestamp.
- Public-key type and key size.
- Certificate signature hash algorithm.

RSA keys must be at least **2048 bits** and elliptic-curve keys must be at least **256 bits**. Other public-key types are accepted when a public key is available. `MD5` and `SHA-1` signatures are flagged as weak.

Certificate verification is disabled for the inspection TLS contexts (`CERT_NONE` and `check_hostname = False`) so that expired or otherwise untrusted endpoints can still be inspected and reported. This tool observes certificate posture; it does not establish that a certificate is trusted by a client.

### TLS and protocol health

The negotiated TLS version is recorded. TLS 1.0 and TLS 1.1 are classified as deprecated and produce a grade deduction.

### HSTS audit

CertWatch sends an HTTPS `HEAD /` request and checks for the `Strict-Transport-Security` response header. Missing HSTS produces a finding with remediation guidance.

### Async concurrency and failure isolation

The API starts one `inspect_domain_async()` coroutine per requested domain and awaits them with `asyncio.gather()`. DNS resolution, TCP connection, TLS negotiation, and HSTS reads are bounded by a 2.5-second timeout per operation.

Unexpected errors are converted into a domain result with `status: "Critical"` and an explanatory `error` field. The `/api/scan` route also uses `return_exceptions=True` as a final isolation boundary, ensuring one unexpected coroutine failure does not abort the other domains in the batch.

### Latency telemetry

Successful inspections expose timings for:

| Metric | Meaning |
| --- | --- |
| `dns_ms` | Time spent resolving the endpoint address |
| `tcp_ms` | Time spent establishing the TCP connection |
| `tls_ms` | Time spent negotiating TLS |
| `total_ms` | Elapsed time for the primary inspection pipeline |

## Security grading

Grades are calculated in `grade_result()` in this order:

| Grade | Exact criteria |
| --- | --- |
| **F** | Any error; an expired certificate (`days_remaining < 0`); an unacceptable key (RSA below 2048 bits, EC below 256 bits, or no public key); or an MD5/SHA-1 certificate signature. |
| **C** | No F condition, but the negotiated protocol is TLS 1.0 or TLS 1.1. |
| **B** | No F or C condition, but HSTS is missing or the certificate expires in 30 days or less. |
| **A** | HSTS is present and the negotiated protocol is TLS 1.2 or TLS 1.3. |
| **A+** | HSTS is present and the negotiated protocol is TLS 1.3. |

The response status is derived separately:

- **Critical** when an error exists, fewer than seven days remain, or the grade is `F`.
- **Warning** when there are findings but the result is not critical.
- **OK** when there are no findings.

Because the implementation checks errors and expiry before protocol and HSTS rules, an endpoint with an expired certificate is `F` even if its TLS version and HSTS configuration are otherwise strong.

## Architecture

```text
Browser dashboard ──POST /api/scan──▶ FastAPI serverless function
                                          │
                                          ├─ asyncio.gather()
                                          │    ├─ DNS resolution
                                          │    ├─ TCP connection
                                          │    ├─ TLS handshake + X.509 parsing
                                          │    └─ HSTS HEAD request
                                          │
                                          └─ Structured result per domain
```

### Technology stack

| Layer | Implementation |
| --- | --- |
| Backend | Python 3.12, FastAPI, `asyncio`, `ssl`, `socket`, and `cryptography` |
| Frontend | Static HTML and JavaScript, Tailwind CSS loaded from the CDN, and Lucide Icons |
| Deployment | Vercel Python function for `api/index.py` and static assets from `public/` |
| Automation | GitHub Actions, Python `requests`, and optional Discord webhook notifications |
| CLI | Typer and Rich |

The repository does not currently include a Framer Motion dependency or a `LICENSE` file. The UI animation is implemented with native CSS keyframes and JavaScript.

## API

### `GET /api/health`

Returns a basic service health response:

```json
{
  "status": "ok"
}
```

### `POST /api/scan`

Scans one or more hostnames concurrently.

#### Request

```json
{
  "domains": [
    "example.com",
    "https://openai.com/path"
  ]
}
```

The request must contain between 1 and 50 strings. Inputs may be bare hostnames, `http://` or `https://` URLs, IPv4 addresses, bracketed IPv6 addresses, or hostnames with a numeric port. URL paths, query strings, and fragments are removed; the scanner always connects to port 443.

Invalid request shape or a request exceeding the Pydantic/API limits is rejected by FastAPI with a validation response, normally HTTP **422**. A valid batch does not fail because one domain is malformed or unreachable.

#### Response

The endpoint returns an array with one result for each requested domain:

```json
[
  {
    "domain": "example.com",
    "status": "OK",
    "security_grade": "A+",
    "days_remaining": 120,
    "tls_version": "TLSv1.3",
    "hsts": true,
    "latency": {
      "dns_ms": 12.4,
      "tcp_ms": 18.7,
      "tls_ms": 23.1,
      "total_ms": 55.2
    },
    "certificate": {
      "subject": "example.com",
      "issuer": "C=US,O=Example CA,CN=Example RSA CA",
      "expires_at": "2027-02-20T12:00:00+00:00",
      "signature_algorithm": "sha256",
      "key_type": "RSAPublicKey",
      "key_size": 2048
    },
    "issues": [],
    "recommendations": [],
    "error": null
  }
]
```

The response object always includes:

| Field | Description |
| --- | --- |
| `domain` | Normalized domain or the original trimmed value for invalid input |
| `status` | `OK`, `Warning`, or `Critical` |
| `security_grade` | `A+`, `A`, `B`, `C`, or `F` |
| `days_remaining` | Whole days until certificate expiry, or `null` |
| `tls_version` | Negotiated TLS version, or `null` |
| `hsts` | Whether the response included the HSTS header |
| `latency` | DNS, TCP, TLS, and total timings in milliseconds |
| `certificate` | Parsed certificate metadata, or `{}` when unavailable |
| `issues` | Human-readable findings |
| `recommendations` | Remediation guidance aligned by index with `issues` |
| `error` | Error description, or `null` |

Individual failures are returned as structured domain results, for example:

```json
{
  "domain": "unreachable.example",
  "status": "Critical",
  "security_grade": "F",
  "error": "DNS, TCP, or TLS connection timed out after 2.5 seconds",
  "issues": [
    "TLS connection timeout"
  ]
}
```

### Frontend response handling

The dashboard reads the response body as text before parsing JSON. Valid JSON is processed normally; a non-JSON error response is surfaced as `Server error (<status>): <body preview>` instead of causing a second JSON parsing exception in the browser.

## Local development

CertWatch requires Python 3.12.

### 1. Clone and enter the repository

```powershell
git clone https://github.com/belovist/CertWatch.git
cd CertWatch
```

### 2. Create and activate a virtual environment

PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Windows Command Prompt:

```bat
python -m venv .venv
.venv\Scripts\activate
```

### 3. Install dependencies

```powershell
python -m pip install -r requirements.txt
```

### 4. Start the API and static dashboard

```powershell
uvicorn api.index:app --reload
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000) in a browser. The Vercel routing configuration serves the `public/` dashboard and forwards `/api/*` requests to the FastAPI application; for local development, use a Vercel-compatible preview or configure the static frontend/API routing in your local environment.

You can verify the API directly:

```powershell
curl http://127.0.0.1:8000/api/health
curl -Method Post http://127.0.0.1:8000/api/scan `
  -ContentType "application/json" `
  -Body '{"domains":["example.com","openai.com"]}'
```

### CLI scan

The terminal interface uses the same inspection engine:

```powershell
python certwatch_cli.py example.com openai.com
```

It prints domain, grade, total latency, days remaining, and negotiated TLS version.

## Scheduled monitoring and Discord alerts

The workflow in `.github/workflows/scan.yml` runs every 12 hours and supports manual dispatch. It installs the requirements and runs `scripts/monitor.py`.

Configure these GitHub Actions secrets:

| Secret | Purpose |
| --- | --- |
| `TARGET_DOMAINS` | Comma- or newline-separated domains to scan |
| `DISCORD_WEBHOOK_URL` | Discord webhook used when findings exist |

For local execution:

```powershell
$env:DOMAINS = "example.com,openai.com"
python scripts/monitor.py
```

`DOMAINS` takes precedence over `TARGET_DOMAINS`. If neither is set, the monitor scans `example.com` and `openai.com`. Findings are printed locally and, when configured, sent to Discord. The monitor includes at most 25 findings in the Discord embed and truncates each finding description to Discord's field limit.

## Deployment to Vercel

1. Push the repository to GitHub.
2. In Vercel, select **Add New → Project** and import `belovist/CertWatch`.
3. Deploy without adding environment variables for the web dashboard.
4. Vercel uses `vercel.json` to deploy `api/index.py` as a Python function, serve `public/` as static assets, and route `/api/*` to the API.
5. Open the generated Vercel URL and run a scan from the dashboard.

The scheduled GitHub Actions monitor is independent of the Vercel deployment and requires its own optional Discord/domain secrets.

## Project layout

```text
.
├── api/
│   └── index.py              # FastAPI app and async TLS inspection engine
├── public/
│   ├── index.html            # Dashboard markup and Tailwind/CSS presentation
│   └── app.js                # Dashboard state, fetch handling, rendering, CSV export
├── scripts/
│   └── monitor.py            # Scheduled scanner and Discord notifications
├── certwatch_cli.py          # Typer/Rich terminal scanner
├── requirements.txt
├── vercel.json
├── Dockerfile
└── .github/workflows/scan.yml
```

## License

No `LICENSE` file is currently included in the repository. Add an explicit license before distributing the project as open source.
