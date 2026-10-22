# CertWatch

CertWatch is a free, serverless TLS certificate and HTTPS health monitor. Its FastAPI endpoint scans target domains concurrently, while a scheduled GitHub Action sends Discord alerts for certificate or HTTPS-policy findings.

## What it checks

- Certificate expiry and remaining days
- Trusted TLS certificate chain and HTTPS reachability
- Negotiated TLS protocol version
- RSA key size and SHA-1/MD5 certificate signatures
- `Strict-Transport-Security` response header

Every result includes a status (`OK`, `Warning`, or `Critical`) and concise remediation guidance. TLS handshakes and HSTS requests execute concurrently. Each network operation has a three-second timeout, so a batch of normal hosts completes in roughly the duration of the slowest host rather than the sum of all hosts.

## Run locally

Requires Python 3.12.

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
uvicorn api.index:app --reload
```

Open `http://127.0.0.1:8000`. The dashboard posts a JSON request to `POST /api/scan`:

```json
{"domains":["example.com","openai.com"]}
```

The API accepts up to 50 hostnames per request. Only hostnames (or `https://` host URLs) are accepted; paths are stripped and ports are not scanned.

## Deploy to Vercel

1. Push this repository to GitHub.
2. Import it into Vercel and select the free Hobby plan.
3. Vercel detects `vercel.json`, deploys `api/index.py` as the Python Function, and serves the dashboard from `public/`.
4. Visit the deployed URL and run a scan.

No Vercel environment variables are needed for the web dashboard.

## GitHub Actions + Discord

The workflow in `.github/workflows/scan.yml` runs at `00:00` and `12:00` UTC each day, plus on manual dispatch. In the GitHub repository, add these Actions secrets:

| Secret | Value |
| --- | --- |
| `TARGET_DOMAINS` | Comma- or newline-separated domains, such as `example.com,app.example.com` |
| `DISCORD_WEBHOOK_URL` | A Discord channel webhook URL |

Without `TARGET_DOMAINS`, the scanner uses `example.com` and `openai.com` so a new workflow remains runnable. Without the Discord secret it logs findings but does not send a notification.

Run it locally with:

```bash
$env:DOMAINS="example.com,openai.com"
python scripts/monitor.py
```

`DOMAINS` takes precedence over `TARGET_DOMAINS` for convenient local use.

## Status policy

- **Critical:** certificate expired/untrusted, TLS unavailable, RSA key below 2048 bits, weak SHA-1/MD5 signature, or fewer than seven days until expiry.
- **Warning:** missing/unverifiable HSTS, TLS 1.0/1.1, or expiry within 7–30 days.
- **OK:** no findings; certificate has more than 30 days remaining, modern TLS is negotiated, and HSTS is present.

The API reports errors as individual domain results, rather than failing the whole batch. This makes DNS errors, timeouts, and certificate trust failures visible in both the dashboard and scheduled alerts.
