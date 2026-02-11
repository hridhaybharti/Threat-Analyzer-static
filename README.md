# Security Analyzer (FastAPI, Heuristics Only)

A simple, explainable Security Analyzer for **domains**, **URLs**, and **IP addresses** using **heuristic-based risk scoring** (no ML).

## How It Works

1. The API receives a `target` (domain/url/ip)
2. The target is classified and normalized (`backend/utils/validators.py`)
3. Relevant heuristics generate **signals** (`backend/heuristics/*`)
4. Signals are scored into:
   - `risk_score` (0-100)
   - `confidence` (0-1)
   - `verdict` (`SAFE`, `SUSPICIOUS`, `MALICIOUS`)
   - `breakdown` (risk contribution split across `reputation` / `structure` / `network`)

Each signal is explainable and includes:
- `name`
- `category`
- `bucket` (`reputation` / `structure` / `network`)
- `impact` (positive increases risk; negative reduces risk)
- `description`
- optional `confidence` and `evidence`

## Heuristics Implemented

### Domain
- Domain age (WHOIS) + age bucketing
- Registrar reputation + registrar “randomness/noise” (weak heuristic)
- DNS record validity (A/AAAA/NS/MX)
- Parked domain detection (best-effort via NS keywords + MX absence)
- Typosquatting detection (edit-distance vs a small transparent brand list)
- Suspicious TLDs

### URL
- URL shortener detection (bit.ly, t.co, …)
- Homograph/IDN indicators (punycode / non-ASCII host)
- Suspicious keywords (login/verify/secure/update/etc.)
- URL length & entropy
- Path/query entropy scoring
- Excessive subdomains
- IP-based URLs
- Redirect count (best-effort; may be unavailable in restricted environments)

### IP
- Private vs public IP check
- IPv6-specific heuristics (6to4 / Teredo / documentation ranges)
- ASN & ISP type (hosting vs non-hosting hints) with caching
- Hosting provider clustering (best-effort via ASN/network keywords)
- Country risk (weak heuristic; small configurable map)
- TOR/VPN indicators (best-effort via reverse DNS / ASN keywords)

## Configuration

### Heuristic Weights
Weights are externalized in `backend/config/weights.json` and loaded at runtime.

Optional override:
- `SECURITY_ANALYZER_WEIGHTS=/path/to/weights.json`

### SQLite History DB
History is stored in a single local SQLite file:
- default: `backend/data/analyzer.sqlite3`
- override: `SECURITY_ANALYZER_DB_PATH=/path/to/analyzer.sqlite3`

## Running

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn backend.main:app --reload
```

Endpoints:
- `GET /health`
- `POST /api/analyze`
- `GET /api/history`
- `DELETE /api/history`
- `GET /api/explain/{id}`

## Example Requests

Preferred request shape:

```bash
curl -X POST http://127.0.0.1:8000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"target":"https://example.com"}'
```

Also supported (compatible with `shared/routes.ts`):

```bash
curl -X POST http://127.0.0.1:8000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"type":"url","input":"https://example.com"}'
```

## Response Format

```json
{
  "target": "<input>",
  "type": "domain | url | ip",
  "risk_score": 0,
  "confidence": 0.2,
  "verdict": "SAFE",
  "signals": [],
  "breakdown": {
    "reputation": 0,
    "structure": 0,
    "network": 0
  }
}
```

## Tests

```powershell
pytest
```
