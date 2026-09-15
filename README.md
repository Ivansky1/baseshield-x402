# 🛡️ BaseShield — x402 Token Security Oracle

**Machine-to-machine on-chain token security and honeypot screening oracle for autonomous AI agents on Base mainnet.**

Pay-per-query micropayments ($0.02 USDC on Base) via the **x402** protocol (HTTP 402 Payment Required standard).

---

## ⚡ Key Features

- **Honeypot Detection**: Simulates transfer rules and identifies malicious contract traps.
- **Privileged Access Audit**: Scans contract bytecode for arbitrary `mint()`, `blacklist()`, `pause()`, and emergency freeze functions.
- **Proxy Architecture Inspection**: Detects upgradeable proxy implementations and unrenounced owner control.
- **Deterministic Risk Scoring**: Generates standardized scores (0–100) and actionable safety verdicts (`SAFE_FOR_AGENT_SWAP`, `PROCEED_WITH_CAUTION`, `DO_NOT_TRADE_HONEYPOT_RISK`).
- **x402 v2 Native**: Implements pre-validation HTTP 402 payment challenges compliant with the `x402scan` ecosystem specification.

---

## 💰 Payment Specifications

- **Protocol**: `x402` (v2)
- **Network**: Base Mainnet (`eip155:8453`)
- **Asset**: Base USDC (`0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`)
- **Fee**: $0.02 USDC (`20000` atomic units)
- **Recipient (`payTo`)**: `0xc175dd157aAc14ebDe9D57F8483AC3B63d696bE3`
- **Settlement**: EIP-3009 (`receiveWithAuthorization`) / EIP-712

---

## 🚀 Endpoints

| Method | Path | Auth / Payment | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/` | Free | Service overview and documentation |
| `GET` | `/health` | Free | Health check & chain confirmation |
| `GET` | `/self-test` | Free | Live x402 compliance & payee verification |
| `GET` | `/.well-known/x402` | Free | Standard x402 discovery manifest |
| `GET` | `/openapi.json` | Free | OpenAPI 3.1 schema with `x-payment-info` |
| `POST` | `/v1/screen` | $0.02 USDC | Paid token security & honeypot screening |

### Example Request (`POST /v1/screen`)

```bash
# 1. Unauthenticated Probe (Returns 402 Challenge)
curl -i -X POST https://<domain>/v1/screen

# 2. Paid Execution (With x402 Header)
curl -X POST https://<domain>/v1/screen \
  -H "Content-Type: application/json" \
  -H "X-PAYMENT: <signed-authorization>" \
  -d '{"token_address": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"}'
```

---

## 🛠️ Local Setup & Testing

```bash
pip install -r requirements.txt
python test_server.py
python -m uvicorn server:app --host 0.0.0.0 --port 8000
```
