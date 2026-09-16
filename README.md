# BaseShield — static token risk screening

Performs static on-chain ERC-20 inspection on Base: deployed bytecode, metadata,
owner(), and selector indicators for mint, blacklist, pause, and proxy behavior.
**It does not simulate transfers, buys, sells, or honeypots.**

## Operations and price

| Method | Path | Description |
| --- | --- | --- |
| POST | /v1/screen | Static risk screening, 0.02 USDC per successful request |
| GET | / | Service information |
| GET | /health | Process health; not an upstream or payment readiness test |
| GET | /self-test | Configuration information only |
| GET | /.well-known/x402 | One canonical paid operation |
| GET | /openapi.json | Operation-level payment metadata and request/response schemas |

POST /v1/screen accepts {"token_address":"0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"}.
Addresses must contain 0x and 40 hexadecimal characters.

GET /v1/screen and GET/POST /v1/token-security remain compatibility routes;
they use the same payment gate and are hidden from OpenAPI and discovery.
HEAD requests return a payment challenge and do not execute or settle.

## Interpreting a result

The response retains data.risk_score (0–100), risk_level, owner, and selector
indicator fields. It now includes:

- analysis_type: static_onchain_heuristic
- confidence: limited, or low when reads are incomplete
- data_sources and fetched_at
- analysis_complete, data_gaps, and limitations
- LOW_RISK_INDICATORS instead of an absolute safe-trading verdict

Missing metadata remains null. Failure to read owner() is unknown ownership,
never proof of renunciation. Invalid or unavailable bytecode returns a sanitized
upstream_unavailable error. Decimal counts outside the ERC-20 uint8 range are
rejected before supply scaling.

safe_for_agent_swap remains a deprecated compatibility indicator for complete
reads with a heuristic score at most 50. **It is not trading approval.**
Selector matching has false positives and negatives. Proxy implementations are
not recursively analyzed; controls and contract behavior can change after a read.

## x402 v2 payments

- Network: Base mainnet, eip155:8453.
- Asset: USDC, 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913.
- Amount: 20000 atomic units (0.02 USDC, six decimals).
- Default payee: 0xb5aFc89b57Fa8270bB7261348179D28099BEa2a0.
- Payee configuration precedence: PAYEE_ADDRESS, then PAYMENT_RECIPIENT, then default.
- Scheme: exact, EIP-3009 authorization, x402Version: 2.

1. A missing PAYMENT-SIGNATURE returns 402 with a Base64 JSON PAYMENT-REQUIRED
   challenge header and a machine-readable error body.
2. An official x402 client signs the advertised USDC authorization and sends its
   Base64-encoded v2 PaymentPayload in PAYMENT-SIGNATURE.
3. The local gate validates the payload and expected network, asset, amount,
   payee, scheme, and resource, then uses the official Python SDK facilitator
   client for POST /verify.
4. Only verified requests reach the analyzer. A successful business response is
   buffered while the facilitator's POST /settle processes the payment.
5. Only successful settlement releases the data and canonical PAYMENT-RESPONSE.
   Failed business requests are not settled; settlement failure does not release
   the buffered result.

Arbitrary Authorization, Payment-Receipt, Payment-Response, X-PAYMENT, and
x-payment-response input never authorize access. Legacy payment formats are
unsupported. The canonical challenge/settlement headers are exposed through CORS.

EIP-3009 cryptographically signs the token transfer, not the resource URI or
request body. Resource checking here is application-level. On-chain nonce
consumption prevents repeated successful settlement; local in-flight suppression
is only per process. This is not a claim of global exactly-once execution.
The configured facilitator is a trust boundary for cryptography, authorization
state, balances, and settlement confirmation.

## Configuration and running

Required for paid execution: X402_FACILITATOR_URL, an explicit trusted HTTPS
facilitator base URL supporting exact EIP-3009 USDC on Base mainnet. There is no
automatic mainnet facilitator default. Missing configuration fails closed.

Optional:

- X402_PUBLIC_BASE_URL: canonical HTTPS origin for advertised resources.
- X402_FACILITATOR_BEARER_TOKEN: static bearer token, only for providers that
  support it. Provider-specific rotating JWT generation, including CDP JWT
  provisioning, is not implemented.
- PAYEE_ADDRESS and legacy PAYMENT_RECIPIENT: nonzero EVM payee address.
- BASE_RPC_URL: primary Base JSON-RPC URL; public RPC fallbacks remain.
- PORT: HTTP port, default 8000.

Install and start:

```bash
python -m pip install -r requirements.txt
python -m uvicorn server:app --host 0.0.0.0 --port 8000
```

Example unpaid request:

```bash
curl -i -X POST http://localhost:8000/v1/screen \
  -H "Content-Type: application/json" \
  -d '{"token_address":"0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"}'
```

Use the [official Python client examples](https://github.com/x402-foundation/x402/tree/main/examples/python)
to produce PAYMENT-SIGNATURE; a random string or a settlement response is not a
valid payment payload. Wire behavior follows the
[v2 specification](https://github.com/x402-foundation/x402/blob/main/specs/x402-specification-v2.md),
[HTTP transport](https://github.com/x402-foundation/x402/blob/main/specs/transports-v2/http.md),
and [Bazaar extension](https://github.com/x402-foundation/x402/blob/main/specs/extensions/bazaar.md).
The well-known manifest and OpenAPI x-payment-info are service discovery
conventions; they are not proof of verified ownership or crawler acceptance.

## Offline regression tests

```bash
python -m pip install --require-hashes -r requirements.lock -r requirements-dev.txt
python -m pytest -q
python -m compileall .
```

test_payment_security.py exercises the real application with a mocked
facilitator, including fake-header denial before business execution, malformed
payloads, binding failures, successful verification/settlement, settlement
failure, and aliases. test_server.py covers analyzer structure, invalid
addresses, unknown ownership, excessive decimals, and truthful upstream errors.
No funded wallet, external RPC call, or real USDC transfer is required.

Tests do not prove production facilitator credentials, mainnet settlement,
deployment readiness, or the safety of a token.

## Deployment verification notes

The payment dependency is pinned to official `x402==2.23.0`. Tests use a mocked
facilitator: they prove the local payment boundary, not live settlement. Configure
`X402_FACILITATOR_URL` to a trusted HTTPS facilitator that supports exact payments
on `eip155:8453`. No mainnet facilitator is assumed. If the provider requires
short-lived CDP JWTs, supply a maintained authentication adapter/token provisioning;
this service does not generate CDP JWTs automatically.

`X402_PUBLIC_BASE_URL` should be the deployed HTTPS origin. A settlement timeout
can be ambiguous after broadcast: reconcile the authorization/chain before paying
again. The local nonce guard is bounded and process-local; on-chain authorization
consumption and facilitator verification remain necessary across replicas/restarts.
No distributed rate limiter or durable payment/recovery database is introduced.
Request bodies are limited to 64 KiB, buffered responses to 2 MiB. HEAD is discovery
only (402); it never verifies, executes a paid operation, or settles.

CI runs the entire pytest suite on Python 3.12, including
`test_fake_header_does_not_unlock_resource`, on pushes and pull requests. This
workflow must be enabled and configured as a required check in repository hosting
to block merges; merely adding the workflow does not change branch protections.

## Locked installation and settlement recovery

`requirements.lock` pins the complete runtime and test dependency closure with
official PyPI artifact SHA256 hashes. A separate clean CPython 3.12.10 environment
was installed and tested with the released x402 2.23.0 wheel for this repository;
no SDK source checkout or PYTHONPATH override is required. Install with:

```bash
python -m pip install --require-hashes -r requirements.lock -r requirements-dev.txt
python -m pytest -q
```

CI uses the same hashed installation and the `payment-security` job. Requiring
that job before merging is a separate repository branch-protection setting.

If settlement returns `settlement_pending` with a validated transaction hash,
the service returns HTTP 503 `payment_settlement_pending` with that hash. A
transport failure or ambiguous receipt returns `payment_settlement_unknown`.
Both omit PAYMENT-REQUIRED/PAYMENT-RESPONSE and set `retry_new_payment: false`:
reconcile the existing authorization before paying again. The process-local
guard retains that outcome for the authorization lifetime; a duplicate does not
rerun business work or settlement. Successfully used/in-flight authorizations
return 409 on local reuse, without requesting a new payment.

There is no automatic settlement retry, durable cross-replica reconciliation,
or refund mechanism. On-chain nonce consumption alone is not proof of a transfer
(an authorization can be canceled); recovery must verify the matching successful
chain receipt and transfer/authorization events with the trusted provider.

The regenerated `uv.lock` includes x402 and the pinned pytest development group.
`uv sync --frozen` uses that full lock on Python 3.12.
