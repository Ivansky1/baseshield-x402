"""Static on-chain ERC-20 risk screening, protected by verified x402 v2 payments."""

from datetime import datetime, timezone
import os

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, ValidationError

from analyzer import screen_token
from x402_payment import PaidOperation, PaymentGate, configured_payee

PAYEE_ADDRESS = configured_payee(legacy_env="PAYMENT_RECIPIENT")
PAYMENT_RECIPIENT = PAYEE_ADDRESS  # Existing deployments and imports remain compatible.
USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
PRICE_ATOMIC = "20000"
PRICE_HUMAN = "$0.02"
CHAIN_ID = "eip155:8453"
DESCRIPTION = (
    "Performs static on-chain ERC-20 risk screening using bytecode, owner, mint, "
    "pause, blacklist, and proxy indicators. No transfer or buy/sell simulation."
)


class ScreenTokenRequest(BaseModel):
    token_address: str = Field(
        pattern=r"^0x[0-9a-fA-F]{40}$", description="Base ERC-20 contract address"
    )


payment = PaymentGate(
    service="BaseShield",
    payee=PAYEE_ADDRESS,
    amount=PRICE_ATOMIC,
    operations=[PaidOperation(
        method="POST", path="/v1/screen", description=DESCRIPTION,
        input_schema=ScreenTokenRequest.model_json_schema(),
        output_schema={
            "type": "object",
            "properties": {
                "success": {"type": "boolean"},
                "network": {"type": "string"},
                "data": {
                    "type": "object",
                    "properties": {
                        "analysis_type": {"const": "static_onchain_heuristic"},
                        "token_address": {"type": "string", "pattern": r"^0x[0-9a-fA-F]{40}$"},
                        "is_contract": {"type": "boolean"},
                        "name": {"type": ["string", "null"]},
                        "symbol": {"type": ["string", "null"]},
                        "decimals": {"type": ["integer", "null"], "minimum": 0, "maximum": 255},
                        "total_supply": {"type": ["number", "null"], "minimum": 0},
                        "owner": {"type": ["string", "null"]},
                        "is_ownership_renounced": {"type": ["boolean", "null"]},
                        "is_proxy": {"type": "boolean"},
                        "can_mint": {"type": "boolean"},
                        "can_blacklist": {"type": "boolean"},
                        "can_pause": {"type": "boolean"},
                        "risk_score": {"type": "integer", "minimum": 0, "maximum": 100},
                        "risk_level": {"enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]},
                        "verdict": {"type": "string"},
                        "risk_factors": {"type": "array", "items": {"type": "string"}},
                        "confidence": {"enum": ["limited", "low"]},
                        "safe_for_agent_swap": {"type": "boolean", "deprecated": True,
                                                "description": "Heuristic compatibility indicator, not trading approval."},
                        "analysis_complete": {"type": "boolean"},
                        "data_gaps": {"type": "array", "items": {"type": "string"}},
                        "data_sources": {"type": "array", "items": {"type": "object"}},
                        "fetched_at": {"type": "string", "format": "date-time"},
                        "network": {"const": "base-mainnet"},
                        "chainId": {"const": 8453},
                        "limitations": {"type": "array", "items": {"type": "string"}},
                    },
                    "required": ["analysis_type", "confidence", "risk_score", "risk_level", "verdict",
                                 "safe_for_agent_swap", "analysis_complete", "data_sources", "limitations"],
                },
                "paid_via": {"const": "x402"},
                "timestamp": {"type": "string", "format": "date-time"},
            },
            "required": ["success", "data", "network", "timestamp"],
        },
        example={"token_address": USDC_BASE},
    )],
    aliases={"/v1/token-security": "/v1/screen"},
)

app = FastAPI(
    title="BaseShield Token Risk Screener", description=DESCRIPTION,
    version="1.1.0", redirect_slashes=False,
)


def error_response(code: str, message: str, status: int = 400) -> JSONResponse:
    return JSONResponse(status_code=status, content={
        "success": False, "error": {"code": code, "message": message},
    })


@app.get("/")
async def root():
    return {
        "service": "BaseShield Token Risk Screener", "version": "1.1.0",
        "description": DESCRIPTION, "network": "base-mainnet",
        "docs": "/docs", "openapi": "/openapi.json", "manifest": "/.well-known/x402",
        "paid_endpoint": "/v1/screen", "price_usd": PRICE_HUMAN, "payee": PAYEE_ADDRESS,
    }


@app.get("/health")
async def health():
    return {
        "status": "ok", "service": "baseshield-x402", "network": "base-mainnet",
        "chainId": 8453, "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/self-test")
async def self_test():
    """Configuration only; this endpoint does not claim live payment verification."""
    return {
        "protocol": "x402", "version": 2, "network": CHAIN_ID,
        "payTo": PAYEE_ADDRESS, "asset": USDC_BASE, "amount_atomic": PRICE_ATOMIC,
        "amount_usd": PRICE_HUMAN, "live_payment_tested": False,
        "facilitator_configured": bool(payment.facilitator.url),
    }


@app.get("/.well-known/x402")
async def x402_manifest(request: Request):
    return payment.manifest(request)


@app.post("/v1/screen", summary="Static ERC-20 risk screening (x402 paid)")
@app.api_route("/v1/screen", methods=["GET", "HEAD"], include_in_schema=False)
@app.api_route("/v1/token-security", methods=["GET", "HEAD", "POST"], include_in_schema=False)
async def screen_endpoint(request: Request):
    # The payment middleware verifies before this handler or any RPC is invoked.
    try:
        if request.method == "POST":
            body = await request.json()
        else:
            body = dict(request.query_params)
        payload = ScreenTokenRequest.model_validate(body)
    except (ValueError, ValidationError):
        return error_response("invalid_request", "Provide a valid token_address (0x and 40 hex digits).")
    try:
        result = await screen_token(payload.token_address)
    except ValueError:
        return error_response("invalid_request", "Provide a valid Base contract address.")
    except Exception:
        return error_response("upstream_unavailable", "On-chain analysis is currently unavailable.", 502)
    return {
        "success": True, "data": result, "paid_via": "x402", "network": "base-mainnet",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


payment.install(app)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
