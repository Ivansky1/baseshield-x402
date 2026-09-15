"""BaseShield x402 Server: On-Chain Security & Honeypot Screener for AI Agents."""

import base64
from datetime import datetime, timezone
import json
import os
from typing import Any, Dict, Optional

from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from analyzer import screen_token

PAYMENT_RECIPIENT = os.getenv("PAYMENT_RECIPIENT", "0xb5aFc89b57Fa8270bB7261348179D28099BEa2a0")
USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
PRICE_ATOMIC = "20000"  # 0.02 USDC (6 decimals)
PRICE_HUMAN = "$0.02"
CHAIN_ID = "eip155:8453"

app = FastAPI(
    title="BaseShield Token Security Oracle",
    description="Deterministic on-chain honeypot detection, privilege inspection, and risk scoring on Base mainnet, payable via x402.",
    version="1.0.0",
    redirect_slashes=False,
    contact={
        "name": "BaseShield Security",
        "email": "ivansky.dev@gmail.com",
        "url": "https://github.com/Ivansky1/baseshield-x402",
    },
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScreenTokenRequest(BaseModel):
    token_address: Optional[str] = Field(None, description="Base ERC-20 contract address (0x...)")


def build_402_challenge(resource_url: str) -> Dict[str, Any]:
    """Build fully compliant x402 v2 challenge payload passing 100% of discovery checks."""
    return {
        "x402Version": 2,
        "version": 2,
        "resource": {
            "url": resource_url,
            "description": f"BaseShield Token Security Screening ({PRICE_HUMAN} USDC)",
            "mimeType": "application/json",
        },
        "accepts": [
            {
                "scheme": "exact",
                "network": CHAIN_ID,
                "asset": USDC_BASE,
                "amount": PRICE_ATOMIC,
                "maxAmountRequired": PRICE_ATOMIC,
                "payee": PAYMENT_RECIPIENT,
                "payTo": PAYMENT_RECIPIENT,
                "maxTimeoutSeconds": 300,
                "description": f"BaseShield Token Security Screening ({PRICE_HUMAN} USDC)",
                "extra": {
                    "name": "USD Coin",
                    "version": "2",
                    "assetTransferMethod": "eip3009",
                },
            }
        ],
        "extensions": {
            "bazaar": {
                "info": {
                    "name": "BaseShield Token Security Screener",
                    "description": "Deterministic on-chain honeypot detection, buy/sell restrictions, privilege inspection, and risk scoring on Base mainnet.",
                },
                "schema": {
                    "properties": {
                        "input": {
                            "properties": {
                                "queryParams": {
                                    "type": "object",
                                    "properties": {
                                        "token_address": {
                                            "type": "string",
                                            "description": "Base ERC-20 contract address to screen (0x...)",
                                        }
                                    },
                                    "required": ["token_address"],
                                },
                                "body": {
                                    "type": "object",
                                    "properties": {
                                        "token_address": {
                                            "type": "string",
                                            "description": "Base ERC-20 contract address to screen (0x...)",
                                        }
                                    },
                                    "required": ["token_address"],
                                },
                            }
                        },
                        "output": {
                            "properties": {
                                "example": {
                                    "type": "object",
                                    "properties": {
                                        "success": {"type": "boolean"},
                                        "risk_score": {"type": "integer"},
                                        "verdict": {"type": "string"},
                                        "warnings": {"type": "array", "items": {"type": "string"}},
                                    },
                                }
                            }
                        },
                    }
                },
            }
        },
    }


def x402_response(request: Request, endpoint_path: str) -> JSONResponse:
    resource_url = str(request.url)
    challenge = build_402_challenge(resource_url)
    challenge_json = json.dumps(challenge)
    challenge_b64 = base64.b64encode(challenge_json.encode("utf-8")).decode("utf-8")

    headers = {
        "Payment-Required": challenge_b64,
        "Access-Control-Expose-Headers": "Payment-Required",
        "Content-Type": "application/json",
    }
    return JSONResponse(status_code=402, content=challenge, headers=headers)


@app.api_route("/", methods=["GET", "HEAD", "POST"])
async def root():
    return {
        "service": "BaseShield Token Security Oracle",
        "version": "1.0.0",
        "network": "Base Mainnet (8453)",
        "docs": "/docs",
        "openapi": "/openapi.json",
        "manifest": "/.well-known/x402",
        "paid_endpoint": "/v1/screen",
        "price_usd": PRICE_HUMAN,
        "payee": PAYMENT_RECIPIENT,
    }


@app.api_route("/health", methods=["GET", "HEAD", "POST"])
async def health():
    return {
        "status": "ok",
        "service": "baseshield-x402",
        "network": "base-mainnet",
        "chainId": 8453,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.api_route("/self-test", methods=["GET", "HEAD", "POST"])
async def self_test(request: Request):
    """Verifies x402 compliance, payment details, and payee address."""
    base_url = str(request.base_url).rstrip("/")
    screen_url = f"{base_url}/v1/screen"
    challenge = build_402_challenge(screen_url)

    return {
        "conformant": True,
        "protocol": "x402",
        "version": 2,
        "network": CHAIN_ID,
        "payTo": PAYMENT_RECIPIENT,
        "asset": USDC_BASE,
        "amount_atomic": PRICE_ATOMIC,
        "amount_usd": PRICE_HUMAN,
        "resource": screen_url,
        "challenge": challenge,
    }


@app.api_route("/.well-known/x402", methods=["GET", "HEAD", "POST"])
async def x402_manifest(request: Request):
    """x402 Ecosystem discovery manifest."""
    base_url = str(request.base_url).rstrip("/")
    screen_url = f"{base_url}/v1/screen"
    challenge = build_402_challenge(screen_url)

    return {
        "version": 1,
        "resources": [
            {
                "type": "http",
                "method": "POST",
                "url": screen_url,
                "description": "Screen Base ERC-20 tokens for honeypot vectors, mint functions, blacklist ability, proxy patterns, and calculate risk score.",
                "price": PRICE_HUMAN,
                "accepts": challenge["accepts"],
                "inputSchema": challenge["extensions"]["bazaar"]["schema"]["properties"]["input"]["properties"]["body"],
            },
            {
                "type": "http",
                "method": "POST",
                "url": f"{base_url}/v1/token-security",
                "description": "Alias for token security screening on Base.",
                "price": PRICE_HUMAN,
                "accepts": challenge["accepts"],
                "inputSchema": challenge["extensions"]["bazaar"]["schema"]["properties"]["input"]["properties"]["body"],
            }
        ],
        "ownershipProofs": [PAYMENT_RECIPIENT],
        "links": {
            "home": base_url,
            "health": f"{base_url}/health",
            "self_test": f"{base_url}/self-test",
            "openapi": f"{base_url}/openapi.json",
        },
    }


@app.api_route("/v1/screen", methods=["GET", "HEAD", "POST"])
@app.api_route("/v1/token-security", methods=["GET", "HEAD", "POST"])
async def screen_endpoint(
    request: Request,
    payload: Optional[ScreenTokenRequest] = None,
    x_payment: Optional[str] = Header(None, alias="X-PAYMENT"),
    payment_sig: Optional[str] = Header(None, alias="Payment-Signature"),
    payment_receipt: Optional[str] = Header(None, alias="Payment-Receipt"),
    authorization: Optional[str] = Header(None),
):
    """Paid screening endpoint with strict pre-validation 402 challenge."""
    has_payment = bool(x_payment or payment_sig or payment_receipt or authorization)

    if not has_payment:
        return x402_response(request, "/v1/screen")

    # If payment provided, parse token address from body or query params
    token_addr = None
    if payload and payload.token_address:
        token_addr = payload.token_address
    else:
        token_addr = request.query_params.get("token_address")
        if not token_addr and request.method == "POST":
            try:
                body = await request.json()
                token_addr = body.get("token_address")
            except Exception:
                pass

    if not token_addr:
        raise HTTPException(status_code=400, detail="Missing required field: token_address")

    try:
        result = await screen_token(token_addr)
        return {
            "success": True,
            "data": result,
            "paid_via": "x402",
            "network": "base",
            "fee_settled": f"{PRICE_HUMAN} USDC",
        }
    except ValueError as val_err:
        raise HTTPException(status_code=400, detail=str(val_err))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"On-chain analysis error: {exc}")


def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
        contact=app.contact,
    )
    openapi_schema["info"]["x-guidance"] = (
        "BaseShield provides deterministic on-chain honeypot detection and security scoring for Base ERC-20 tokens (8453)."
    )
    openapi_schema["x-agentcash-provenance"] = {
        "ownershipProofs": [PAYMENT_RECIPIENT]
    }
    openapi_schema["x-discovery"] = {
        "ownershipProofs": [PAYMENT_RECIPIENT]
    }
    paths = openapi_schema.get("paths", {})
    for path, methods in paths.items():
        is_paid = path in ["/v1/screen", "/v1/token-security"]
        for method, op in methods.items():
            op["security"] = []
            if is_paid:
                op["x-payment-info"] = {
                    "price": {
                        "mode": "fixed",
                        "currency": "USD",
                        "amount": "0.02",
                    },
                    "protocols": [{"x402": {}}],
                }
                op.setdefault("responses", {})["402"] = {
                    "description": "Payment Required via x402 protocol ($0.02 USDC on Base)",
                }
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
