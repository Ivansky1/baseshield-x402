"""Static on-chain ERC-20 indicators. This does not simulate transfers or trades."""

import asyncio
from datetime import datetime, timezone
import os
import re
from typing import Any, Dict, Optional

import httpx

BASE_RPCS = [
    os.getenv("BASE_RPC_URL", "https://mainnet.base.org"),
    "https://base-rpc.publicnode.com",
    "https://1rpc.io/base",
]
WETH_BASE = "0x4200000000000000000000000000000000000006"
USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
SEL_NAME = "0x06fdde03"
SEL_SYMBOL = "0x95d89b41"
SEL_DECIMALS = "0x313ce567"
SEL_TOTAL_SUPPLY = "0x18160ddd"
SEL_OWNER = "0x8da5cb5b"
MINT_SELECTORS = ["40c10f19", "a0712d68"]
BLACKLIST_SELECTORS = ["f9f92be4", "44337666", "ebf08819"]
PAUSE_SELECTORS = ["0234050b", "8456cb59"]
PROXY_SELECTORS = ["5c60da1b"]
LIMITATIONS = [
    "No transfer, buy, sell, router, or honeypot simulation is performed.",
    "Bytecode selector matches are heuristic and may produce false positives or negatives.",
    "Proxy implementations and all external contract dependencies are not recursively inspected.",
    "A low score does not establish trading safety or predict future contract changes.",
    "safe_for_agent_swap is a deprecated compatibility indicator, not trading approval.",
]


def _clean_address(addr: str) -> str:
    if not isinstance(addr, str) or not re.fullmatch(r"0x[0-9a-fA-F]{40}", addr):
        raise ValueError("Invalid EVM address format.")
    return addr.lower()


async def rpc_call(method: str, params: list, timeout: float = 5.0) -> Any:
    """Read Base JSON-RPC with bounded timeouts and sanitized upstream failures."""
    payload = {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
    async with httpx.AsyncClient(timeout=httpx.Timeout(timeout, connect=3.0)) as client:
        for rpc in BASE_RPCS:
            try:
                response = await client.post(rpc, json=payload)
                response.raise_for_status()
                data = response.json()
                if not isinstance(data, dict) or "error" in data or "result" not in data:
                    continue
                return data["result"]
            except (httpx.HTTPError, ValueError, TypeError):
                continue
    raise RuntimeError("Base RPC data is unavailable.")


def _decode_string(hex_data: Any) -> Optional[str]:
    if not isinstance(hex_data, str) or not re.fullmatch(r"0x(?:[0-9a-fA-F]{2}){32,4096}", hex_data):
        return None
    clean = hex_data[2:]
    try:
        offset = int(clean[:64], 16)
        if offset == 32 and len(clean) >= 128:
            length = int(clean[64:128], 16)
            if length > 1024 or len(clean) < 128 + length * 2:
                return None
            encoded = clean[128:128 + length * 2]
        else:
            encoded = clean[:64]
        return bytes.fromhex(encoded).decode("utf-8").replace("\x00", "").strip() or None
    except (ValueError, UnicodeDecodeError):
        return None


def _decode_uint(hex_data: Any) -> Optional[int]:
    if not isinstance(hex_data, str) or not re.fullmatch(r"0x[0-9a-fA-F]{64}", hex_data):
        return None
    return int(hex_data[2:], 16)


def _decode_address(hex_data: Any) -> Optional[str]:
    if not isinstance(hex_data, str) or not re.fullmatch(r"0x0{24}[0-9a-fA-F]{40}", hex_data):
        return None
    return "0x" + hex_data[-40:].lower()


async def screen_token(token_address: str) -> Dict[str, Any]:
    token = _clean_address(token_address)
    code = await rpc_call("eth_getCode", [token, "latest"])
    if not isinstance(code, str) or not re.fullmatch(r"0x(?:[0-9a-fA-F]{2}){0,100000}", code):
        raise RuntimeError("Invalid Base RPC bytecode response.")
    metadata = {
        "analysis_type": "static_onchain_heuristic",
        "confidence": "limited",
        "data_sources": [{"source": "base_json_rpc", "network": "eip155:8453",
                          "methods": ["eth_getCode", "eth_call"], "block_tag": "latest"}],
        "limitations": list(LIMITATIONS),
        "network": "base-mainnet", "chainId": 8453,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
    }
    if code == "0x":
        metadata["data_sources"][0]["methods"] = ["eth_getCode"]
        return {
            **metadata, "token_address": token, "is_contract": False,
            "risk_score": 100, "risk_level": "CRITICAL", "verdict": "NOT_A_CONTRACT",
            "summary": "No deployed bytecode was returned at the latest block.",
            "safe_for_agent_swap": False, "analysis_complete": True, "data_gaps": [],
        }

    selectors = [SEL_NAME, SEL_SYMBOL, SEL_DECIMALS, SEL_TOTAL_SUPPLY, SEL_OWNER]
    raw = await asyncio.gather(
        *(rpc_call("eth_call", [{"to": token, "data": selector}, "latest"]) for selector in selectors),
        return_exceptions=True,
    )
    name, symbol = _decode_string(raw[0]), _decode_string(raw[1])
    decimals, supply_raw, owner = _decode_uint(raw[2]), _decode_uint(raw[3]), _decode_address(raw[4])
    if decimals is not None and not 0 <= decimals <= 255:
        decimals = None
    total_supply = supply_raw / (10 ** decimals) if supply_raw is not None and decimals is not None else None
    gaps = [key for key, value in [
        ("name", name), ("symbol", symbol), ("decimals", decimals),
        ("total_supply", supply_raw), ("owner", owner),
    ] if value is None]

    bytecode = code[2:].lower()
    can_mint = any(selector in bytecode for selector in MINT_SELECTORS)
    can_blacklist = any(selector in bytecode for selector in BLACKLIST_SELECTORS)
    can_pause = any(selector in bytecode for selector in PAUSE_SELECTORS)
    is_proxy = any(selector in bytecode for selector in PROXY_SELECTORS)
    renounced = (owner in {"0x" + "0" * 40, "0x" + "0" * 36 + "dead"}) if owner is not None else None

    score = 10
    factors = []
    for present, weight, explanation in [
        (is_proxy, 15, "Proxy implementation selector found; implementation may be upgradeable."),
        (can_mint, 30, "Mint selector found; permissions and reachability are not established."),
        (can_blacklist, 25, "Blacklist or freeze selector found."),
        (can_pause, 15, "Pause selector found."),
    ]:
        if present:
            score += weight
            factors.append(explanation)
    if renounced is None:
        factors.append("owner() could not be decoded; ownership status is unknown.")
    elif not renounced:
        score += 15
        factors.append("owner() returned a nonzero, non-burn address.")
    else:
        score = max(0, score - 10)
    score = min(100, max(0, score))
    if score <= 25:
        level, verdict = "LOW", "LOW_RISK_INDICATORS"
    elif score <= 55:
        level, verdict = "MEDIUM", "PROCEED_WITH_CAUTION"
    elif score <= 75:
        level, verdict = "HIGH", "ELEVATED_RISK"
    else:
        level, verdict = "CRITICAL", "HIGH_RISK_INDICATORS"
    complete = not gaps
    if not complete:
        metadata["confidence"] = "low"
        metadata["limitations"].append("Some contract reads failed or returned unsupported data; missing values are null.")
    return {
        **metadata, "token_address": token, "is_contract": True,
        "name": name, "symbol": symbol, "decimals": decimals, "total_supply": total_supply,
        "owner": owner, "is_ownership_renounced": renounced, "is_proxy": is_proxy,
        "can_mint": can_mint, "can_blacklist": can_blacklist, "can_pause": can_pause,
        "risk_score": score, "risk_level": level, "verdict": verdict, "risk_factors": factors,
        "safe_for_agent_swap": complete and score <= 50,
        "analysis_complete": complete, "data_gaps": gaps,
    }
