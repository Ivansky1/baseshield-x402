"""Base on-chain token security and contract risk analyzer."""

import asyncio
import json
import logging
import re
from typing import Any, Dict, List, Optional
import urllib.request

logger = logging.getLogger("baseshield.analyzer")

BASE_RPCS = [
    "https://mainnet.base.org",
    "https://base-rpc.publicnode.com",
    "https://1rpc.io/base",
]

# Canonical tokens on Base
WETH_BASE = "0x4200000000000000000000000000000000000006"
USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"

# Standard ERC-20 Function Selectors
SEL_NAME = "0x06fdde03"          # name()
SEL_SYMBOL = "0x95d89b41"        # symbol()
SEL_DECIMALS = "0x313ce567"      # decimals()
SEL_TOTAL_SUPPLY = "0x18160ddd"  # totalSupply()
SEL_OWNER = "0x8da5cb5b"         # owner()

# Suspicious / Privileged function selectors in bytecode
MINT_SELECTORS = ["40c10f19", "a0712d68"]                   # mint(address,uint256), mint(uint256)
BLACKLIST_SELECTORS = ["f9f92be4", "44337666", "ebf08819"] # blacklist/freeze
PAUSE_SELECTORS = ["0234050b", "8456cb59"]                 # pause(), pause(address)
PROXY_SELECTORS = ["5c60da1b"]                             # implementation()


def _clean_address(addr: str) -> str:
    addr = str(addr or "").strip().lower()
    if not re.fullmatch(r"0x[0-9a-f]{40}", addr):
        raise ValueError("Invalid EVM address format. Expected 0x followed by 40 hex characters.")
    return addr


async def rpc_call(method: str, params: list, timeout: float = 5.0) -> Any:
    """Execute JSON-RPC call with automatic fallback across multiple Base RPC endpoints."""
    payload = json.dumps({"jsonrpc": "2.0", "method": method, "params": params, "id": 1}).encode("utf-8")
    
    last_err = None
    for rpc in BASE_RPCS:
        try:
            req = urllib.request.Request(
                rpc,
                data=payload,
                headers={"Content-Type": "application/json", "User-Agent": "BaseShield-Oracle/1.0"}
            )
            loop = asyncio.get_event_loop()
            res_bytes = await loop.run_in_executor(None, lambda: urllib.request.urlopen(req, timeout=timeout).read())
            data = json.loads(res_bytes.decode("utf-8"))
            if "error" in data:
                raise ValueError(data["error"].get("message", "RPC error"))
            return data.get("result")
        except Exception as exc:
            last_err = exc
            continue

    raise RuntimeError(f"All Base RPC nodes failed. Last error: {last_err}")


def _decode_string(hex_data: Optional[str]) -> str:
    """Safely decode an ABI-encoded string or bytes32 from eth_call."""
    if not hex_data or hex_data == "0x":
        return "Unknown"
    clean = hex_data[2:]
    if len(clean) < 64:
        return "Unknown"

    try:
        offset = int(clean[:64], 16)
        if offset == 32 and len(clean) >= 128:
            length = int(clean[64:128], 16)
            str_hex = clean[128 : 128 + length * 2]
            return bytes.fromhex(str_hex).decode("utf-8", errors="ignore").replace("\x00", "").strip()
        else:
            raw = bytes.fromhex(clean[:64]).decode("utf-8", errors="ignore").replace("\x00", "").strip()
            if raw:
                return raw
    except Exception:
        pass
    return "Unknown"


def _decode_uint(hex_data: Optional[str]) -> int:
    """Decode ABI uint256 from eth_call."""
    if not hex_data or hex_data == "0x":
        return 0
    try:
        return int(hex_data, 16)
    except Exception:
        return 0


def _decode_address(hex_data: Optional[str]) -> str:
    """Decode ABI address from eth_call."""
    if not hex_data or hex_data == "0x" or len(hex_data) < 66:
        return "0x0000000000000000000000000000000000000000"
    return "0x" + hex_data[-40:].lower()


async def screen_token(token_address: str) -> Dict[str, Any]:
    """Perform comprehensive on-chain security screening of an ERC-20 token on Base."""
    token = _clean_address(token_address)

    # 1. Fetch Bytecode
    code = await rpc_call("eth_getCode", [token, "latest"])
    if not code or code == "0x" or len(code) <= 2:
        return {
            "token_address": token,
            "is_contract": False,
            "risk_score": 100,
            "risk_level": "CRITICAL",
            "verdict": "NOT_A_CONTRACT",
            "summary": "Target address is an EOA or un-deployed contract.",
            "safe_for_agent_swap": False,
        }

    bytecode_clean = code[2:].lower()

    # 2. Call standard ERC-20 methods concurrently
    name_call = rpc_call("eth_call", [{"to": token, "data": SEL_NAME}, "latest"])
    sym_call = rpc_call("eth_call", [{"to": token, "data": SEL_SYMBOL}, "latest"])
    dec_call = rpc_call("eth_call", [{"to": token, "data": SEL_DECIMALS}, "latest"])
    supply_call = rpc_call("eth_call", [{"to": token, "data": SEL_TOTAL_SUPPLY}, "latest"])
    owner_call = rpc_call("eth_call", [{"to": token, "data": SEL_OWNER}, "latest"])

    raw_name, raw_sym, raw_dec, raw_supply, raw_owner = await asyncio.gather(
        name_call, sym_call, dec_call, supply_call, owner_call, return_exceptions=True
    )

    name = _decode_string(raw_name) if isinstance(raw_name, str) else "Unknown Token"
    symbol = _decode_string(raw_sym) if isinstance(raw_sym, str) else "UNK"
    decimals = _decode_uint(raw_dec) if isinstance(raw_dec, str) else 18
    total_supply_raw = _decode_uint(raw_supply) if isinstance(raw_supply, str) else 0
    owner = _decode_address(raw_owner) if isinstance(raw_owner, str) else "0x0000000000000000000000000000000000000000"

    total_supply = total_supply_raw / (10 ** decimals) if decimals > 0 else total_supply_raw

    # 3. Analyze Bytecode for Vulnerabilities / Privileged Access
    can_mint = any(sel in bytecode_clean for sel in MINT_SELECTORS)
    can_blacklist = any(sel in bytecode_clean for sel in BLACKLIST_SELECTORS)
    can_pause = any(sel in bytecode_clean for sel in PAUSE_SELECTORS)
    is_proxy = any(sel in bytecode_clean for sel in PROXY_SELECTORS)
    
    zero_address = "0x0000000000000000000000000000000000000000"
    dead_address = "0x000000000000000000000000000000000000dead"
    is_ownership_renounced = (owner == zero_address or owner == dead_address)

    # 4. Risk Assessment & Heuristics
    risk_factors = []
    risk_score = 10  # Baseline risk

    if is_proxy:
        risk_score += 15
        risk_factors.append("Upgradeable proxy contract detected (implementation can change)")

    if can_mint:
        risk_score += 30
        risk_factors.append("Arbitrary mint function selector detected in bytecode")

    if can_blacklist:
        risk_score += 25
        risk_factors.append("Blacklist or balance freeze mechanism detected")

    if can_pause:
        risk_score += 15
        risk_factors.append("Transfer pause mechanism detected")

    if not is_ownership_renounced:
        risk_score += 15
        risk_factors.append(f"Contract owner is active ({owner})")
    else:
        risk_score = max(0, risk_score - 10)

    risk_score = min(100, max(0, risk_score))

    if risk_score <= 25:
        risk_level = "LOW"
        verdict = "SAFE_FOR_AGENT_SWAP"
    elif risk_score <= 55:
        risk_level = "MEDIUM"
        verdict = "PROCEED_WITH_CAUTION"
    elif risk_score <= 75:
        risk_level = "HIGH"
        verdict = "ELEVATED_RISK"
    else:
        risk_level = "CRITICAL"
        verdict = "DO_NOT_TRADE_HONEYPOT_RISK"

    return {
        "token_address": token,
        "name": name,
        "symbol": symbol,
        "decimals": decimals,
        "total_supply": total_supply,
        "owner": owner,
        "is_ownership_renounced": is_ownership_renounced,
        "is_proxy": is_proxy,
        "can_mint": can_mint,
        "can_blacklist": can_blacklist,
        "can_pause": can_pause,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "verdict": verdict,
        "risk_factors": risk_factors,
        "safe_for_agent_swap": (risk_score <= 50),
        "network": "base-mainnet",
        "chainId": 8453,
    }
