"""Offline service and static-analysis regressions; payment security has its own suite."""

import base64
import json
import time
import unittest
from unittest.mock import AsyncMock, patch
import uuid

from fastapi.testclient import TestClient
from starlette.requests import Request

import analyzer
import server
from x402_payment import encode_header


def request_for(body, method="POST"):
    encoded = json.dumps(body).encode()
    async def receive():
        return {"type": "http.request", "body": encoded, "more_body": False}
    return Request({"type": "http", "method": method, "path": "/v1/screen",
                    "headers": [], "query_string": b""}, receive)


def abi_uint(value):
    return "0x" + f"{value:064x}"


def abi_string(value):
    return "0x" + value.encode().hex().ljust(64, "0")


async def complete_rpc(method, params):
    if method == "eth_getCode":
        return "0x60006000"
    return {
        analyzer.SEL_NAME: abi_string("Fixture Token"),
        analyzer.SEL_SYMBOL: abi_string("FIX"),
        analyzer.SEL_DECIMALS: abi_uint(6),
        analyzer.SEL_TOTAL_SUPPLY: abi_uint(1000000),
        analyzer.SEL_OWNER: abi_uint(0),
    }[params[0]["data"]]


class TestBaseShieldServer(unittest.TestCase):
    def test_self_test_reports_configuration_without_network_or_credentials(self):
        client = TestClient(server.app)
        facilitator = server.payment.facilitator
        with patch.object(facilitator, "bearer_token", "diagnostic-fixture-secret"), \
             patch.object(facilitator, "verify", new_callable=AsyncMock) as verify, \
             patch.object(facilitator, "settle", new_callable=AsyncMock) as settle:
            for url in ("", "https://diagnostic-facilitator.invalid"):
                with self.subTest(configured=bool(url)), patch.object(facilitator, "url", url):
                    response = client.get("/self-test")
                    self.assertEqual(response.status_code, 200)
                    self.assertEqual(response.json()["facilitator_configured"], bool(url))
                    self.assertNotIn("diagnostic-facilitator", response.text)
                    self.assertNotIn("diagnostic-fixture-secret", response.text)
            verify.assert_not_awaited()
            settle.assert_not_awaited()

    def setUp(self):
        self.client = TestClient(server.app)

    def test_root_and_health(self):
        self.assertEqual(self.client.get("/").status_code, 200)
        data = self.client.get("/health").json()
        self.assertEqual(data["status"], "ok")
        self.assertEqual(data["chainId"], 8453)

    def test_configuration_does_not_claim_live_payment_test(self):
        data = self.client.get("/self-test").json()
        self.assertFalse(data["live_payment_tested"])
        self.assertEqual(data["payTo"], server.PAYEE_ADDRESS)

    def test_one_canonical_resource_and_hidden_alias(self):
        manifest = self.client.get("/.well-known/x402").json()
        self.assertEqual(len(manifest["resources"]), 1)
        self.assertEqual(manifest["resources"][0]["method"], "POST")
        self.assertTrue(manifest["resources"][0]["resource"].endswith("/v1/screen"))
        schema = self.client.get("/openapi.json").json()
        self.assertEqual(set(schema["paths"]["/v1/screen"]), {"post"})
        self.assertNotIn("/v1/token-security", schema["paths"])

    def test_unpaid_request_and_alias_return_challenge(self):
        with patch("server.screen_token", new_callable=AsyncMock) as analysis:
            for path in ("/v1/screen", "/v1/token-security"):
                response = self.client.post(path, json={"token_address": analyzer.USDC_BASE})
                self.assertEqual(response.status_code, 402)
                self.assertIn("PAYMENT-REQUIRED", response.headers)
            analysis.assert_not_awaited()

    def test_verified_rpc_failure_is_not_settled_or_returned_as_success(self):
        body = {"token_address": analyzer.USDC_BASE}
        challenge_response = self.client.post("/v1/screen", json=body)
        challenge = json.loads(base64.b64decode(challenge_response.headers["PAYMENT-REQUIRED"]))
        payer = "0x" + "1" * 40
        payload = {
            "x402Version": 2, "resource": challenge["resource"], "accepted": challenge["accepts"][0],
            "payload": {"signature": "0x" + "11" * 65, "authorization": {
                "from": payer, "to": server.PAYEE_ADDRESS, "value": server.PRICE_ATOMIC,
                "validAfter": str(int(time.time()) - 10), "validBefore": str(int(time.time()) + 55),
                "nonce": "0x" + uuid.uuid4().hex + uuid.uuid4().hex,
            }},
        }
        with patch.object(server.payment.facilitator, "verify", new_callable=AsyncMock,
                          return_value={"isValid": True, "payer": payer}) as verify, \
             patch.object(server.payment.facilitator, "settle", new_callable=AsyncMock) as settle, \
             patch("analyzer.rpc_call", new_callable=AsyncMock, side_effect=RuntimeError("private RPC detail")):
            response = self.client.post("/v1/screen", json=body,
                                        headers={"PAYMENT-SIGNATURE": encode_header(payload)})
        self.assertEqual(response.status_code, 502)
        self.assertFalse(response.json()["success"])
        self.assertEqual(response.json()["error"]["code"], "upstream_unavailable")
        self.assertNotIn("PAYMENT-RESPONSE", response.headers)
        self.assertNotIn("private RPC detail", response.text)
        verify.assert_awaited_once()
        settle.assert_not_awaited()


class TestAnalyzer(unittest.IsolatedAsyncioTestCase):
    async def test_static_output_structure_and_no_simulation_claim(self):
        with patch("analyzer.rpc_call", side_effect=complete_rpc):
            data = await analyzer.screen_token(analyzer.USDC_BASE)
        self.assertEqual(data["analysis_type"], "static_onchain_heuristic")
        self.assertEqual(data["verdict"], "LOW_RISK_INDICATORS")
        self.assertEqual(data["risk_score"], 0)
        self.assertTrue(data["analysis_complete"])
        self.assertEqual(data["total_supply"], 1)
        self.assertIn("No transfer", data["limitations"][0])
        self.assertEqual(data["confidence"], "limited")
        self.assertTrue(data["data_sources"])

    async def test_invalid_addresses_never_call_rpc(self):
        with patch("analyzer.rpc_call", new_callable=AsyncMock) as rpc:
            for value in ("", "hello", "0x" + "z" * 40, "0x" + "a" * 39, None):
                with self.assertRaises(ValueError):
                    await analyzer.screen_token(value)
            rpc.assert_not_awaited()

    async def test_missing_owner_is_unknown_not_renounced(self):
        async def rpc(method, params):
            if method == "eth_call" and params[0]["data"] == analyzer.SEL_OWNER:
                raise RuntimeError("private provider detail")
            return await complete_rpc(method, params)
        with patch("analyzer.rpc_call", side_effect=rpc):
            data = await analyzer.screen_token(analyzer.USDC_BASE)
        self.assertIsNone(data["owner"])
        self.assertIsNone(data["is_ownership_renounced"])
        self.assertFalse(data["safe_for_agent_swap"])
        self.assertFalse(data["analysis_complete"])
        self.assertEqual(data["confidence"], "low")
        self.assertNotIn("private provider detail", json.dumps(data))

    async def test_enormous_decimals_are_not_exponentiated(self):
        async def rpc(method, params):
            if method == "eth_call" and params[0]["data"] == analyzer.SEL_DECIMALS:
                return abi_uint(2 ** 256 - 1)
            return await complete_rpc(method, params)
        with patch("analyzer.rpc_call", side_effect=rpc):
            data = await analyzer.screen_token(analyzer.USDC_BASE)
        self.assertIsNone(data["decimals"])
        self.assertIsNone(data["total_supply"])
        self.assertFalse(data["safe_for_agent_swap"])

    async def test_selector_indicators_increase_risk(self):
        async def rpc(method, params):
            if method == "eth_getCode":
                return "0x" + "".join([analyzer.MINT_SELECTORS[0], analyzer.BLACKLIST_SELECTORS[0],
                                       analyzer.PAUSE_SELECTORS[0], analyzer.PROXY_SELECTORS[0]])
            return await complete_rpc(method, params)
        with patch("analyzer.rpc_call", side_effect=rpc):
            data = await analyzer.screen_token(analyzer.USDC_BASE)
        self.assertTrue(data["can_mint"])
        self.assertTrue(data["can_blacklist"])
        self.assertTrue(data["can_pause"])
        self.assertTrue(data["is_proxy"])
        self.assertEqual(data["verdict"], "HIGH_RISK_INDICATORS")
        self.assertFalse(data["safe_for_agent_swap"])

    async def test_no_contract_is_explicit(self):
        with patch("analyzer.rpc_call", new_callable=AsyncMock, return_value="0x"):
            data = await analyzer.screen_token(analyzer.USDC_BASE)
        self.assertFalse(data["is_contract"])
        self.assertEqual(data["verdict"], "NOT_A_CONTRACT")
        self.assertFalse(data["safe_for_agent_swap"])
        self.assertEqual(data["data_sources"][0]["methods"], ["eth_getCode"])

    async def test_malformed_bytecode_is_not_a_safe_result(self):
        with patch("analyzer.rpc_call", new_callable=AsyncMock, return_value=None):
            with self.assertRaises(RuntimeError):
                await analyzer.screen_token(analyzer.USDC_BASE)

    async def test_endpoint_rejects_invalid_address_before_analysis(self):
        with patch("server.screen_token", new_callable=AsyncMock) as analysis:
            response = await server.screen_endpoint(request_for({"token_address": "garbage"}))
        self.assertEqual(response.status_code, 400)
        analysis.assert_not_awaited()

    async def test_endpoint_sanitizes_upstream_errors(self):
        with patch("server.screen_token", new_callable=AsyncMock,
                   side_effect=RuntimeError("secret RPC url")):
            response = await server.screen_endpoint(request_for({"token_address": analyzer.USDC_BASE}))
        self.assertEqual(response.status_code, 502)
        self.assertEqual(json.loads(response.body)["error"]["code"], "upstream_unavailable")
        self.assertNotIn("secret", response.body.decode())


if __name__ == "__main__":
    unittest.main()
