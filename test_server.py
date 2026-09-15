"""Unit tests for BaseShield x402 server and analyzer."""

import json
import unittest
from fastapi.testclient import TestClient

from server import app, PAYMENT_RECIPIENT, PRICE_ATOMIC, USDC_BASE

client = TestClient(app)


class TestBaseShieldServer(unittest.TestCase):
    def test_health(self):
        resp = client.get("/health")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "ok")
        self.assertEqual(data["chainId"], 8453)

    def test_self_test(self):
        resp = client.get("/self-test")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data["conformant"])
        self.assertEqual(data["protocol"], "x402")
        self.assertEqual(data["version"], 2)
        self.assertEqual(data["network"], "eip155:8453")
        self.assertEqual(data["payTo"], PAYMENT_RECIPIENT)
        self.assertEqual(data["asset"], USDC_BASE)
        self.assertEqual(data["amount_atomic"], PRICE_ATOMIC)

    def test_x402_manifest(self):
        resp = client.get("/.well-known/x402")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["version"], 1)
        self.assertIn("resources", data)
        self.assertGreaterEqual(len(data["resources"]), 1)
        res0 = data["resources"][0]
        self.assertEqual(res0["method"], "POST")
        self.assertIn("/v1/screen", res0["url"])
        self.assertEqual(res0["accepts"][0]["payTo"], PAYMENT_RECIPIENT)
        self.assertEqual(res0["accepts"][0]["asset"], USDC_BASE)
        self.assertIn(PAYMENT_RECIPIENT, data["ownershipProofs"])

    def test_screen_unpaid_returns_402(self):
        """Verify unpaid requests receive HTTP 402 with full x402 challenge BEFORE validation."""
        # Unpaid empty POST
        resp = client.post("/v1/screen")
        self.assertEqual(resp.status_code, 402)
        self.assertIn("Payment-Required", resp.headers)
        body = resp.json()
        self.assertEqual(body["x402Version"], 2)
        self.assertEqual(body["accepts"][0]["scheme"], "exact")
        self.assertEqual(body["accepts"][0]["network"], "eip155:8453")
        self.assertEqual(body["accepts"][0]["payTo"], PAYMENT_RECIPIENT)
        self.assertEqual(body["accepts"][0]["amount"], PRICE_ATOMIC)

    def test_screen_with_payment_canary(self):
        """Verify paid request with test header processes token screening."""
        payload = {"token_address": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"}
        resp = client.post(
            "/v1/screen",
            json=payload,
            headers={"X-PAYMENT": "test-canary-auth"}
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["paid_via"], "x402")
        token_info = data["data"]
        self.assertEqual(token_info["symbol"], "USDC")
        self.assertEqual(token_info["decimals"], 6)
        self.assertTrue(token_info["safe_for_agent_swap"])


if __name__ == "__main__":
    unittest.main()
