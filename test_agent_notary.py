"""
Unit Test Suite for Agent-Notary.
Validates cryptographic integrity, causal ordering, ZK invariant proofing,
wire voucher serialization, line-rate public verification, replay protection,
and multi-agent causal graph invariants.
Author: Aniket Agrawal <aniketagrawal@google.com>
"""

import json
import time
import unittest
from agent_notary.models import (
    PolicyInvariant,
    ZKActorVoucher,
    sha256_hex,
    hmac_sha256_hex
)
from agent_notary.merkle_dag import MerkleDAG
from agent_notary.prover import ZKInvariantProver
from agent_notary.verifier import PublicNotaryVerifier
from agent_notary.gateway import AgentNotaryGateway


class TestAgentNotary(unittest.TestCase):

    def setUp(self):
        self.key_id = "notary-key-prod-001"
        self.secret_key = b"super_secret_google_cloud_notary_signing_key_32b"
        self.session_id = "swarm-session-finance-987"

        self.policy_disbursement = PolicyInvariant(
            invariant_id="inv-fin-001",
            rule_type="disbursement_limit",
            parameter_path="amount_usd",
            constraint_expression="<= 25000",
            target_tool="sap_disburse_vendor_payment"
        )

        self.policy_regex_bucket = PolicyInvariant(
            invariant_id="inv-sec-002",
            rule_type="regex_match",
            parameter_path="destination_uri",
            constraint_expression=r"^gs://acme-finance-prod/.*$",
            target_tool="gcs_archive_financial_ledger"
        )

        self.policy_cidr = PolicyInvariant(
            invariant_id="inv-net-003",
            rule_type="network_cidr_whitelist",
            parameter_path="destination_ip",
            constraint_expression="10.240.0, 10.240.1",
            target_tool="vpc_egress_api"
        )

        self.gateway = AgentNotaryGateway(
            gateway_key_id=self.key_id,
            gateway_private_key=self.secret_key,
            session_id=self.session_id,
            active_policies=[self.policy_disbursement, self.policy_regex_bucket, self.policy_cidr]
        )

    def test_policy_invariant_evaluation(self):
        """Test evaluation of deterministic policy constraints."""
        valid_params = {"amount_usd": 15000, "vendor_id": "VEND-88"}
        self.assertTrue(self.policy_disbursement.evaluate(valid_params))

        invalid_params = {"amount_usd": 35000, "vendor_id": "VEND-88"}
        self.assertFalse(self.policy_disbursement.evaluate(invalid_params))

        valid_uri = {"destination_uri": "gs://acme-finance-prod/ledger_2026.parquet"}
        self.assertTrue(self.policy_regex_bucket.evaluate(valid_uri))

        invalid_uri = {"destination_uri": "gs://attacker-bucket-exfil/leak.txt"}
        self.assertFalse(self.policy_regex_bucket.evaluate(invalid_uri))

        valid_ip = {"destination_ip": "10.240.0.45"}
        self.assertTrue(self.policy_cidr.evaluate(valid_ip))

        invalid_ip = {"destination_ip": "192.168.1.1"}
        self.assertFalse(self.policy_cidr.evaluate(invalid_ip))

    def test_zk_prover_success_and_violation(self):
        """Test ZK Invariant Prover emits valid proofs or raises violations."""
        prover = ZKInvariantProver(self.secret_key)
        pub_ctx = {"agent_id": "agent-lead", "target_tool": "sap_disburse_vendor_payment", "session_id": "s-1"}

        proof = prover.generate_invariant_proof(
            invariant=self.policy_disbursement,
            public_context=pub_ctx,
            private_parameters={"amount_usd": 12000}
        )
        self.assertIsNotNone(proof.zk_proof_hex)
        self.assertGreater(len(proof.circuit_commitment), 0)

        # Violation should raise ValueError
        with self.assertRaises(ValueError):
            prover.generate_invariant_proof(
                invariant=self.policy_disbursement,
                public_context=pub_ctx,
                private_parameters={"amount_usd": 99999}
            )

    def test_merkle_dag_causal_ordering(self):
        """Test Lamport clock increments and causal linking in Merkle-DAG."""
        dag = MerkleDAG(swarm_session_id="test-session")
        n1 = dag.append_action("act-1", "agent-a", "read_db", "paramhash1", "outhash1")
        self.assertEqual(n1.causal_lamport_ts, 1)

        n2 = dag.append_action("act-2", "agent-b", "calc_tax", "paramhash2", "outhash2", parent_node_ids=["act-1"])
        self.assertEqual(n2.causal_lamport_ts, 2)
        self.assertIn(n1.node_hash, n2.parent_hashes)

        n3 = dag.append_action("act-3", "agent-c", "generate_pdf", "paramhash3", "outhash3", parent_node_ids=["act-2"])
        self.assertEqual(n3.causal_lamport_ts, 3)

        root = dag.compute_frontier_merkle_root()
        self.assertIsNotNone(root)
        self.assertEqual(len(root), 64)

    def test_end_to_end_notarization_and_verification(self):
        """Test gateway intercepts, mints voucher, and verifies payload."""
        tool_params = {
            "amount_usd": 20000,
            "vendor_id": "VEND-GOOGLE-01",
            "invoice_num": "INV-2026-X9"
        }

        wire_payload, voucher = self.gateway.notarize_tool_call(
            agent_id="finance-agent-alpha",
            tool_name="sap_disburse_vendor_payment",
            tool_params=tool_params
        )

        self.assertIn("headers", wire_payload)
        self.assertIn("x-agent-notary-voucher", wire_payload["headers"])

        # Receiving endpoint verification
        res = self.gateway.verify_wire_invocation(wire_payload)
        self.assertTrue(res.is_valid, f"Verification failed: {res.error_reason}")
        self.assertGreater(res.verification_latency_us, 0)
        self.assertEqual(res.proofs_verified_count, 1)

    def test_adversarial_tamper_detection(self):
        """Test verifier rejects any tampered parameters or modified signature."""
        tool_params = {"amount_usd": 5000, "vendor_id": "VEND-GOOD"}
        wire_payload, voucher = self.gateway.notarize_tool_call(
            agent_id="finance-agent-alpha",
            tool_name="sap_disburse_vendor_payment",
            tool_params=tool_params
        )

        # Attack 1: Adversary escalates amount from 5000 to 500000 in transit
        tampered_payload = dict(wire_payload)
        tampered_payload["params"] = {"amount_usd": 500000, "vendor_id": "VEND-GOOD"}
        res1 = self.gateway.verify_wire_invocation(tampered_payload)
        self.assertFalse(res1.is_valid)
        self.assertIn("ParameterBindingMismatch", res1.error_reason)

        # Attack 2: Adversary modifies signature
        raw_header = wire_payload["headers"]["x-agent-notary-voucher"]
        vchr = ZKActorVoucher.from_wire_header(raw_header)
        vchr.notary_signature = sha256_hex("FORGED_SIGNATURE")
        tampered_payload2 = dict(wire_payload)
        tampered_payload2["headers"] = {"x-agent-notary-voucher": vchr.to_wire_header()}
        res2 = self.gateway.verify_wire_invocation(tampered_payload2)
        self.assertFalse(res2.is_valid)
        self.assertIn("SignatureMismatch", res2.error_reason)

    def test_untrusted_key_rejection(self):
        """Test verifier rejects vouchers signed by an unknown/untrusted key ID."""
        verifier = PublicNotaryVerifier(trusted_notary_public_keys={"other-key": b"key2"})
        tool_params = {"amount_usd": 1000}
        _, voucher = self.gateway.notarize_tool_call(
            agent_id="test-agent",
            tool_name="sap_disburse_vendor_payment",
            tool_params=tool_params
        )
        params_hash = sha256_hex(json.dumps(tool_params, sort_keys=True))
        res = verifier.verify_voucher(voucher, params_hash)
        self.assertFalse(res.is_valid)
        self.assertIn("UntrustedNotaryKey", res.error_reason)

    def test_replay_attack_expired_timestamp(self):
        """Test verifier detects replay attacks with expired timestamps."""
        tool_params = {"amount_usd": 1000}
        _, voucher = self.gateway.notarize_tool_call(
            agent_id="test-agent",
            tool_name="sap_disburse_vendor_payment",
            tool_params=tool_params
        )
        params_hash = sha256_hex(json.dumps(tool_params, sort_keys=True))
        # 10 minutes skew exceeds 5 minute threshold
        res = self.gateway.verifier.verify_voucher(voucher, params_hash, max_clock_skew_ns=1_000_000)
        # Give small sleep or test small skew
        self.assertTrue(res.is_valid)  # Valid under default, but if voucher timestamp backdated:
        voucher_backdated = ZKActorVoucher.from_wire_header(voucher.to_wire_header())
        voucher_backdated.timestamp_ns = time.time_ns() - 1000_000_000_000  # 16 mins ago
        # Update signature to isolate timestamp expiry
        canonical_msg = (
            f"{voucher_backdated.voucher_id}:{voucher_backdated.root_merkle_hash}:"
            f"{voucher_backdated.action_leaf_hash}:{voucher_backdated.agent_id}:"
            f"{voucher_backdated.target_tool}:{voucher_backdated.causal_lamport_ts}:{voucher_backdated.timestamp_ns}"
        )
        voucher_backdated.notary_signature = hmac_sha256_hex(self.secret_key, canonical_msg)
        res_backdated = self.gateway.verifier.verify_voucher(voucher_backdated, params_hash)
        self.assertFalse(res_backdated.is_valid)
        self.assertIn("ExpiredVoucher", res_backdated.error_reason)

    def test_wire_header_roundtrip_compactness(self):
        """Test that voucher serializes to a compact base64 header (< 2 KB)."""
        tool_params = {"amount_usd": 1000}
        _, voucher = self.gateway.notarize_tool_call(
            agent_id="test-agent",
            tool_name="sap_disburse_vendor_payment",
            tool_params=tool_params
        )
        header = voucher.to_wire_header()
        self.assertLess(len(header), 2048)  # Fits cleanly in standard HTTP header limits (8 KB)


if __name__ == "__main__":
    unittest.main()
