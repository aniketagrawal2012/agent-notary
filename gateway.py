"""
Agent-Notary: Cloud Agent Interceptor Gateway.
Intercepts agentic tool invocations at the wire boundary, mints ZKA-Vouchers,
and enforces non-repudiable audit logging.
Author: Aniket Agrawal <aniketagrawal@google.com>
"""

from __future__ import annotations
import json
import time
from typing import Any, Dict, List, Optional, Tuple
import uuid
from agent_notary.models import (
    PolicyInvariant,
    ZKActorVoucher,
    ZKInvariantProof,
    compute_action_node_hash,
    hmac_sha256_hex,
    sha256_hex
)
from agent_notary.merkle_dag import MerkleDAG
from agent_notary.prover import ZKInvariantProver
from agent_notary.verifier import PublicNotaryVerifier, VoucherVerificationResult


class AgentNotaryGateway:
    """
    Cloud Gateway Interceptor deployed at the boundary between
    autonomous agent swarms and destination tool execution APIs.
    """

    def __init__(
        self,
        gateway_key_id: str,
        gateway_private_key: bytes,
        session_id: str,
        active_policies: Optional[List[PolicyInvariant]] = None
    ):
        self.key_id = gateway_key_id
        self.private_key = gateway_private_key
        self.session_id = session_id
        self.policies = active_policies or []
        self.dag = MerkleDAG(swarm_session_id=session_id)
        self.prover = ZKInvariantProver(prover_private_key=gateway_private_key)
        self.verifier = PublicNotaryVerifier(trusted_notary_public_keys={gateway_key_id: gateway_private_key})

    def notarize_tool_call(
        self,
        agent_id: str,
        tool_name: str,
        tool_params: Dict[str, Any],
        parent_action_ids: Optional[List[str]] = None
    ) -> Tuple[Dict[str, Any], ZKActorVoucher]:
        """
        Intercepts tool call, proves applicable policy invariants,
        records action in Merkle-DAG, and mints an attested ZKA-Voucher.
        Returns the annotated tool payload (with wire headers) and the voucher.
        """
        voucher_id = f"vchr-{uuid.uuid4().hex[:12]}"
        timestamp_ns = time.time_ns()
        params_hash = sha256_hex(json.dumps(tool_params, sort_keys=True))
        output_hash = sha256_hex("PENDING_EXECUTION")

        # 1. Identify relevant policy invariants
        matching_policies = [p for p in self.policies if p.target_tool == tool_name or p.target_tool == "*"]

        # 2. Generate ZK Invariant Proofs
        public_context = {
            "agent_id": agent_id,
            "target_tool": tool_name,
            "session_id": self.session_id,
            "nonce": voucher_id,
        }
        zk_proofs = self.prover.batch_prove(
            invariants=matching_policies,
            public_context=public_context,
            private_parameters=tool_params
        )

        proof_id_concat = ",".join([p.proof_id for p in zk_proofs])

        # 3. Append to Merkle-DAG
        dag_node = self.dag.append_action(
            node_id=voucher_id,
            agent_id=agent_id,
            tool_name=tool_name,
            sanitized_params_hash=params_hash,
            output_hash=output_hash,
            parent_node_ids=parent_action_ids,
            zk_proof_id=proof_id_concat
        )

        root_hash = self.dag.compute_frontier_merkle_root()
        action_leaf_hash = dag_node.node_hash
        inclusion_path = self.dag.generate_inclusion_proof(action_leaf_hash)

        # 4. Sign the canonical message
        canonical_msg = (
            f"{voucher_id}:{root_hash}:{action_leaf_hash}:{agent_id}:"
            f"{tool_name}:{dag_node.causal_lamport_ts}:{timestamp_ns}"
        )
        notary_signature = hmac_sha256_hex(self.private_key, canonical_msg)

        voucher = ZKActorVoucher(
            voucher_id=voucher_id,
            root_merkle_hash=root_hash,
            action_leaf_hash=action_leaf_hash,
            agent_id=agent_id,
            target_tool=tool_name,
            causal_lamport_ts=dag_node.causal_lamport_ts,
            timestamp_ns=timestamp_ns,
            parent_hashes=dag_node.parent_hashes,
            output_hash=output_hash,
            zk_proofs=zk_proofs,
            merkle_inclusion_path=inclusion_path,
            notary_signature=notary_signature,
            notary_public_key=self.key_id
        )

        # 5. Pack into outbound JSON-RPC wire payload with metadata header
        wire_payload = {
            "jsonrpc": "2.0",
            "method": f"tools/{tool_name}",
            "params": tool_params,
            "headers": {
                "x-agent-notary-voucher": voucher.to_wire_header(),
                "x-agent-notary-key-id": self.key_id,
            }
        }

        return wire_payload, voucher

    def verify_wire_invocation(
        self,
        wire_payload: Dict[str, Any]
    ) -> VoucherVerificationResult:
        """
        Receiving endpoint verification: extracts the voucher from headers and validates.
        """
        headers = wire_payload.get("headers", {})
        raw_header = headers.get("x-agent-notary-voucher")
        if not raw_header:
            return VoucherVerificationResult(
                is_valid=False,
                verification_latency_us=0.0,
                error_reason="MissingNotaryVoucherHeader"
            )

        voucher = ZKActorVoucher.from_wire_header(raw_header)
        params_hash = sha256_hex(json.dumps(wire_payload.get("params", {}), sort_keys=True))

        return self.verifier.verify_voucher(
            voucher=voucher,
            target_tool_params_hash=params_hash
        )
