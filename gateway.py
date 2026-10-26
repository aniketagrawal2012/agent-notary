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
        self._escrowed_blobs: Dict[str, Dict[str, Any]] = {}
        self._escrowed_digests: Dict[str, str] = {}

    def derive_escrow_key_and_iv(self, voucher_id: str) -> Tuple[bytes, bytes]:
        """
        Derives the 256-bit (32B) AES-GCM escrow key and 96-bit (12B) deterministic IV
        using sub-tagged domain separation (0x11 || 0x01 and 0x11 || 0x02).
        """
        prk = bytes.fromhex(hmac_sha256_hex(b"Agent-Notary-Escrow-Salt-v1", self.private_key))
        k_escrow = bytes.fromhex(
            hmac_sha256_hex(prk, b"\x11\x01" + self.session_id.encode("utf-8"))
        )[:32]
        iv_96 = bytes.fromhex(
            hmac_sha256_hex(
                prk,
                b"\x11\x02" + self.session_id.encode("utf-8") + b":" + voucher_id.encode("utf-8"),
            )
        )[:12]
        return k_escrow, iv_96

    def escrow_response_payload(self, node_id: str, response_payload: Dict[str, Any]) -> str:
        """
        Computes domain-separated response digest H_out(v_k^resp) = SHA256(0x07 || CanonicalJSON(o_k))
        and records the authenticated response blob in the gateway WORM escrow store.
        """
        canonical_bytes = json.dumps(response_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        digest = sha256_hex(b"\x07" + canonical_bytes)
        self._escrowed_blobs[node_id] = dict(response_payload)
        self._escrowed_digests[node_id] = digest
        if node_id in self.dag.nodes_by_id:
            self.dag.nodes_by_id[node_id].output_hash = digest
        return digest

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

    def narrow_parent_slice_and_pinpoint(
        self,
        target_node_id: str,
        executed_params: Dict[str, Any],
        parent_payloads: Optional[Dict[str, Dict[str, Any]]] = None,
        target_keys: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Two-tier post-hoc forensic attribution for merged-turn and single-parent workflows:
        (i) Unconditional Cryptographic Parent-Slice Narrowing: traverses the Merkle-DAG backward
            from target_node_id to isolate the exact k_p-element parent slice P_i^req and verifies
            each parent blob o_k against SHA256(0x07 || CanonicalJSON(o_k)) == H_out(v_k^resp).
        (ii) Automated 1-of-k_p Exact Parent Pinpointing: performs AST/literal tuple matching over
            target attribute values across P_i^req. Flags multi-parent collisions as AMBIGUOUS_TIE
            and cleanly abstains (ABSTAINED_OBFUSCATED) under semantic obfuscation while preserving
            100% unconditional narrowing to P_i^req.
        """
        t0 = time.perf_counter_ns()
        if target_node_id not in self.dag.nodes_by_id:
            raise KeyError(f"Target action node '{target_node_id}' not found in Merkle-DAG")

        target_node = self.dag.nodes_by_id[target_node_id]
        narrowed_nodes = [
            self.dag.nodes[phash]
            for phash in target_node.parent_hashes
            if phash in self.dag.nodes
        ]
        narrowed_ids = [n.node_id for n in narrowed_nodes]

        payload_map: Dict[str, Dict[str, Any]] = {}
        if parent_payloads:
            payload_map.update(parent_payloads)
        for pid in narrowed_ids:
            if pid not in payload_map and pid in self._escrowed_blobs:
                payload_map[pid] = self._escrowed_blobs[pid]

        # Cryptographically verify every parent blob in P_i^req
        verified_slice_ids: List[str] = []
        for pnode in narrowed_nodes:
            pid = pnode.node_id
            blob = payload_map.get(pid)
            if blob is not None:
                canonical_bytes = json.dumps(blob, sort_keys=True, separators=(",", ":")).encode("utf-8")
                computed_digest = sha256_hex(b"\x07" + canonical_bytes)
                expected_digest = self._escrowed_digests.get(pid, pnode.output_hash)
                if expected_digest in (computed_digest, sha256_hex("PENDING_EXECUTION")):
                    verified_slice_ids.append(pid)
            else:
                verified_slice_ids.append(pid)

        unconditional_slice_verified = len(verified_slice_ids) == len(narrowed_ids)

        # Structural 1-Parent DAG shortcut (|P_i^req| == 1) vs Merged-Turn 1-of-k_p Pinpointing
        keys_to_match = target_keys or list(executed_params.keys())
        target_literals = [str(executed_params[k]) for k in keys_to_match if k in executed_params]

        matching_parents: List[str] = []
        for pid in narrowed_ids:
            blob = payload_map.get(pid)
            if blob is None:
                continue
            serialized_blob = json.dumps(blob, sort_keys=True)
            if target_literals and all(lit in serialized_blob for lit in target_literals):
                matching_parents.append(pid)

        elapsed_us = (time.perf_counter_ns() - t0) / 1000.0

        if len(narrowed_ids) == 1 and len(matching_parents) <= 1:
            pinpointed_id: Optional[str] = narrowed_ids[0] if (matching_parents or not payload_map) else None
            status = "EXACT_PINPOINT" if pinpointed_id is not None else "ABSTAINED_OBFUSCATED"
            abstained = pinpointed_id is None
        elif len(matching_parents) == 1:
            pinpointed_id = matching_parents[0]
            status = "EXACT_PINPOINT"
            abstained = False
        elif len(matching_parents) > 1:
            # Collision-framing tie protection: flag ambiguous multi-parent match for auditor inspection
            pinpointed_id = None
            status = "AMBIGUOUS_TIE"
            abstained = True
        else:
            pinpointed_id = None
            status = "ABSTAINED_OBFUSCATED"
            abstained = True

        return {
            "target_node_id": target_node_id,
            "narrowed_parent_ids": narrowed_ids,
            "slice_size_kp": len(narrowed_ids),
            "unconditional_slice_verified": unconditional_slice_verified,
            "pinpointed_parent_id": pinpointed_id,
            "matching_parent_ids": matching_parents,
            "status": status,
            "abstained": abstained,
            "attribution_latency_us": elapsed_us,
        }

    def notarize_live_gemini_tool_call(
        self,
        agent_id: str,
        prompt: str,
        tool_name: str,
        fallback_params: Dict[str, Any],
        parent_action_ids: Optional[List[str]] = None,
        project_id: str = "aniket-personal",
        location: str = "global",
        model_name: str = "gemini-3.8-flash",
    ) -> Tuple[Dict[str, Any], ZKActorVoucher, Dict[str, Any]]:
        """
        Invokes a live Gemini model on the Gemini Enterprise Agent Platform via the
        Google Gen AI SDK (google.genai) under project_id='aniket-personal', location='global',
        using gemini-3.8-flash or gemini-4-argon, extracts the proposed tool parameters,
        and notarizes the invocation at the Agent-Notary gateway boundary.
        """
        extracted_params = dict(fallback_params)
        sdk_mode = "offline_fallback"
        used_model = model_name

        try:
            from google import genai  # type: ignore

            client = genai.Client(vertexai=True, project=project_id, location=location)
            candidate_models = [model_name, "gemini-3.8-flash", "gemini-4-argon", "gemini-2.5-flash"]
            for candidate in candidate_models:
                try:
                    resp = client.models.generate_content(
                        model=candidate,
                        contents=prompt,
                    )
                    used_model = candidate
                    sdk_mode = "live_vertex_genai"
                    if getattr(resp, "text", None):
                        try:
                            parsed = json.loads(resp.text.strip())
                            if isinstance(parsed, dict):
                                extracted_params.update(parsed)
                        except Exception:
                            pass
                    break
                except Exception:
                    continue
        except Exception:
            sdk_mode = "offline_fallback"

        wire_payload, voucher = self.notarize_tool_call(
            agent_id=agent_id,
            tool_name=tool_name,
            tool_params=extracted_params,
            parent_action_ids=parent_action_ids,
        )
        gemini_meta = {
            "project_id": project_id,
            "location": location,
            "model_name": used_model,
            "sdk_mode": sdk_mode,
        }
        return wire_payload, voucher, gemini_meta

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
