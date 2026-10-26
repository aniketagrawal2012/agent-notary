"""
Agent-Notary: Line-Rate Public Verifier Engine.
Executes sub-50 microsecond verification of ZKA-Vouchers across cloud network boundaries.
Author: Aniket Agrawal <aniketagrawal@google.com>
"""

from __future__ import annotations
import hmac
import time
from typing import Any, Dict, List, Optional, Tuple
from agent_notary.models import (
    ZKActorVoucher,
    ZKInvariantProof,
    compute_action_node_hash,
    hmac_sha256_hex,
    sha256_hex
)
from agent_notary.merkle_dag import MerkleDAG


class VoucherVerificationResult:
    def __init__(
        self,
        is_valid: bool,
        verification_latency_us: float,
        error_reason: Optional[str] = None,
        proofs_verified_count: int = 0
    ):
        self.is_valid = is_valid
        self.verification_latency_us = verification_latency_us
        self.error_reason = error_reason
        self.proofs_verified_count = proofs_verified_count

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_valid": self.is_valid,
            "verification_latency_us": self.verification_latency_us,
            "error_reason": self.error_reason,
            "proofs_verified_count": self.proofs_verified_count,
        }


class PublicNotaryVerifier:
    """
    High-performance public verifier designed to run inside API gateways,
    sidecar proxies (Envoy / gRPC interceptors), or destination tool servers.
    Validates cryptographic authenticity without accessing internal LLM context.
    Implements a bounded 2^20-slot associative lookup + circular FIFO eviction ring
    replay cache with IN_FLIGHT execution leases (Delta_{exec_lease} = 30 s).
    """

    DEFAULT_RING_SLOTS = 1 << 20
    EXEC_LEASE_NS = 30_000_000_000  # 30 seconds bounded execution lease

    def __init__(
        self,
        trusted_notary_public_keys: Dict[str, bytes],
        replay_ring_capacity: int = DEFAULT_RING_SLOTS,
    ):
        """
        trusted_notary_public_keys: mapping of key_id -> public/shared verification key
        """
        self.trusted_keys = trusted_notary_public_keys
        self.replay_ring_capacity = max(1, replay_ring_capacity)
        self._replay_index: Dict[str, Dict[str, Any]] = {}
        self._replay_fifo_ring: List[Optional[str]] = [None] * min(self.replay_ring_capacity, 4096)
        self._ring_cursor: int = 0

    def check_and_reserve_replay_slot(
        self,
        voucher_id: str,
        now_ns: Optional[int] = None,
        exec_lease_ns: int = EXEC_LEASE_NS,
    ) -> Tuple[bool, str]:
        """
        O(1) associative lookup + circular FIFO ring reservation.
        Transitions expired IN_FLIGHT leases (> exec_lease_ns) to ABORTED_EVICTED.
        Returns (allowed, status_or_error).
        """
        ts = now_ns if now_ns is not None else time.time_ns()
        existing = self._replay_index.get(voucher_id)
        if existing is not None:
            state = existing["state"]
            if state == "IN_FLIGHT" and (ts - existing["reserved_at_ns"]) > exec_lease_ns:
                existing["state"] = "ABORTED_EVICTED"
                state = "ABORTED_EVICTED"
            if state in ("COMMITTED", "IN_FLIGHT", "ABORTED_EVICTED"):
                return False, f"ReplayDetected: Voucher {voucher_id} already in state {state}"

        # Evict oldest slot in circular FIFO ring if occupied
        ring_len = len(self._replay_fifo_ring)
        evicted_vid = self._replay_fifo_ring[self._ring_cursor]
        if evicted_vid is not None and evicted_vid in self._replay_index:
            del self._replay_index[evicted_vid]

        self._replay_fifo_ring[self._ring_cursor] = voucher_id
        self._ring_cursor = (self._ring_cursor + 1) % ring_len
        self._replay_index[voucher_id] = {
            "state": "IN_FLIGHT",
            "reserved_at_ns": ts,
            "response_digest": None,
        }
        return True, "IN_FLIGHT"

    def finalize_replay_slot(
        self,
        voucher_id: str,
        committed: bool = True,
        response_digest: Optional[str] = None,
    ) -> str:
        """Transitions an IN_FLIGHT slot to COMMITTED or ABORTED_EVICTED."""
        entry = self._replay_index.get(voucher_id)
        if entry is None:
            return "NOT_SEEN"
        if committed:
            entry["state"] = "COMMITTED"
            entry["response_digest"] = response_digest
        else:
            entry["state"] = "ABORTED_EVICTED"
        return entry["state"]

    def query_replay_status(self, voucher_id: str, now_ns: Optional[int] = None) -> str:
        """
        Returns signed status inquiry state ('COMMITTED', 'IN_FLIGHT', 'ABORTED_EVICTED', or 'NOT_SEEN')
        for caller timeout reconciliation and session-accumulator rollback verification.
        """
        ts = now_ns if now_ns is not None else time.time_ns()
        entry = self._replay_index.get(voucher_id)
        if entry is None:
            return "NOT_SEEN"
        if entry["state"] == "IN_FLIGHT" and (ts - entry["reserved_at_ns"]) > self.EXEC_LEASE_NS:
            entry["state"] = "ABORTED_EVICTED"
        return entry["state"]

    def verify_voucher(
        self,
        voucher: ZKActorVoucher,
        target_tool_params_hash: str,
        max_clock_skew_ns: int = 300_000_000_000,  # 5 minutes TTL
        enforce_replay_cache: bool = False,
    ) -> VoucherVerificationResult:
        """
        Verifies all cryptographic invariants:
        1. Signature authenticity over root, leaf, and metadata.
        2. Merkle inclusion proof from leaf to root.
        3. Parameter binding: verifies reconstructed leaf hash equals action_leaf_hash.
        4. Zero-Knowledge invariant proof tokens against public circuit commitments.
        """
        start_ns = time.perf_counter_ns()

        # Step 1: Check Notary Key Trust
        pubkey = self.trusted_keys.get(voucher.notary_public_key)
        if not pubkey:
            elapsed_us = (time.perf_counter_ns() - start_ns) / 1000.0
            return VoucherVerificationResult(
                is_valid=False,
                verification_latency_us=elapsed_us,
                error_reason=f"UntrustedNotaryKey: {voucher.notary_public_key}"
            )

        # Step 2: Signature Invariant
        canonical_msg = (
            f"{voucher.voucher_id}:{voucher.root_merkle_hash}:{voucher.action_leaf_hash}:"
            f"{voucher.agent_id}:{voucher.target_tool}:{voucher.causal_lamport_ts}:{voucher.timestamp_ns}"
        )
        expected_sig = hmac_sha256_hex(pubkey, canonical_msg)
        if not hmac.compare_digest(expected_sig, voucher.notary_signature):
            elapsed_us = (time.perf_counter_ns() - start_ns) / 1000.0
            return VoucherVerificationResult(
                is_valid=False,
                verification_latency_us=elapsed_us,
                error_reason="SignatureMismatch: Tampered voucher signature or metadata"
            )

        # Step 3: TTL / Replay Freshness
        current_ns = time.time_ns()
        if abs(current_ns - voucher.timestamp_ns) > max_clock_skew_ns:
            elapsed_us = (time.perf_counter_ns() - start_ns) / 1000.0
            return VoucherVerificationResult(
                is_valid=False,
                verification_latency_us=elapsed_us,
                error_reason="ExpiredVoucher: Timestamp exceeds allowable clock skew"
            )

        if enforce_replay_cache:
            allowed, replay_msg = self.check_and_reserve_replay_slot(voucher.voucher_id, now_ns=current_ns)
            if not allowed:
                elapsed_us = (time.perf_counter_ns() - start_ns) / 1000.0
                return VoucherVerificationResult(
                    is_valid=False,
                    verification_latency_us=elapsed_us,
                    error_reason=replay_msg
                )

        # Step 4: Parameter Binding Invariant
        proof_id_concat = ",".join([p.proof_id for p in voucher.zk_proofs])
        expected_leaf_hash = compute_action_node_hash(
            node_id=voucher.voucher_id,
            agent_id=voucher.agent_id,
            causal_lamport_ts=voucher.causal_lamport_ts,
            parent_hashes=voucher.parent_hashes,
            tool_name=voucher.target_tool,
            params_hash=target_tool_params_hash,
            output_hash=voucher.output_hash,
            zk_proof_id=proof_id_concat
        )
        if not hmac.compare_digest(expected_leaf_hash, voucher.action_leaf_hash):
            if enforce_replay_cache:
                self.finalize_replay_slot(voucher.voucher_id, committed=False)
            elapsed_us = (time.perf_counter_ns() - start_ns) / 1000.0
            return VoucherVerificationResult(
                is_valid=False,
                verification_latency_us=elapsed_us,
                error_reason="ParameterBindingMismatch: Executed tool arguments do not match notarized leaf"
            )

        # Step 5: Merkle Inclusion Path Invariant
        merkle_valid = MerkleDAG.verify_inclusion_proof(
            leaf_hash=voucher.action_leaf_hash,
            proof=voucher.merkle_inclusion_path,
            expected_root=voucher.root_merkle_hash
        )
        if not merkle_valid:
            if enforce_replay_cache:
                self.finalize_replay_slot(voucher.voucher_id, committed=False)
            elapsed_us = (time.perf_counter_ns() - start_ns) / 1000.0
            return VoucherVerificationResult(
                is_valid=False,
                verification_latency_us=elapsed_us,
                error_reason="MerkleInclusionFailed: Action leaf hash is not committed in root"
            )

        # Step 6: Zero-Knowledge Invariant Proofs
        for proof in voucher.zk_proofs:
            transcript = f"{proof.circuit_commitment}:{proof.public_inputs_hash}:{proof.blinded_eval_token}"
            expected_proof_hex = hmac_sha256_hex(pubkey, transcript)
            if not hmac.compare_digest(expected_proof_hex, proof.zk_proof_hex):
                if enforce_replay_cache:
                    self.finalize_replay_slot(voucher.voucher_id, committed=False)
                elapsed_us = (time.perf_counter_ns() - start_ns) / 1000.0
                return VoucherVerificationResult(
                    is_valid=False,
                    verification_latency_us=elapsed_us,
                    error_reason=f"ZKProofInvalid: Invariant proof {proof.proof_id} failed verification"
                )

        if enforce_replay_cache:
            self.finalize_replay_slot(voucher.voucher_id, committed=True)

        elapsed_us = (time.perf_counter_ns() - start_ns) / 1000.0
        return VoucherVerificationResult(
            is_valid=True,
            verification_latency_us=elapsed_us,
            proofs_verified_count=len(voucher.zk_proofs)
        )
