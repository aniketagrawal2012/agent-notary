"""
Agent-Notary: Cryptographic Non-Repudiation, Zero-Knowledge Invariant Attestation,
and Merkle-DAG Action Provenance for Autonomous Multi-Agent Swarms.

Core Data Models & Wire Structures.
Author: Aniket Agrawal <aniketagrawal@google.com>
"""

from __future__ import annotations
import base64
from dataclasses import dataclass, field, asdict
import hashlib
import hmac
import json
import secrets
import time
from typing import Any, Dict, List, Optional, Tuple


def sha256_hex(data: bytes | str) -> str:
    """Computes SHA-256 hex digest of given bytes or string."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def hmac_sha256_hex(key: bytes | str, data: bytes | str) -> str:
    """Computes HMAC-SHA256 hex digest."""
    if isinstance(key, str):
        key = key.encode("utf-8")
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def compute_action_node_hash(
    node_id: str,
    agent_id: str,
    causal_lamport_ts: int,
    parent_hashes: List[str],
    tool_name: str,
    params_hash: str,
    output_hash: str,
    zk_proof_id: str = ""
) -> str:
    canonical = (
        f"{node_id}:{agent_id}:{causal_lamport_ts}:"
        f"{','.join(sorted(parent_hashes))}:{tool_name}:{params_hash}:"
        f"{output_hash}:{zk_proof_id}"
    )
    return sha256_hex(canonical)


@dataclass
class PolicyInvariant:
    """
    Formal execution constraint that a tool action must satisfy.
    Evaluated by the Prover without leaking private prompt context.
    """
    invariant_id: str
    rule_type: str  # 'parameter_range', 'regex_match', 'disbursement_limit', 'network_cidr_whitelist'
    parameter_path: str
    constraint_expression: str  # e.g. "<= 50000", "^gs://acme-prod-bucket/.*$"
    target_tool: str

    def evaluate(self, tool_params: Dict[str, Any]) -> bool:
        """Evaluates whether the provided parameters satisfy this policy invariant."""
        val = tool_params.get(self.parameter_path)
        if val is None:
            return False

        if self.rule_type == "disbursement_limit":
            try:
                num_val = float(val)
                limit = float(self.constraint_expression.replace("<=", "").strip())
                return num_val <= limit
            except (ValueError, TypeError):
                return False

        elif self.rule_type == "regex_match":
            import re
            return bool(re.match(self.constraint_expression, str(val)))

        elif self.rule_type == "network_cidr_whitelist":
            allowed_cidrs = [c.strip() for c in self.constraint_expression.split(",")]
            return any(str(val).startswith(c.replace("/24", "").replace("/16", "")) for c in allowed_cidrs)

        return True


@dataclass
class ZKInvariantProof:
    """
    Zero-Knowledge Invariant Attestation proof.
    Mathematically proves that PolicyInvariants were satisfied over private inputs
    without disclosing raw prompt tokens or sensitive business payload parameters.
    """
    proof_id: str
    invariant_id: str
    circuit_commitment: str     # Hash of the verification circuit & policy
    public_inputs_hash: str     # Hash of public context (caller identity, target tool, timestamp)
    blinded_eval_token: str     # Cryptographic commitment to the private satisfied parameters
    zk_proof_hex: str           # Simulated succinct non-interactive proof
    generation_latency_us: float = 0.0

    def to_wire_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class MerkleDAGNode:
    """
    Causally ordered node in the multi-agent execution Merkle-DAG.
    Binds the agent's step, tool call, parent references, and cryptographic proofs.
    """
    node_id: str
    agent_id: str
    causal_lamport_ts: int
    parent_hashes: List[str]
    tool_name: str
    sanitized_params_hash: str  # SHA256 of parameters (preserves privacy)
    output_hash: str
    zk_proof_id: Optional[str] = None
    node_hash: str = field(init=False)

    def __post_init__(self):
        self.node_hash = compute_action_node_hash(
            node_id=self.node_id,
            agent_id=self.agent_id,
            causal_lamport_ts=self.causal_lamport_ts,
            parent_hashes=self.parent_hashes,
            tool_name=self.tool_name,
            params_hash=self.sanitized_params_hash,
            output_hash=self.output_hash,
            zk_proof_id=self.zk_proof_id or ""
        )

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["node_hash"] = self.node_hash
        return d


@dataclass
class ZKActorVoucher:
    """
    The canonical wire format token: Zero-Knowledge Action Attestation Voucher (ZKA-Voucher).
    Carried in HTTP/2 gRPC metadata headers and Model Context Protocol (MCP) JSON-RPC messages.
    Provides mathematically non-repudiable audit trails.
    """
    voucher_id: str
    root_merkle_hash: str
    action_leaf_hash: str
    agent_id: str
    target_tool: str
    causal_lamport_ts: int
    timestamp_ns: int
    parent_hashes: List[str]
    output_hash: str
    zk_proofs: List[ZKInvariantProof]
    merkle_inclusion_path: List[Tuple[str, str]]  # List of (hash, 'L'|'R')
    notary_signature: str                          # Cryptographic signature from Notary Gateway
    notary_public_key: str

    def to_wire_header(self) -> str:
        """Serializes the voucher to a compact Base64-encoded JSON wire header."""
        d = asdict(self)
        compact_json = json.dumps(d, separators=(",", ":"))
        return base64.b64encode(compact_json.encode("utf-8")).decode("utf-8")

    @classmethod
    def from_wire_header(cls, header_val: str) -> ZKActorVoucher:
        """Deserializes from a Base64-encoded wire header."""
        raw_json = base64.b64decode(header_val.encode("utf-8")).decode("utf-8")
        data = json.loads(raw_json)
        proofs = [ZKInvariantProof(**p) for p in data.pop("zk_proofs")]
        return cls(zk_proofs=proofs, **data)
