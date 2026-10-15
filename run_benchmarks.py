"""
Agent-Notary: Empirical Systems Benchmark Suite.
Evaluates line-rate verification latency, wire header overhead,
and adversarial tamper detection across 1,000 synthetic enterprise traces.
Generates benchmark_results.csv.
Author: Aniket Agrawal <aniketagrawal@google.com>
"""

from __future__ import annotations
import csv
import json
import os
import random
import statistics
import time
from typing import Any, Dict, List
from agent_notary.models import PolicyInvariant, ZKActorVoucher, sha256_hex
from agent_notary.gateway import AgentNotaryGateway
from agent_notary.verifier import PublicNotaryVerifier


def run_full_benchmark_suite():
    print("=" * 80)
    print("STARTING EMPIRICAL BENCHMARK SUITE: AGENT-NOTARY")
    print("=" * 80)

    key_id = "notary-key-prod-001"
    secret_key = b"google_cloud_notary_signing_key_32b_prod_secret"
    session_id = "bench-session-erp-multiagent-01"

    policies = [
        PolicyInvariant(
            invariant_id="inv-fin-001",
            rule_type="disbursement_limit",
            parameter_path="amount_usd",
            constraint_expression="<= 50000",
            target_tool="sap_disburse_vendor_payment"
        ),
        PolicyInvariant(
            invariant_id="inv-sec-002",
            rule_type="regex_match",
            parameter_path="destination_uri",
            constraint_expression=r"^gs://acme-finance-prod/.*$",
            target_tool="gcs_archive_financial_ledger"
        ),
        PolicyInvariant(
            invariant_id="inv-net-003",
            rule_type="network_cidr_whitelist",
            parameter_path="destination_ip",
            constraint_expression="10.240.0, 10.240.1",
            target_tool="vpc_egress_api"
        )
    ]

    gateway = AgentNotaryGateway(
        gateway_key_id=key_id,
        gateway_private_key=secret_key,
        session_id=session_id,
        active_policies=policies
    )

    # -------------------------------------------------------------
    # Experiment 1: 1,000 Adversarial & Benign Traces
    # -------------------------------------------------------------
    num_traces = 1000
    results: List[Dict[str, Any]] = []

    prover_latencies: List[float] = []
    verifier_latencies: List[float] = []
    header_sizes_bytes: List[int] = []

    tp, fp, tn, fn = 0, 0, 0, 0

    print(f"\n[1/3] Generating & Evaluating {num_traces} Multi-Agent Traces across 5 Cohorts...")

    for i in range(num_traces):
        trace_id = f"trace-{i:04d}"
        cohort = random.choice([
            "benign_valid",
            "tampered_parameter_escalation",
            "tampered_signature",
            "replay_clock_desync",
            "untrusted_key_forgery"
        ])

        # Generate base parameters
        if i % 3 == 0:
            tool = "sap_disburse_vendor_payment"
            params = {"amount_usd": random.randint(1000, 45000), "vendor_id": f"VEND-{random.randint(100, 999)}"}
        elif i % 3 == 1:
            tool = "gcs_archive_financial_ledger"
            params = {"destination_uri": f"gs://acme-finance-prod/report_{i}.parquet", "records_count": 500}
        else:
            tool = "vpc_egress_api"
            params = {"destination_ip": f"10.240.0.{random.randint(2, 250)}", "port": 443}

        # Step 1: Notarize (Gateway)
        t0 = time.perf_counter_ns()
        wire_payload, voucher = gateway.notarize_tool_call(
            agent_id=f"agent-{random.randint(1, 10)}",
            tool_name=tool,
            tool_params=params
        )
        t_notarize_us = (time.perf_counter_ns() - t0) / 1000.0
        prover_latencies.append(t_notarize_us)

        header_bytes = len(wire_payload["headers"]["x-agent-notary-voucher"])
        header_sizes_bytes.append(header_bytes)

        # Step 2: Apply attack injection if adversarial cohort
        eval_payload = dict(wire_payload)
        is_adversarial = cohort != "benign_valid"

        if cohort == "tampered_parameter_escalation":
            # Attacker modifies amount or parameter
            tampered_params = dict(params)
            if "amount_usd" in tampered_params:
                tampered_params["amount_usd"] = tampered_params["amount_usd"] * 100  # huge escalation
            elif "destination_uri" in tampered_params:
                tampered_params["destination_uri"] = "gs://attacker-exfil/leak.txt"
            else:
                tampered_params["destination_ip"] = "192.168.1.99"
            eval_payload["params"] = tampered_params

        elif cohort == "tampered_signature":
            # Attacker alters signature
            v = ZKActorVoucher.from_wire_header(eval_payload["headers"]["x-agent-notary-voucher"])
            v.notary_signature = sha256_hex("FORGED_NOTARY_SIGNATURE")
            eval_payload["headers"] = {"x-agent-notary-voucher": v.to_wire_header()}

        elif cohort == "replay_clock_desync":
            # Attacker replays old token outside allowable TTL
            v = ZKActorVoucher.from_wire_header(eval_payload["headers"]["x-agent-notary-voucher"])
            v.timestamp_ns = time.time_ns() - 600_000_000_000  # 10 minutes ago
            canonical_msg = (
                f"{v.voucher_id}:{v.root_merkle_hash}:{v.action_leaf_hash}:"
                f"{v.agent_id}:{v.target_tool}:{v.causal_lamport_ts}:{v.timestamp_ns}"
            )
            v.notary_signature = sha256_hex(canonical_msg)
            eval_payload["headers"] = {"x-agent-notary-voucher": v.to_wire_header()}

        elif cohort == "untrusted_key_forgery":
            # Signed with an unknown rogue key
            v = ZKActorVoucher.from_wire_header(eval_payload["headers"]["x-agent-notary-voucher"])
            v.notary_public_key = "rogue-compromised-key-999"
            eval_payload["headers"] = {"x-agent-notary-voucher": v.to_wire_header()}

        # Step 3: Verification
        t_verify = gateway.verify_wire_invocation(eval_payload)
        verifier_latencies.append(t_verify.verification_latency_us)

        # Classification stats: Adversarial is Positive class for detection
        detected = not t_verify.is_valid
        if is_adversarial:
            if detected:
                tp += 1
            else:
                fn += 1
        else:
            if not detected:
                tn += 1
            else:
                fp += 1

        results.append({
            "trace_id": trace_id,
            "cohort": cohort,
            "is_adversarial": is_adversarial,
            "detected": detected,
            "error_reason": t_verify.error_reason or "VALID",
            "notarize_latency_us": round(t_notarize_us, 2),
            "verify_latency_us": round(t_verify.verification_latency_us, 2),
            "header_size_bytes": header_bytes,
        })

    # Save to CSV
    csv_path = "/Users/aniketagrawal/antigravity_workshop/agent_notary/benchmark_results.csv"
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(results[0].keys()))
        writer.writeheader()
        writer.writerows(results)

    # -------------------------------------------------------------
    # Experiment 2: Comparative Architecture Benchmarks
    # -------------------------------------------------------------
    print("\n[2/3] Computing Statistical Performance Metrics...")

    accuracy = (tp + tn) / (tp + tn + fp + fn)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 1.0

    p50_ver = statistics.median(verifier_latencies)
    p95_ver = statistics.quantiles(verifier_latencies, n=20)[18]  # 95th percentile
    p99_ver = statistics.quantiles(verifier_latencies, n=100)[98] # 99th percentile
    mean_ver = statistics.mean(verifier_latencies)

    mean_header = statistics.mean(header_sizes_bytes)

    print("\n" + "=" * 80)
    print("EMPIRICAL BENCHMARK RESULTS SUMMARY (N = 1,000 TRACES)")
    print("=" * 80)
    print(f"True Positives (Attacks Blocked):   {tp}")
    print(f"True Negatives (Benign Allowed):     {tn}")
    print(f"False Positives:                    {fp}")
    print(f"False Negatives:                    {fn}")
    print(f"Accuracy:                           {accuracy * 100:.2f}%")
    print(f"Precision:                          {precision:.4f}")
    print(f"Recall:                             {recall:.4f}")
    print(f"F1-Score:                           {f1:.4f}")
    print(f"Mean Verification Latency:          {mean_ver:.2f} µs")
    print(f"P50 Verification Latency:           {p50_ver:.2f} µs")
    print(f"P95 Verification Latency:           {p95_ver:.2f} µs")
    print(f"P99 Verification Latency:           {p99_ver:.2f} µs")
    print(f"Mean Wire Header Size:              {mean_header:.0f} bytes")
    print(f"Results CSV persisted at:           {csv_path}")
    print("=" * 80)


if __name__ == "__main__":
    run_full_benchmark_suite()
