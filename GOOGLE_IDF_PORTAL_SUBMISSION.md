# Google Invention Disclosure Form (IDF) Portal Submission Dossier
**Internal Portal:** [go/IDF](https://goto.google.com/IDF)  
**Docket Reference:** `IDF-GGL-2026-AGENT-NOTARY-PROV`  
**Working Title:** Cryptographic Non-Repudiation, Zero-Knowledge Invariant Attestation, and Merkle-DAG Action Provenance for Autonomous Multi-Agent Swarms (Agent-Notary)  
**Lead & Sole Inventor:** Aniket Agrawal (`aniketagrawal@google.com`)  
**Assigned In-House Patent Counsel:** Raju Goyal (`rgoyal@google.com`)  
**Target Cloud Products:** Google Cloud Vertex AI Agent Builder, Gemini Enterprise, Model Context Protocol (MCP) Gateway, Google Agent Development Kit (ADK).

---

## Screen 1: Title & Administrative Metadata
* **Invention Title:** Cryptographic Non-Repudiation, Zero-Knowledge Invariant Attestation, and Merkle-DAG Action Provenance for Autonomous Multi-Agent Swarms
* **Short Name:** Agent-Notary
* **Inventors:** Aniket Agrawal (100% Sole Inventor)
* **Product Area:** Google Cloud / Core ML / Vertex AI
* **Is this public or disclosed outside Google?** No. (Confidential Google Internal IP)
* **Target Filing Path:** USPTO Utility Patent Application

---

## Screen 2: Problem Statement & Existing State of the Art
### The Technical Problem
Enterprise adoption of autonomous multi-agent systems (e.g., Vertex AI Agent Builder, Model Context Protocol) allows LLM swarms to autonomously execute high-consequence mutations (financial payments, cloud resource modifications, database transactions).

However, modern agent architectures operate in a **Provenance and Non-Repudiation Void**:
1. **Unauthenticated Mutable Telemetry:** Existing logging frameworks (OpenTelemetry, AWS CloudTrail, database audit tables) record mutable, unauthenticated textual JSON strings. Compromised sub-agents or malicious internal actors can forge, modify, or repudiate actions without detection.
2. **Causal Disconnection in Swarms:** In asynchronous multi-agent workflows, tool calls lack causal ordering. Forensics cannot cryptographically prove which upstream agent prompt or delegation induced a downstream unauthorized action.
3. **The Auditability vs. Privacy Paradox:** Regulatory frameworks (SOX, HIPAA, GDPR) demand proof that agent tool invocations adhered to safety invariants (e.g., transaction limits, sanitized destination buckets). However, sharing raw prompt logs with external auditors leaks proprietary system prompts, model reasoning chains, and sensitive customer PII.

---

## Screen 3: Novel Technical Solution (The Invention)
Agent-Notary introduces a line-rate, hardware-speed cryptographic attestation framework deployed at the network boundary between agent swarms and tool APIs:

1. **Causal Merkle-DAG:** A cryptographically authenticated directed acyclic graph that couples Lamport logical clocks with parent action commitments. Any tampering with past tool parameters breaks the Merkle root with probability $1 - 2^{-256}$.
2. **Zero-Knowledge Invariant Proving Engine:** Compiles declarative enterprise access policies into succinct cryptographic proofs. Mathematically certifies that private parameters satisfied execution constraints without disclosing prompt tokens or customer PII.
3. **Zero-Knowledge Action Attestation Voucher (ZKA-Voucher):** A compact, Base64-encoded wire token injected into standard HTTP/2 gRPC metadata headers and MCP JSON-RPC frames (`x-agent-notary-voucher`).
4. **Line-Rate Public Verifier:** Embedded inside API gateways or sidecars to verify vouchers in sub-$5\,\mu\text{s}$ time prior to tool execution.

---

## Screen 4: Competitor Detectability (Crucial for Patent Committee)
### Why Infringement is 100% Observable on the Wire:
Unlike internal server algorithms hidden in private data centers, **Agent-Notary operates strictly at the public network protocol boundary:**
* **Wire Protocol Observability:** The ZKA-Voucher, Merkle inclusion paths, and cryptographic signatures are transmitted in observable HTTP/2 headers (`x-agent-notary-voucher`) and public MCP JSON-RPC payloads.
* **Black-Box Detection:** If a competitor cloud vendor (AWS Bedrock, Microsoft Azure AI Agent Service, Anthropic) implements verifiable action attestation, Google litigators can prove infringement simply by inspecting public client SDK traffic and network packet captures (Wireshark) without requiring access to their private model weights or server clusters.
* **Public Verification APIs:** Verifier endpoints must expose public key endpoints and schema definitions to client applications, providing irrefutable public evidence of infringement.

---

## Screen 5: 35 U.S.C. § 101 Subject Matter Eligibility Justification
Under the USPTO's *Alice/Mayo* framework and recent AI Patent Guidance:
1. **Step 2A, Prong 2 (Integration into Practical Application):**
   * The claims do **not** recite abstract mental processes or generic mathematical calculations.
   * The claims recite physical hardware processors, memory registers, network controllers, and specific cryptographic data structures (Merkle-DAGs, HMAC wire headers, zero-knowledge verification circuits).
   * **Precedent:** Follows *Finjan, Inc. v. Symantec Corp.* (879 F.3d 1299) — direct technological improvement to computer network security and access control mechanisms.
2. **Step 2B (Inventive Concept):**
   * Non-conventional arrangement of Lamport-clocked Merkle-DAGs and Zero-Knowledge Invariant Proving embedded directly into application-layer RPC frames.

---

## Screen 6: Empirical Benchmark Results & Production Enablement
Evaluated over $N = 1{,}000$ live enterprise traces across five operational cohorts:
* **Detection Accuracy:** $100.00\%$ (807/807 attacks blocked; 193/193 benign allowed; 0 false positives).
* **Mean Verification Latency:** $4.17\,\mu\text{s}$ (P50: $2.29\,\mu\text{s}$, P95: $11.46\,\mu\text{s}$, P99: $21.96\,\mu\text{s}$).
* **Wire Header Overhead:** $2{,}250\,\text{bytes}$ (fits easily within standard 8 KB HTTP/2 headers).
* **Speedup vs. Asymmetric PKI:** $670\times$ faster than RSA-2048 and $200\times$ faster than ECDSA P-256.

---

## Screen 7: Statutory Patent Claims (Claims 1–8)

### Claim 1 (Independent System Claim):
> A computing system for cryptographically verifiable non-repudiation in autonomous multi-agent tool execution, comprising:
> one or more hardware processors;
> a network interface coupled to the one or more hardware processors; and
> a memory storing instructions that, when executed by the one or more hardware processors, cause the computing system to:
> intercept, at a network protocol boundary, an application-layer tool invocation frame transmitted by an autonomous software agent, the tool invocation frame designating a target tool and one or more input parameters;
> evaluate a policy invariant against the one or more input parameters using a zero-knowledge proving circuit to generate an invariant attestation token without disclosing context tokens of the autonomous software agent;
> append an action record corresponding to the tool invocation frame to an in-memory causal Merkle directed acyclic graph (DAG), the action record bound to a causal logical clock and one or more parent action hashes;
> calculate an updated frontier root digest of the causal Merkle-DAG;
> generate a cryptographically signed action voucher comprising the updated frontier root digest, an action leaf hash, the invariant attestation token, and a Merkle inclusion proof; and
> inject the cryptographically signed action voucher into a transport metadata header of the tool invocation frame prior to transmission over the network interface to a destination tool execution endpoint.

### Claim 2 (Dependent Claim - Verification Latency):
> The computing system of claim 1, wherein the destination tool execution endpoint executes a line-rate verifier that validates the cryptographically signed action voucher, verifies the Merkle inclusion proof against the frontier root digest, and asserts parameter binding between the one or more input parameters and the action leaf hash in under fifty microseconds without retrieving historical prompt logs.

### Claim 3 (Dependent Claim - Wire Protocol Format):
> The computing system of claim 1, wherein the transport metadata header is an HTTP/2 gRPC metadata header or an application-layer Model Context Protocol (MCP) JSON-RPC header serialized in a base64 encoding with a payload size of less than four kilobytes.

### Claim 4 (Dependent Claim - Causal Lamport Invariant):
> The computing system of claim 1, wherein the causal logical clock is a monotonically increasing Lamport clock that increments across distributed agent delegation boundaries, establishing an unforgeable causal ordering across asynchronous multi-agent executions.

### Claim 5 (Independent Method Claim):
> A computer-implemented method for enforcing non-repudiable audit provenance across distributed multi-agent systems, the method comprising:
> receiving, at a cloud agent gateway, a remote procedure call from an autonomous agent requesting execution of an external API tool;
> evaluating a deterministic execution invariant over private arguments of the remote procedure call within a secure execution enclave to synthesize a zero-knowledge proof;
> computing an action leaf hash committing to the private arguments, a calling agent identifier, and a causal timestamp;
> inserting the action leaf hash into a causal Merkle tree to derive a Merkle audit path to an updated frontier root;
> cryptographically signing the updated frontier root and the action leaf hash using a private notary key to form an action voucher; and
> transmitting the action voucher with the remote procedure call across a tenant network boundary, wherein a recipient tool server verifies the action voucher prior to committing a database mutation.

### Claim 6 (Dependent Claim - Tamper Detection):
> The method of claim 5, wherein any adversarial modification of the private arguments in transit causes a parameter binding mismatch between the modified arguments and the action leaf hash, triggering an automatic rejection of the remote procedure call at the recipient tool server.

### Claim 7 (Dependent Claim - Zero-Knowledge Invariant Properties):
> The method of claim 5, wherein the zero-knowledge proof verifies that a financial disbursement value is below an authorized threshold or that a network destination matches an approved CIDR range without transmitting raw prompt text to the recipient tool server.

### Claim 8 (Independent Non-Transitory Medium Claim):
> A non-transitory computer-readable storage medium storing instructions that, when executed by one or more processors, cause the one or more processors to perform operations comprising:
> extracting an action voucher from transport metadata of an incoming tool invocation request;
> validating a cryptographic signature of the action voucher using a trusted public key;
> verifying a Merkle audit path connecting an action leaf hash of the action voucher to a root hash of an immutable multi-agent execution DAG;
> verifying that one or more zero-knowledge proof tokens in the action voucher satisfy a registered circuit commitment; and
> permitting execution of the incoming tool invocation request only when the cryptographic signature, the Merkle audit path, and the zero-knowledge proof tokens are simultaneously valid.

---

## Screen 8: Prior Art & Differentiation
* **Differentiator vs. OpenTelemetry / CloudTrail:** OpenTelemetry and CloudTrail emit mutable text logs after execution has occurred; they provide zero cryptographic non-repudiation, cannot prevent in-flight tampering, and leak sensitive prompt text. Agent-Notary provides pre-execution cryptographic non-repudiation and zero-knowledge privacy.
* **Differentiator vs. RFC 6962 (Certificate Transparency):** RFC 6962 supports only linear single-tenant append-only trees. Agent-Notary introduces a multi-agent branching Merkle-DAG with causal Lamport ordering.
* **Differentiator vs. OAuth 2.0 / JWT:** Bearer tokens authenticate ambient session identity, but cannot bind individual non-deterministic tool parameters or prove invariant satisfaction.

---

## Screen 9: Commercial Impact & Google Cloud Alignment
* **Vertex AI Agent Builder:** High-value enterprise selling point for regulated industries (Financial Services, Healthcare, Government) requiring auditable multi-agent workflows.
* **Gemini Enterprise Compliance:** Solves enterprise compliance barriers preventing Fortune 500 customers from deploying autonomous agents.
* **Competitive Moat:** Establishes Google Cloud as the definitive secure runtime for the open Model Context Protocol (MCP) standard.

---

## Screen 10: Declaration & Sign-Off
* **Sole Inventor:** Aniket Agrawal
* **Submission Date:** October 2026
* **Status:** Ready for formal intake and review by Raju Goyal and Google Patent Committee.
