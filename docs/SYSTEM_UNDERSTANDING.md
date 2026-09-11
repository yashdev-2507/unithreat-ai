# SYSTEM UNDERSTANDING — SIH 26145

## 0. Document Purpose

This is the team's **permanent conceptual and implementation reference** for the SIH 26145 project: *AI-Based Detection of Cyber Threats in Unidirectional IP Traffic*.

It is designed so that any team member — or any technical judge — can read it and confidently understand:

- What the official Problem Statement asks us to build
- Why the problem exists
- The networking and security concepts behind the system
- What architecture we designed
- What our actual implementation does
- How every studied component works
- Why each component exists
- What technologies, libraries, and resources we use
- How data moves through the system
- Which exact repository files, functions, and classes implement each part
- What is actually implemented
- What is partially implemented
- What is only a PS requirement
- What is not implemented
- What limitations exist
- What we can honestly claim to judges
- How to explain the system technically

### Distinction from PROJECT_STATE.md

| Document | Purpose |
|---|---|
| **PROJECT_STATE.md** | Development status, handoff notes, milestones, current work, sprint progress |
| **SYSTEM_UNDERSTANDING.md** (this document) | Permanent technical and conceptual knowledge base for understanding the actual system |

PROJECT_STATE.md answers: *"Where are we in development?"*

SYSTEM_UNDERSTANDING.md answers: *"How does our system actually work, and why?"*

### Two Layers of Understanding

This document preserves two layers:

**LAYER A — CONCEPTUAL UNDERSTANDING**: What the technology/concept means and why it matters.

**LAYER B — ACTUAL IMPLEMENTATION**: How OUR repository actually implements or uses that concept.

These two layers are never confused. If something is conceptually relevant to the PS but not implemented by us, that is clearly stated.

### Evidence Rules

All implementation claims follow strict evidence rules:

- Never assume an implementation exists because it is mentioned in the PS
- Never assume an implementation exists because it would be a logical design choice
- The actual repository is inspected before making implementation claims
- Implementation claims include: FILE, FUNCTION/CLASS, INPUT, PROCESSING, OUTPUT
- If something is not found: `NOT FOUND IN REPOSITORY`
- If the PS requires it but we don't provide it: `PS REQUIREMENT — NOT CURRENTLY IMPLEMENTED`
- If our implementation differs from the PS: `IMPLEMENTED DIFFERENTLY`
- If something is planned but not implemented: `PLANNED/FUTURE — NOT CURRENTLY IMPLEMENTED`

---

# PART A — CONCEPTUAL FOUNDATION

## 1. Problem Statement

### 1.1 Official PS 26145

**Title:** AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

**Organization:** National Technical Research Organisation (NTRO)

**Category:** Software

**Theme:** Blockchain & Cybersecurity

> The official verbatim text is preserved in [`official-problem-statement.md`](file:///home/ash/sih/unithreat-ai/docs/official-problem-statement.md).

### 1.2 Objective

Design and build an AI/ML pipeline that:

1. **Ingests** a one-directional stream of IP traffic from simulated IP data
2. **Detects**, **classifies**, and **scores** cybersecurity threats in near real time
3. Uses **only passively collected data**
4. **Cannot** re-contact the traffic's source or destination
5. **Cannot** complete any handshake itself
6. **Cannot** issue any action back across the ingest path
7. Outputs **intelligence**: labelled alerts, confidence scores, supporting evidence, on a visualisation dashboard

### 1.3 Required Threat Categories

The PS explicitly requires detection of six threat types:

| # | Threat | PS Detection Basis |
|---|---|---|
| a | Volumetric / protocol DDoS (SYN floods, UDP reflection/amplification, spoofed-source floods) | Flow-level rate + source-IP entropy statistics |
| b | Botnet C2 beaconing | Periodicity / inter-arrival analysis toward a small set of destinations |
| c | DGA domains and DNS tunnelling | Entropy/n-gram analysis of DNS query names, query-length and record-type anomalies |
| d | Malware inside encrypted sessions | TLS/QUIC metadata only (JA3/JA3S/JA4, packet-size and timing sequences) — no decryption |
| e | Reconnaissance / port scanning | Fan-out from one source across many destination ports/hosts |
| f | Data exfiltration | Asymmetric flow-volume anomalies, unusual outbound/inbound byte ratios |

### 1.4 Expected Solution

The PS expects:

- Working prototype (source repository): ingest, feature extraction, model inference, alert output
- Documentation of model(s) used, features engineered, training approach, validation approach
- Simple dashboard of live or replayed detections with severity and confidence

### 1.5 Mandatory Architectural Constraints

1. **Read-only ingest** — no return path, no live query to source, no inline block
2. **No payload decryption** — TLS/QUIC analysed from metadata only
3. **Streaming, not batch** — incremental processing, bounded-latency alerts
4. **Defined throughput target** — must state and demonstrate tested rate (flows/sec or Mbps sustained)
5. **Standardized alert schema** — timestamp, flow identifier, threat class, confidence score, supporting evidence feature, minimum

### 1.6 Dataset Direction (from PS)

The PS suggests:

- **Benign:** iperf3, Ostinato, TRex, normal DNS/HTTP/HTTPS/TLS/QUIC background traffic
- **Attack:** hping3 (SYN/UDP floods), Slowloris (slow HTTP exhaustion), dnscat2/iodine (DNS tunnelling), DGA samples (e.g. DGArchive), sandboxed C2 emulator for beaconing timing
- All attack-traffic generation confined to an isolated, authorized lab environment
- No real malware

### 1.7 PS Requirement vs Our Implementation (Summary)

| PS Requirement | Our Implementation Status |
|---|---|
| Read-only ingest | ✅ Implemented — JSONL replay adapter, strictly read-only |
| No payload decryption | ✅ Implemented — metadata-only extraction from `dns`, `tls`, `quic` sub-objects |
| Streaming, not batch | ✅ Implemented — line-by-line generator, incremental processing |
| Defined throughput target | Status: NOT YET STUDIED (see §34) |
| Standardized alert schema | ✅ Implemented — `contracts/alert-schema.json` |
| DDoS detection | ✅ Statistical detector implemented |
| C2 beaconing detection | ✅ Statistical detector implemented |
| DGA / DNS tunnelling detection | ✅ Statistical detector implemented |
| Encrypted session anomaly | ✅ Statistical detector implemented |
| Reconnaissance / port scanning | ✅ Statistical detector implemented |
| Data exfiltration detection | ✅ Statistical detector implemented |
| ML model inference | ✅ Random Forest implemented |
| Visualization dashboard | ✅ React frontend implemented |
| PCAP ingest | PLANNED/FUTURE — NOT CURRENTLY IMPLEMENTED |
| NetFlow/IPFIX/sFlow ingest | PLANNED/FUTURE — NOT CURRENTLY IMPLEMENTED |
| JA3/JA3S/JA4 fingerprinting (computed from raw packets) | PS REQUIREMENT — NOT CURRENTLY IMPLEMENTED (see §18) |
| Real external traffic datasets (hping3, dnscat2, etc.) | Status: NOT YET STUDIED (see §32–33) |

---

## 2. Why This Problem Exists

### 2.1 Critical Infrastructure Monitoring

Critical infrastructure operators (power grids, telecommunications, government networks, financial systems) need to continuously monitor their network gateways and peering links for cybersecurity threats. These operators cannot afford to allow any monitoring tool to become a vector for attack against the production network itself.

### 2.2 Passive Monitoring Enclave

To solve this, operators deploy a **monitoring enclave** — a physically or logically isolated environment that receives a copy of all network traffic crossing a gateway link. This enclave:

- **Can see** everything crossing the link
- **Has no physical or protocol-level path back** into the production network

This isolation is deliberate. If a compromised monitoring system could communicate back to the production network, it would become a pivot point for attackers to reach the core infrastructure.

### 2.3 Why the System Cannot Interact with Production Traffic

The monitoring enclave is fed by either:

- **Passive mirroring** (e.g., a network TAP or SPAN port that copies traffic)
- **Hardware data diodes** (physical devices that enforce one-way data flow at the hardware level)

In either case, the monitoring system:

- Cannot send packets back to the production network
- Cannot probe hosts on the production network
- Cannot complete TCP handshakes with endpoints it observes
- Cannot issue mitigation commands (block, quarantine, etc.)
- Cannot modify traffic in any way

This is the fundamental constraint that shapes the entire system: **all intelligence must be derived from passive observation alone**.

---

## 3. Unidirectional IP Traffic

### 3.1 What Unidirectional Means

"Unidirectional" describes the data flow between the production network and the monitoring enclave. Traffic flows in **one direction only**: from the production network into the monitoring system. There is no return path.

### 3.2 One-Way Observation

The system receives a copy of IP packets as they cross a monitored link. It observes:

- Packet headers (IP, TCP, UDP, DNS, TLS ClientHello, etc.)
- Packet sizes and timing
- Flow metadata (source/destination, ports, protocols, duration, volumes)
- Protocol-specific metadata that can be extracted from headers

It **cannot**:

- Send any response back to the traffic source
- Request additional information from endpoints
- Actively scan or probe any host

### 3.3 Data Diode / Passive Mirror Concept

A **data diode** is a hardware device that physically enforces one-way data flow. It may use optical isolation or similar techniques to guarantee that signals can only travel in one direction. Even a software compromise of the monitoring system cannot reverse the data flow.

A **passive mirror** (SPAN port, TAP) copies traffic without modifying it. While not as physically enforced as a data diode, the monitoring system is architecturally designed not to have a return path.

Both methods produce the same result for our system: a stream of observed traffic with no ability to interact.

---

## 4. Passive Monitoring

### 4.1 Observation vs Active Interaction

**Active monitoring** involves sending probes, running vulnerability scans, or querying endpoints to gather information. Examples: Nmap scans, active health checks, SNMP queries.

**Passive monitoring** involves observing traffic that already exists on the network without generating any additional traffic. The monitoring system is a silent observer.

### 4.2 Why Probing Is Prohibited

In the context of SIH 26145:

1. **No return path exists** — the hardware/architecture physically prevents sending packets back
2. **Security isolation** — if the monitoring system could probe, a compromised monitor could be used to attack the production network
3. **Chain of custody** — passive observation preserves forensic integrity; active probing would contaminate the evidence

### 4.3 Why the System Cannot Initiate Investigation Traffic

Even if the system detects something suspicious, it cannot:

- Send a DNS query to resolve a suspicious domain
- Attempt a TCP connection to a suspicious IP
- Download a suspicious file for analysis
- Query a threat intelligence API in real-time (unless the API is reachable from the monitoring enclave via a separate, non-production path)

All analysis must work with what has already been passively captured.

---

## 5. Handshake Concept

### 5.1 What a TCP Handshake Is

A TCP connection is established through a **three-way handshake**:

1. **SYN** — Client sends a SYN (synchronize) packet to the server
2. **SYN-ACK** — Server responds with SYN-ACK (synchronize-acknowledge)
3. **ACK** — Client sends a final ACK (acknowledge) to confirm

After these three packets, the TCP connection is "established" and data can flow in both directions.

### 5.2 Why Our System Cannot Complete a Handshake

Our system **observes** SYN packets, SYN-ACK packets, and ACK packets as they cross the monitored link. It can identify TCP flags in the traffic it sees.

However, it **cannot**:

- Send its own SYN to initiate a connection to any observed host
- Send a SYN-ACK in response to an observed SYN
- Complete any handshake with any endpoint on the production network

This means the system cannot verify whether a connection was actually established — it can only observe the handshake packets that were captured. In a unidirectional mirror, it may only see one direction of the handshake (e.g., only the SYN packets from one side, without the SYN-ACK responses).

### 5.3 Implications for Detection

Because handshakes cannot be completed:

- The system cannot confirm if a scanned port is actually open
- The system cannot negotiate TLS to inspect certificate chains
- The system cannot verify DNS responses by querying the domain itself
- Detection must rely on statistical patterns in the observed partial traffic

---

## 6. Payload and Encryption

### 6.1 Packet Headers vs Payload

Every IP packet has two logical parts:

- **Headers**: Structured metadata fields (source/destination IP, ports, protocol, flags, sequence numbers, etc.)
- **Payload**: The actual data content carried by the packet (HTTP request body, file contents, encrypted application data, etc.)

### 6.2 Encryption: TLS and QUIC

**TLS (Transport Layer Security)** encrypts the payload of TCP connections. After a TLS handshake, the application data is encrypted and cannot be read without the session keys.

**QUIC** is a transport protocol built on UDP that includes built-in encryption (based on TLS 1.3). QUIC encrypts both the payload and most of the transport-layer headers.

### 6.3 What Our System Can and Cannot See

**Can see (metadata):**

- TLS ClientHello message contents (before encryption begins): TLS version, cipher suites offered, Server Name Indication (SNI), extensions
- TLS ServerHello message contents: selected cipher, server certificate (in TLS 1.2)
- QUIC initial packets (partially observable): QUIC version, some connection metadata
- Packet sizes, timing, direction

**Cannot see (encrypted payload):**

- Application-layer data (HTTP request/response bodies, file contents, etc.)
- Anything encrypted by TLS or QUIC after the handshake completes

### 6.4 Why Our System Cannot Decrypt Payloads

The PS explicitly prohibits payload decryption:

> "No payload decryption — TLS/QUIC analysed from metadata only."

Even if decryption were attempted:

- The system does not possess the private keys of monitored servers
- The system cannot perform a man-in-the-middle attack (no return path)
- Modern TLS 1.3 and QUIC use ephemeral key exchange, so even if server keys were available, past sessions cannot be decrypted

Therefore, all encrypted-session analysis must use **metadata only**: TLS version, cipher suite, SNI, certificate properties, packet sizes, timing patterns, JA3/JA3S/JA4 fingerprints.

---

## 7. Packets

### 7.1 What a Packet Is

A **packet** is the fundamental unit of data transmitted across an IP network. Each packet is an independent, self-contained unit that carries:

- **IP header**: Source IP, destination IP, protocol number, TTL, total length
- **Transport header** (TCP/UDP): Source port, destination port, sequence numbers (TCP), flags (TCP), length
- **Application/payload data**: The actual content being transmitted

### 7.2 Packet Structure (Simplified)

```
┌──────────────────────────────────────┐
│           IP Header (20+ bytes)      │
│  src_ip, dst_ip, protocol, TTL, ... │
├──────────────────────────────────────┤
│     Transport Header (TCP/UDP)       │
│  src_port, dst_port, flags, seq, ...│
├──────────────────────────────────────┤
│           Payload (variable)         │
│  Application data (may be encrypted) │
└──────────────────────────────────────┘
```

### 7.3 Metadata vs Payload

For our system:

- **Metadata** = headers + observable protocol handshake fields = what we can use
- **Payload** = encrypted or application-layer content = what we cannot use

### 7.4 What Can Be Observed Passively

From passively captured packets, we can extract:

- Source and destination IP addresses
- Source and destination ports
- Protocol (TCP, UDP, ICMP, etc.)
- TCP flags (SYN, ACK, FIN, RST, PSH, URG)
- Packet size
- Packet timing (arrival time)
- DNS query names and record types (DNS packets are typically unencrypted, though DoH/DoT are not)
- TLS ClientHello/ServerHello metadata
- QUIC initial packet metadata

---

## 8. Flows

### 8.1 What a Flow Is

A **flow** is a logical grouping of related packets that belong to the same network conversation. Instead of analyzing individual packets, flows aggregate packet-level observations into a higher-level summary.

### 8.2 Packet vs Flow

| Aspect | Packet | Flow |
|---|---|---|
| Granularity | Single transmission unit | Aggregated conversation |
| Volume | Very high (millions/sec on busy links) | Much lower (one record per conversation) |
| Information | Headers + payload of one packet | Statistics across many packets |
| Use case | Deep packet inspection, forensics | Statistical analysis, anomaly detection |

### 8.3 Flow Identification: The 5-Tuple

A flow is traditionally identified by a **5-tuple**:

1. **Source IP address**
2. **Destination IP address**
3. **Source port**
4. **Destination port**
5. **Protocol** (TCP, UDP, ICMP, etc.)

All packets sharing the same 5-tuple within a time window are considered part of the same flow.

### 8.4 Why Flow-Level Analysis Is Useful

Flow-level analysis is essential for this system because:

1. **Volume reduction**: Aggregating packets into flows dramatically reduces the data volume
2. **Statistical patterns**: Threats like DDoS, beaconing, and exfiltration are characterized by flow-level statistics (rates, volumes, timing patterns), not individual packet contents
3. **Metadata sufficiency**: Since payload decryption is prohibited, flow-level metadata (IPs, ports, byte counts, durations, protocol flags) contains the maximum usable information
4. **Bounded processing**: Flow records enable streaming analysis with bounded memory, which is required by the PS

### Learning Checkpoint — Part A

#### What the concepts mean
The Problem Statement asks us to build a passive, read-only AI/ML pipeline that monitors unidirectional IP traffic and detects six categories of cybersecurity threats using only flow-level metadata and statistical analysis — no probing, no handshake completion, no payload decryption.

#### Why this matters
Critical infrastructure operators need monitoring that cannot become an attack vector. Hardware data diodes and passive mirrors enforce one-way data flow. The intelligence layer must work purely from observation.

#### Key constraints understood
- Unidirectional: one-way data flow, no return path
- Passive: observation only, no probing
- No handshake completion: cannot initiate or complete TCP handshakes
- No payload decryption: TLS/QUIC metadata only
- Streaming: incremental, bounded-latency processing
- Flow-level: packets are aggregated into flows for statistical analysis

#### Next concept
Now switching from theory to the actual repository implementation.

---

# PART B — ACTUAL REPOSITORY IMPLEMENTATION

We are now switching from conceptual understanding to the actual repository.

**Learning position:**

```
Problem Statement
  → Unidirectional/passive monitoring
    → Packet
      → Flow
        → NOW: ACTUAL REPOSITORY
```

---

## 9. Repository Structure

The repository root is at `/home/ash/sih/unithreat-ai/`.

### 9.1 Top-Level Layout

| Path | Type | Purpose |
|---|---|---|
| [`contracts/`](file:///home/ash/sih/unithreat-ai/contracts) | Directory | JSON Schema contracts — the authoritative source of truth for data structures |
| [`src/unithreat/`](file:///home/ash/sih/unithreat-ai/src/unithreat) | Directory | Main Python package — all backend pipeline code |
| [`frontend/`](file:///home/ash/sih/unithreat-ai/frontend) | Directory | React/TypeScript frontend application |
| [`tests/`](file:///home/ash/sih/unithreat-ai/tests) | Directory | Test suite (pytest) |
| [`scripts/`](file:///home/ash/sih/unithreat-ai/scripts) | Directory | CLI demonstration and utility scripts |
| [`docs/`](file:///home/ash/sih/unithreat-ai/docs) | Directory | Documentation (this file, PROJECT_STATE.md, architecture docs) |
| [`artifacts/`](file:///home/ash/sih/unithreat-ai/artifacts) | Directory | Build artifacts (trained models, benchmarks, validation results) |
| [`pyproject.toml`](file:///home/ash/sih/unithreat-ai/pyproject.toml) | File | Project configuration, dependencies, build system |
| [`AGENTS.md`](file:///home/ash/sih/unithreat-ai/AGENTS.md) | File | Agent guidelines and project rules |

### 9.2 Backend Package Structure (`src/unithreat/`)

| Module | Purpose | Role in Pipeline |
|---|---|---|
| [`ingest/`](file:///home/ash/sih/unithreat-ai/src/unithreat/ingest) | Flow ingestion and normalization | Entry point — raw data → normalized `Flow` objects |
| [`generator/`](file:///home/ash/sih/unithreat-ai/src/unithreat/generator) | Synthetic traffic generation | Development/testing — produces schema-compliant flow records |
| [`features/`](file:///home/ash/sih/unithreat-ai/src/unithreat/features) | Feature extraction | `Flow` → `FeatureRecord` with statistical and behavioral features |
| [`detection/`](file:///home/ash/sih/unithreat-ai/src/unithreat/detection) | Statistical/behavioral threat detection | `FeatureRecord` → `DetectionResult` |
| [`ml/`](file:///home/ash/sih/unithreat-ai/src/unithreat/ml) | Machine learning (Random Forest) | ML model training, inference |
| [`alerts/`](file:///home/ash/sih/unithreat-ai/src/unithreat/alerts) | Alert fusion, deduplication, storage | `DetectionResult` → final `Alert` objects |
| [`api/`](file:///home/ash/sih/unithreat-ai/src/unithreat/api) | FastAPI REST + WebSocket | HTTP/WS interface for frontend |
| [`behavioral/`](file:///home/ash/sih/unithreat-ai/src/unithreat/behavioral) | Behavioral analysis | Empty `__init__.py` only — placeholder, NOT CURRENTLY IMPLEMENTED |
| [`metadata/`](file:///home/ash/sih/unithreat-ai/src/unithreat/metadata) | Metadata analysis | Empty `__init__.py` only — placeholder, NOT CURRENTLY IMPLEMENTED |

### 9.3 Contracts

| Contract | Purpose |
|---|---|
| [`flow-schema.json`](file:///home/ash/sih/unithreat-ai/contracts/flow-schema.json) | Normalized passive flow event schema |
| [`feature-schema.json`](file:///home/ash/sih/unithreat-ai/contracts/feature-schema.json) | Network feature record schema |
| [`evidence-schema.json`](file:///home/ash/sih/unithreat-ai/contracts/evidence-schema.json) | Supporting evidence signal schema |
| [`alert-schema.json`](file:///home/ash/sih/unithreat-ai/contracts/alert-schema.json) | Standardized alert output schema |
| [`ml-prediction-schema.json`](file:///home/ash/sih/unithreat-ai/contracts/ml-prediction-schema.json) | ML model prediction schema |

### 9.4 Production Dependencies

Verified from [`pyproject.toml`](file:///home/ash/sih/unithreat-ai/pyproject.toml):

| Dependency | Version | Purpose |
|---|---|---|
| `pydantic` | ≥2.10, <3 | Data model validation and serialization |
| `jsonschema` | ≥4.23, <5 | JSON Schema Draft 2020-12 validation |
| `scikit-learn` | ≥1.4, <2 | Machine learning (Random Forest) |
| `fastapi` | ≥0.115, <1 | REST API and WebSocket framework |
| `uvicorn` | ≥0.30, <1 | ASGI server for FastAPI |
| `websockets` | ≥13, <18 | WebSocket support |

Dev dependencies: `pytest`, `pytest-cov`, `httpx`.

**Python version requirement:** ≥3.14

---

## 10. Actual Ingestion

### 10.1 Concept

**Concept:** Ingestion is the process of reading raw traffic data and converting it into a normalized, typed data structure that the rest of the pipeline can consume.

**Implementation:** Our ingestion layer reads JSON flow records from a JSONL file (one JSON object per line), validates each record against the contract schema, and produces immutable `Flow` model objects.

### 10.2 Input Format

**Actual input:** JSON Lines (`.jsonl`) files containing one JSON object per line. Each JSON object represents a single pre-captured or synthetically generated flow record.

**Example input record:**
```json
{
  "flow_id": "flow-001",
  "timestamp": "2026-09-06T12:00:00.000000Z",
  "src_ip": "192.168.1.100",
  "dst_ip": "10.0.0.1",
  "protocol": "TCP",
  "src_port": 54321,
  "dst_port": 80,
  "direction": "outbound",
  "duration": 1.5,
  "packet_count": 12,
  "byte_count": 4096,
  "tcp_flags": "SYN,ACK"
}
```

**Input schema:** Governed by [`contracts/flow-schema.json`](file:///home/ash/sih/unithreat-ai/contracts/flow-schema.json) (JSON Schema Draft 2020-12, `additionalProperties: false`).

### 10.3 Where Input Comes From

**Currently:** Input comes from JSONL files. These files are either:

1. Written by the synthetic traffic generator (`unithreat.generator`) during development and testing
2. Pre-captured flow records stored as files

**Production adapters (PCAP, NetFlow, IPFIX, sFlow):** PLANNED/FUTURE — NOT CURRENTLY IMPLEMENTED. The adapter architecture is designed but only the JSONL adapter is implemented.

### 10.4 Ingestion Mechanism — Detailed Code Trace

#### Step 1: Adapter opens file and reads lines

**FILE:** [`src/unithreat/ingest/adapters/jsonl.py`](file:///home/ash/sih/unithreat-ai/src/unithreat/ingest/adapters/jsonl.py)
**FUNCTION:** `replay_jsonl()` (functional API) or `JsonlAdapter.__iter__()` (class API)

**INPUT:** File path (`str | Path`) or file-like object (`IO[str]`), plus optional `speed_factor` and `skip_malformed` parameters.

**PROCESSING:**
1. Delegates to `_open_and_stream()` which opens the file in read-only mode (`path.open(encoding="utf-8")`) if given a path, or reads directly if given a file-like object
2. `_stream_lines()` iterates line-by-line using `enumerate(fh, start=1)` — **never loads entire file into memory**
3. Each non-empty line is decoded from JSON via `json.loads(line)`
4. If JSON decoding fails: raises `json.JSONDecodeError` or warns and skips (depending on `skip_malformed`)
5. The decoded dict is passed to `parse_flow()` for validation

**STREAMING BEHAVIOR:** Line-by-line generator. The file is read incrementally. This satisfies the PS requirement for streaming (not batch) processing.

**READ-ONLY BEHAVIOR:** The file is opened with `path.open(encoding="utf-8")` — read-only. No write operations, no network connections, no packet injection occur in this module.

**TIMING SIMULATION:** If `speed_factor > 0.0`, the adapter calculates the wall-clock gap between consecutive flow timestamps and sleeps proportionally to simulate near-real-time replay. `speed_factor=1.0` replays at original capture speed. `speed_factor=0.0` (default) replays as fast as possible with no delay.

**OUTPUT:** Yields validated, immutable `Flow` objects one at a time.

#### Step 2: Schema validation and model construction

**FILE:** [`src/unithreat/ingest/parser.py`](file:///home/ash/sih/unithreat-ai/src/unithreat/ingest/parser.py)
**FUNCTION:** `parse_flow(raw: Any) -> Flow`

**INPUT:** A Python dict decoded from a JSON flow record.

**PROCESSING:**
1. **Type check:** Rejects non-dict inputs immediately with `FlowParseError`
2. **JSON Schema validation:** Validates the dict against `contracts/flow-schema.json` using `jsonschema.Draft202012Validator`. The schema is loaded **once at import time** from `_SCHEMA_PATH = Path(__file__).resolve().parents[3] / "contracts" / "flow-schema.json"`. All schema errors are collected; the first error produces a human-readable `FlowParseError` with the path and message.
3. **Pydantic model construction:** Calls `Flow.model_validate(raw)` to construct the typed, immutable `Flow` model. This applies Pydantic's own type coercion and business constraints (port ranges, non-negative values, etc.).

**OUTPUT:** A validated, immutable `Flow` instance.

**ERROR HANDLING:** Raises `FlowParseError` (subclass of `ValueError`) with attributes `reason` (human-readable) and `raw` (the original dict).

#### Step 3: Flow model

**FILE:** [`src/unithreat/ingest/models.py`](file:///home/ash/sih/unithreat-ai/src/unithreat/ingest/models.py)
**CLASS:** `Flow(BaseModel)`

The `Flow` model is the normalized, immutable representation of a single passive flow event. It mirrors `contracts/flow-schema.json` exactly.

See §11 for full field documentation.

### 10.5 Adapter Architecture

**FILE:** [`src/unithreat/ingest/source.py`](file:///home/ash/sih/unithreat-ai/src/unithreat/ingest/source.py)
**CLASS:** `FlowSource(Protocol)`

The `FlowSource` is a Python `Protocol` (structural typing) that all ingest adapters must satisfy. It requires a single method:

```python
def __iter__(self) -> Iterator[Flow]: ...
```

This decouples the detection pipeline from any specific input mechanism. The pipeline depends only on `FlowSource` / `Iterable[Flow]`, never on a specific adapter.

**Adapter registry (current):**

| Adapter | File | Status |
|---|---|---|
| JSONL replay | [`src/unithreat/ingest/adapters/jsonl.py`](file:///home/ash/sih/unithreat-ai/src/unithreat/ingest/adapters/jsonl.py) | ✅ Implemented |
| PCAP | Not implemented | PLANNED/FUTURE — NOT CURRENTLY IMPLEMENTED |
| NetFlow | Not implemented | PLANNED/FUTURE — NOT CURRENTLY IMPLEMENTED |
| IPFIX | Not implemented | PLANNED/FUTURE — NOT CURRENTLY IMPLEMENTED |
| sFlow | Not implemented | PLANNED/FUTURE — NOT CURRENTLY IMPLEMENTED |

**Deprecated shim:** [`src/unithreat/ingest/replay.py`](file:///home/ash/sih/unithreat-ai/src/unithreat/ingest/replay.py) is a deprecated re-export shim that warns and redirects to `unithreat.ingest.adapters.jsonl`.

### 10.6 Technologies and Libraries Used

| Technology | Used For | Where |
|---|---|---|
| Python `json` stdlib | JSON line decoding | `jsonl.py` → `json.loads()` |
| Python `time` stdlib | Near-real-time replay timing | `jsonl.py` → `time.monotonic()`, `time.sleep()` |
| Python `pathlib` stdlib | File path handling | `jsonl.py`, `parser.py` |
| `jsonschema` (Draft 2020-12) | Schema validation of raw records | `parser.py` → `Draft202012Validator` |
| `pydantic` v2 | Typed model construction and validation | `models.py` → `Flow(BaseModel)` |

### Learning Checkpoint — §10 Ingestion

#### What the concept means
Ingestion is the entry point of the detection pipeline: raw traffic data is read, validated, and normalized into a consistent data structure.

#### What our system actually does
Reads JSON Lines files one line at a time, validates each line against `contracts/flow-schema.json` using `jsonschema`, constructs immutable Pydantic `Flow` models, and yields them as a Python generator. Supports optional near-real-time replay timing.

#### Exact repository locations
- Entry point: [`src/unithreat/ingest/adapters/jsonl.py`](file:///home/ash/sih/unithreat-ai/src/unithreat/ingest/adapters/jsonl.py) → `replay_jsonl()`, `JsonlAdapter`
- Validation: [`src/unithreat/ingest/parser.py`](file:///home/ash/sih/unithreat-ai/src/unithreat/ingest/parser.py) → `parse_flow()`
- Model: [`src/unithreat/ingest/models.py`](file:///home/ash/sih/unithreat-ai/src/unithreat/ingest/models.py) → `Flow`
- Protocol: [`src/unithreat/ingest/source.py`](file:///home/ash/sih/unithreat-ai/src/unithreat/ingest/source.py) → `FlowSource`
- Schema: [`contracts/flow-schema.json`](file:///home/ash/sih/unithreat-ai/contracts/flow-schema.json)
- Tests: [`tests/ingest/`](file:///home/ash/sih/unithreat-ai/tests/ingest) → `test_models.py`, `test_parser.py`, `test_replay.py`, `test_source.py`

#### Technologies/resources used
`jsonschema` (Draft 2020-12), `pydantic` v2, Python stdlib (`json`, `time`, `pathlib`, `warnings`)

#### PS requirement
"Read-only ingest" + "Streaming, not batch" + "No return path"

#### Implementation status
✅ JSONL adapter fully implemented and tested. PCAP/NetFlow/IPFIX/sFlow adapters are PLANNED/FUTURE — NOT CURRENTLY IMPLEMENTED.

#### Important limitations
- Only JSONL input is currently supported — this is a development/demo path, not a production ingest mechanism
- No live network capture capability currently exists
- The JSONL adapter depends on pre-captured or synthetically generated flow records

#### Judge-ready understanding
"Our ingestion layer reads pre-captured or synthetic flow records from JSON Lines files, validates each record against our JSON Schema contract, and produces typed, immutable Flow model objects. It processes one record at a time in a streaming fashion, never loading the entire dataset into memory. The adapter architecture is designed to support multiple input formats (PCAP, NetFlow, IPFIX, sFlow) through a common FlowSource protocol, but currently only the JSONL development adapter is implemented."

#### Questions/uncertainties
None for this section.

#### Next concept
Flow Representation (§11).

---

## 11. Actual Flow Representation

### 11.1 Concept

**Concept:** A flow is a logical grouping of related packets belonging to the same network conversation, represented as a single record with aggregated statistics.

**Implementation:** Our system represents each flow as an immutable Pydantic model (`Flow`) that mirrors `contracts/flow-schema.json` exactly. The model is frozen after construction to reflect the read-only nature of ingest data.

### 11.2 Flow Model — Full Field Documentation

**FILE:** [`src/unithreat/ingest/models.py`](file:///home/ash/sih/unithreat-ai/src/unithreat/ingest/models.py)
**CLASS:** `Flow(BaseModel)` with `model_config = {"frozen": True}`

#### Required Fields (must be present in every flow record)

| Field | Type | Description |
|---|---|---|
| `flow_id` | `str` | Unique identifier for this flow record |
| `timestamp` | `datetime` | When the flow was observed (ISO 8601, parsed by Pydantic) |
| `src_ip` | `str` | Source IP address |
| `dst_ip` | `str` | Destination IP address |
| `protocol` | `str` | Transport protocol (e.g., "TCP", "UDP", "ICMP") |

#### Optional Flow Fields (may be `None` when absent)

| Field | Type | Constraints | Description |
|---|---|---|---|
| `src_port` | `int \| None` | 0–65535 | Source port number |
| `dst_port` | `int \| None` | 0–65535 | Destination port number |
| `direction` | `Literal["inbound", "outbound", "internal", "unknown"] \| None` | Enum | Traffic direction relative to the monitored boundary |
| `duration` | `float \| None` | ≥ 0.0 | Flow duration in seconds |
| `packet_count` | `int \| None` | ≥ 0 | Number of packets in the flow |
| `byte_count` | `int \| None` | ≥ 0 | Total bytes in the flow |
| `tcp_flags` | `str \| None` | — | Observed TCP flags (e.g., "SYN", "SYN,ACK") |

#### Optional Protocol-Metadata Sub-Objects

| Field | Type | Description |
|---|---|---|
| `dns` | `dict[str, Any] \| None` | DNS query/response metadata (query name, qtype, rcode) |
| `tls` | `dict[str, Any] \| None` | TLS handshake metadata (version, SNI, JA3, cipher) |
| `quic` | `dict[str, Any] \| None` | QUIC connection metadata (version, SNI) |

### 11.3 Flow Identification

**Our flow ID mechanism:** Each flow has a `flow_id` field (required, type `str`). This is an opaque string identifier.

**5-tuple concept:** The traditional 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol) is represented by five separate fields on the `Flow` model. These fields are used by downstream components (feature extraction, windowing) to identify conversations and compute per-source/per-destination statistics.

**Important:** The `flow_id` is **not** computed from the 5-tuple by the ingestion layer. It is provided by the input data source (e.g., generated by the synthetic traffic generator). The ingestion layer does not perform flow aggregation from raw packets — it receives pre-aggregated flow records.

### 11.4 Timestamps

The `timestamp` field is required and parsed as a Python `datetime` object. The `_parse_timestamp` field validator in the `Flow` model accepts ISO 8601 strings and passes them through for Pydantic's native parsing. This represents when the flow was observed or captured.

### 11.5 Protocol-Metadata Sub-Objects

The `dns`, `tls`, and `quic` fields are opaque `dict[str, Any]` sub-objects. The flow schema (JSON Schema) validates them only as `"type": ["object", "null"]` — it does not enforce their internal structure.

The **feature extraction layer** (not the ingestion layer) is responsible for interpreting the contents of these sub-objects. For example, feature extraction reads `flow.dns.get("query")` to extract DNS query names.

### 11.6 Immutability

The `Flow` model is configured with `model_config = {"frozen": True}`, making instances immutable after construction. This reflects the read-only nature of passively observed data — once a flow is captured, its data should not be modified.

### 11.7 Schema Enforcement

The flow schema (`contracts/flow-schema.json`) uses `additionalProperties: false`, meaning any fields not explicitly defined in the schema will cause validation to fail. This prevents schema drift and ensures all data structures are contract-compliant.

### Learning Checkpoint — §11 Flow Representation

#### What the concept means
A flow is an aggregated summary of a network conversation, identified by source/destination addresses, ports, and protocol.

#### What our system actually does
Represents each flow as a frozen Pydantic `BaseModel` instance with 5 required fields (`flow_id`, `timestamp`, `src_ip`, `dst_ip`, `protocol`), 7 optional statistical fields, and 3 optional protocol-metadata sub-objects. Schema enforced by `contracts/flow-schema.json` with `additionalProperties: false`.

#### Exact repository locations
- Model: [`src/unithreat/ingest/models.py`](file:///home/ash/sih/unithreat-ai/src/unithreat/ingest/models.py) → `Flow` class (lines 29–74)
- Schema: [`contracts/flow-schema.json`](file:///home/ash/sih/unithreat-ai/contracts/flow-schema.json)

#### Technologies/resources used
`pydantic` v2 (`BaseModel`, `Field`, `field_validator`), `jsonschema` (Draft 2020-12 for schema validation in parser)

#### PS requirement
The PS requires flows with: timestamp, source/destination IP, ports, protocol, direction, duration, packet count, byte count, TCP flags, and protocol-specific metadata (DNS, TLS, QUIC).

#### Implementation status
✅ All PS-required flow fields are defined in the model and schema.

#### Important limitations
- The `dns`, `tls`, and `quic` sub-objects are not schema-validated internally at the flow level — their structure is interpreted downstream by feature extraction
- The `flow_id` is externally assigned, not computed from the 5-tuple by our system
- Our system does not aggregate raw packets into flows — it receives pre-aggregated flow records

#### Judge-ready understanding
"Each flow is represented as an immutable Pydantic model with strict JSON Schema validation. The model includes network coordinates (IPs, ports, protocol), flow statistics (duration, packet count, byte count), TCP flags, and optional protocol-metadata sub-objects for DNS, TLS, and QUIC. The schema uses additionalProperties: false to prevent undocumented fields."

#### Questions/uncertainties
None for this section.

#### Next concept
Handoff to Feature Extraction (§12).

---

## 12. Handoff to Feature Extraction

### 12.1 Concept

**Concept:** After a flow is ingested and normalized, it must be passed to the feature extraction stage, which computes numerical and categorical features for threat detection.

**Implementation:** The handoff from ingestion to feature extraction happens through three verified code paths in our repository.

### 12.2 Code Path Trace

The handoff from `Flow` to `FeatureRecord` occurs at the following verified call sites:

#### Path A: Direct extraction via `FeatureExtractor.extract()`

```
Flow (from ingest)
    ↓
FeatureExtractor.extract(flow)
    ↓
FeatureRecord (output)
```

**FILE:** [`src/unithreat/features/extractor.py`](file:///home/ash/sih/unithreat-ai/src/unithreat/features/extractor.py)
**CLASS:** `FeatureExtractor`
**METHOD:** `extract(flow: Flow | dict[str, Any], context=None, window_id=None) -> FeatureRecord`

**INPUT:** A `Flow` model instance (or a raw dict, which gets validated into a `Flow`)

**PROCESSING:**
1. If input is a `dict`, validates it into a `Flow` via `Flow.model_validate()`
2. Extracts base flow metrics (duration, packet_count, byte_count, rates, ratios)
3. Applies zero-duration safety (`max(duration, 0.001)` for rate calculations)
4. Extracts TCP flag booleans (`is_syn`, `is_ack`, `is_psh`, etc.)
5. Extracts DNS metadata features if `flow.dns` is present (query length, Shannon entropy, lexical metrics)
6. Extracts TLS metadata features if `flow.tls` is present (version, SNI, JA3, cipher, IP-as-SNI detection)
7. Extracts QUIC metadata features if `flow.quic` is present (version, SNI)
8. If windowing is enabled, calls `FeatureWindowTracker.update_and_compute()` to add sliding-window behavioral features
9. Merges any caller-provided contextual features
10. Constructs and returns a `FeatureRecord`

**OUTPUT:** A validated, immutable `FeatureRecord` conforming to `contracts/feature-schema.json`.

#### Path B: Via DetectionEngine.process_flow()

```
Flow (from ingest)
    ↓
DetectionEngine.process_flow(flow)
    ↓
  FeatureExtractor.extract(flow)    → FeatureRecord
    ↓
  DetectionEngine.process(record)   → list[DetectionResult]
```

**FILE:** [`src/unithreat/detection/engine.py`](file:///home/ash/sih/unithreat-ai/src/unithreat/detection/engine.py)
**CLASS:** `DetectionEngine`
**METHOD:** `process_flow(flow: Flow) -> list[DetectionResult]` (line 84)

This is a convenience method that chains feature extraction and detection:

```python
def process_flow(self, flow: Flow) -> list[DetectionResult]:
    record = self.extractor.extract(flow)
    return self.process(record)
```

The `DetectionEngine` holds its own `FeatureExtractor` instance (created in `__init__` at line 40: `self.extractor = FeatureExtractor()`).

#### Path C: Via DetectionEngine.process_stream()

```
Iterable[Flow] (from FlowSource/adapter)
    ↓
DetectionEngine.process_stream(stream)
    ↓
  for item in stream:
    if Flow → process_flow(item) → extract + detect
    if FeatureRecord → process(item) → detect only
    ↓
  yields DetectionResult objects
```

**FILE:** [`src/unithreat/detection/engine.py`](file:///home/ash/sih/unithreat-ai/src/unithreat/detection/engine.py)
**METHOD:** `process_stream(stream: Iterable[Flow | FeatureRecord]) -> Iterator[DetectionResult]` (line 91)

This is the streaming entry point that accepts a flow source and processes the entire stream incrementally, yielding detection results as a generator.

### 12.3 The FeatureRecord — Handoff Output

**FILE:** [`src/unithreat/features/models.py`](file:///home/ash/sih/unithreat-ai/src/unithreat/features/models.py)
**CLASS:** `FeatureRecord(BaseModel)` with `model_config = {"frozen": True}`

| Field | Type | Description |
|---|---|---|
| `flow_id` | `str` | Copied from the source `Flow.flow_id` |
| `timestamp` | `str` | ISO 8601 timestamp string (from `Flow.timestamp`, formatted) |
| `entity_id` | `str \| None` | Set to `flow.src_ip` — identifies the entity being tracked |
| `window_id` | `str \| None` | Optional window identifier (passed by caller) |
| `features` | `dict[str, float \| int \| str \| bool \| None]` | Flat dictionary of computed feature values |

**Schema:** Governed by [`contracts/feature-schema.json`](file:///home/ash/sih/unithreat-ai/contracts/feature-schema.json) (JSON Schema Draft 2020-12, `additionalProperties: false`).

### 12.4 Features Computed at Handoff

The `FeatureExtractor.extract()` method computes the following features from a `Flow`:

**Base flow metrics:**
- `duration`, `packet_count`, `byte_count`
- `packets_per_sec`, `bytes_per_sec`, `bytes_per_packet`

**Network coordinates (passed through):**
- `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `direction`

**TCP/UDP flag booleans:**
- `is_syn`, `is_ack`, `is_psh`, `is_fin`, `is_rst`, `is_urg`, `is_tcp`, `is_udp`
- `tcp_flags` (raw string)

**DNS metadata features (when `flow.dns` is present):**
- `has_dns`, `dns_query`, `dns_query_length`, `dns_entropy`
- `dns_qtype`, `dns_rcode`
- `dns_vowel_ratio`, `dns_consonant_ratio`, `dns_max_consonant_run`
- `dns_ngram_score`, `dns_digit_ratio`

**TLS metadata features (when `flow.tls` is present):**
- `has_tls`, `tls_version`, `tls_sni`, `tls_ja3`, `tls_cipher`, `is_ip_sni`

**QUIC metadata features (when `flow.quic` is present):**
- `has_quic`, `quic_version`, `quic_sni`

**Sliding-window behavioral features (when windowing enabled):**
- `src_fan_out`, `unique_dst_hosts`, `unique_dst_ports`, `dst_fan_in`
- `window_flow_count`, `flow_rate`
- `window_bytes_per_sec`, `window_packets_per_sec`
- `inter_arrival_time`, `mean_inter_arrival_time`, `inter_arrival_std`
- `inter_arrival_cv`, `periodicity_score`
- `protocol_tcp_ratio`, `protocol_udp_ratio`
- `outbound_bytes_window`, `inbound_bytes_window`, `outbound_inbound_byte_ratio`

### 12.5 Windowing at Handoff

**FILE:** [`src/unithreat/features/window.py`](file:///home/ash/sih/unithreat-ai/src/unithreat/features/window.py)
**CLASS:** `FeatureWindowTracker`

The `FeatureWindowTracker` is a stateful, bounded sliding-window tracker that computes rolling behavioral features incrementally. It is called during feature extraction (at handoff time) if windowing is enabled on the `FeatureExtractor`.

**Key parameters:**
- `window_duration_seconds`: Default 60.0 seconds — how far back to look
- `max_events_per_entity`: Default 200 — maximum flow snapshots per tracked entity
- `max_tracked_entities`: Default 10,000 — maximum number of tracked entities (LRU eviction)

**Internal state:**
- `_src_windows`: `OrderedDict[str, deque[FlowSnapshot]]` — tracks per-source-IP flow history
- `_dst_windows`: `OrderedDict[str, deque[FlowSnapshot]]` — tracks per-destination-IP flow history
- `_pair_windows`: `OrderedDict[tuple[str,str], deque[FlowSnapshot]]` — tracks per-conversation-pair flow history (10× window for beaconing)

**Bounded memory:** Uses `OrderedDict` with LRU eviction when `max_tracked_entities` is reached, `deque` with `maxlen` for bounded history per entity, and TTL-based pruning against the event timestamp.

### 12.6 Complete Handoff Diagram

```
┌─────────────────────────────────────────────┐
│  JSONL File (or future: PCAP / NetFlow)     │
└──────────────────┬──────────────────────────┘
                   │ json.loads() per line
                   ▼
┌─────────────────────────────────────────────┐
│  parse_flow(raw_dict)                       │
│  FILE: src/unithreat/ingest/parser.py       │
│  1. jsonschema validation                   │
│  2. Flow.model_validate(raw)                │
└──────────────────┬──────────────────────────┘
                   │ yields Flow objects
                   ▼
┌─────────────────────────────────────────────┐
│  FeatureExtractor.extract(flow)             │
│  FILE: src/unithreat/features/extractor.py  │
│  1. Base metrics (duration, rates, ratios)  │
│  2. TCP/UDP flags                           │
│  3. DNS metadata features                   │
│  4. TLS metadata features                   │
│  5. QUIC metadata features                  │
│  6. Window features (if enabled)            │
│     → FeatureWindowTracker.update_and_compute()
│  7. Contextual features (if provided)       │
└──────────────────┬──────────────────────────┘
                   │ returns FeatureRecord
                   ▼
┌─────────────────────────────────────────────┐
│  DetectionEngine.process(record)            │
│  FILE: src/unithreat/detection/engine.py    │
│  (NEXT STAGE — NOT YET STUDIED)             │
└─────────────────────────────────────────────┘
```

### Learning Checkpoint — §12 Handoff to Feature Extraction

#### What the concept means
The handoff is the transition point where raw, normalized flow data is transformed into numerical/categorical feature vectors suitable for statistical and ML-based threat detection.

#### What our system actually does
The `FeatureExtractor.extract()` method accepts a `Flow` object and produces a `FeatureRecord` containing ~37+ computed features. This includes base flow metrics, TCP/UDP flag parsing, DNS lexical analysis (Shannon entropy, vowel/consonant ratios, n-gram scores), TLS/QUIC metadata extraction, and streaming sliding-window behavioral features (fan-out, flow rates, inter-arrival timing, periodicity scores, byte ratios).

#### Exact repository locations
- Feature extraction: [`src/unithreat/features/extractor.py`](file:///home/ash/sih/unithreat-ai/src/unithreat/features/extractor.py) → `FeatureExtractor.extract()`, `extract_features()`, `compute_shannon_entropy()`, `compute_dns_lexical_metrics()`
- Feature model: [`src/unithreat/features/models.py`](file:///home/ash/sih/unithreat-ai/src/unithreat/features/models.py) → `FeatureRecord`
- Window tracker: [`src/unithreat/features/window.py`](file:///home/ash/sih/unithreat-ai/src/unithreat/features/window.py) → `FeatureWindowTracker`, `FlowSnapshot`
- Detection engine (calls extractor): [`src/unithreat/detection/engine.py`](file:///home/ash/sih/unithreat-ai/src/unithreat/detection/engine.py) → `DetectionEngine.process_flow()`, `process_stream()`
- Schema: [`contracts/feature-schema.json`](file:///home/ash/sih/unithreat-ai/contracts/feature-schema.json)
- Tests: [`tests/features/`](file:///home/ash/sih/unithreat-ai/tests/features) → `test_extractor.py`, `test_window.py`

#### Technologies/resources used
`pydantic` v2 (FeatureRecord model), Python stdlib (`math`, `re`, `collections.Counter`, `collections.OrderedDict`, `collections.deque`, `dataclasses`), Shannon entropy computation, English bigram analysis

#### PS requirement
The PS requires "feature extraction" as a pipeline stage. It specifies feature engineering relevant to each threat type (flow rates, entropy, periodicity, fan-out, byte ratios, TLS/QUIC metadata).

#### Implementation status
✅ Feature extraction is fully implemented with base metrics, DNS lexical analysis, TLS/QUIC metadata extraction, and streaming sliding-window behavioral features. The handoff from Flow → FeatureRecord → DetectionEngine is fully wired.

#### Important limitations
- The `tls_ja3` feature is extracted as a **pass-through** from the `flow.tls.ja3` field — our system does not compute JA3 fingerprints from raw TLS ClientHello packets. The fingerprint must be pre-computed by whatever captures the traffic or generates the flow record. See §18 for detailed JA3/JA3S/JA4 analysis.
- DNS entropy and lexical metrics are computed by the feature extractor, but the DNS query string itself must be present in the flow record's `dns.query` field — our system does not perform DNS packet dissection.
- Window features depend on stateful tracking and are only meaningful when flows arrive in temporal order.

#### Judge-ready understanding
"The handoff from ingestion to feature extraction is a direct function call: FeatureExtractor.extract(flow) → FeatureRecord. The extractor computes base flow metrics with zero-duration safety, parses TCP flags into boolean features, computes DNS query Shannon entropy and lexical metrics for DGA detection, extracts TLS/QUIC metadata fields, and computes streaming sliding-window behavioral features including source fan-out, flow rates, inter-arrival timing statistics, periodicity scores, and directional byte ratios. The window tracker uses bounded LRU state with TTL pruning to enforce memory limits. All output conforms to contracts/feature-schema.json."

#### Questions/uncertainties
None for this section.

#### Next concept
Feature Engineering details (§13) — NOT YET STUDIED.

---

# PART C — CONTINUE THE SAME PROCESS AS WE LEARN

The following sections will be studied and documented progressively as our learning continues. They are initialized as "NOT YET STUDIED" and must not be filled with guesses.

---

## 13. Feature Engineering

**Status: NOT YET STUDIED**

---

## 14. Statistical Detection

**Status: NOT YET STUDIED**

---

## 15. Threat Detection

**Status: NOT YET STUDIED**

### 15.1 DDoS

**Status: NOT YET STUDIED**

### 15.2 C2 Beaconing

**Status: NOT YET STUDIED**

### 15.3 DGA

**Status: NOT YET STUDIED**

### 15.4 DNS Tunneling

**Status: NOT YET STUDIED**

### 15.5 Reconnaissance

**Status: NOT YET STUDIED**

### 15.6 Data Exfiltration

**Status: NOT YET STUDIED**

### 15.7 Encrypted Anomaly

**Status: NOT YET STUDIED**

### 15.8 BENIGN

**Status: NOT YET STUDIED**

---

## 16. DNS Analysis

**Status: NOT YET STUDIED**

---

## 17. TLS / QUIC Metadata

**Status: NOT YET STUDIED**

---

## 18. JA3 / JA3S / JA4

**Status: NOT YET STUDIED**

---

## 19. Machine Learning

**Status: NOT YET STUDIED**

---

## 20. Random Forest

**Status: NOT YET STUDIED**

---

## 21. Training and Validation

**Status: NOT YET STUDIED**

---

## 22. Alert Fusion

**Status: NOT YET STUDIED**

---

## 23. Alert Schema

**Status: NOT YET STUDIED**

---

## 24. Deduplication

**Status: NOT YET STUDIED**

---

## 25. Bounded Storage

**Status: NOT YET STUDIED**

---

## 26. FastAPI

**Status: NOT YET STUDIED**

---

## 27. REST API

**Status: NOT YET STUDIED**

---

## 28. WebSocket

**Status: NOT YET STUDIED**

---

## 29. Frontend

**Status: NOT YET STUDIED**

---

## 30. Backend–Frontend Integration

**Status: NOT YET STUDIED**

---

## 31. Testing

**Status: NOT YET STUDIED**

---

## 32. Traffic Generation

**Status: NOT YET STUDIED**

---

## 33. Controlled Lab Validation

**Status: NOT YET STUDIED**

---

## 34. Performance Benchmarking

**Status: NOT YET STUDIED**

---

## 35. PS Compliance

**Status: NOT YET STUDIED**

---

## 36. Technology Stack

**Status: NOT YET STUDIED**

---

## 37. End-to-End Data Flow

**Status: NOT YET STUDIED**

---

## 38. Known Limitations

**Status: NOT YET STUDIED**

---

## 39. Current Implementation vs PS

**Status: NOT YET STUDIED**

---

## 40. Codebase Map

**Status: NOT YET STUDIED**

---

## 41. Judge Preparation

**Status: NOT YET STUDIED**

---

## 42. Glossary

**Status: NOT YET STUDIED**
