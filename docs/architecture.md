# UniThreat AI — System Architecture

## 1. Purpose

UniThreat AI is a passive AI/ML cybersecurity threat-detection system designed
for a strictly one-directional monitoring environment.

The system observes network traffic without interacting with the observed
network. It converts passively collected traffic metadata into behavioral
features, applies statistical and machine-learning detection, fuses multiple
evidence signals, and produces explainable threat alerts.

The architecture is designed to satisfy SIH 26145 while remaining practical
for a working prototype and reproducible demonstration.

---

# 2. Architectural Principle

The core principle is:

> Passive observation → behavioral reasoning → evidence fusion → explainable
> threat intelligence.

The system must never require interaction with the observed source or
destination.

The monitoring environment has no return path into the monitored network.

The system is an intelligence and detection layer, not an inline prevention
or response system.

---

# 3. High-Level Architecture

```text
                    MONITORED / SIMULATED NETWORK
                              │
                              │
                    ONE-WAY TRAFFIC COPY
                              │
                              ▼
                  ┌──────────────────────┐
                  │   Passive Ingest     │
                  │                      │
                  │ PCAP Replay /        │
                  │ Mirrored Interface   │
                  └──────────┬───────────┘
                             │
                             ▼
                  ┌──────────────────────┐
                  │ Metadata Extraction  │
                  │                      │
                  │ Zeek / passive       │
                  │ protocol metadata    │
                  └──────────┬───────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
         Flow Metadata    DNS Metadata   TLS/QUIC
                                           Metadata
              └──────────────┼──────────────┘
                             ▼
                  ┌──────────────────────┐
                  │   Feature Engine     │
                  └──────────┬───────────┘
                             │
                             ▼
                  ┌──────────────────────┐
                  │ Behavioral Context   │
                  │                      │
                  │ Host / destination   │
                  │ temporal state       │
                  └──────────┬───────────┘
                             │
                    ┌────────┴────────┐
                    ▼                 ▼
             Statistical          ML Inference
               Signals
                    │                 │
                    └────────┬────────┘
                             ▼
                  ┌──────────────────────┐
                  │   Evidence Fusion   │
                  └──────────┬───────────┘
                             │
                             ▼
                  ┌──────────────────────┐
                  │ Threat Hypothesis    │
                  └──────────┬───────────┘
                             │
                    ┌────────┴────────┐
                    ▼                 ▼
               Confidence          Severity
                    └────────┬────────┘
                             ▼
                  ┌──────────────────────┐
                  │ Structured Alert     │
                  └──────────┬───────────┘
                             │
                  ┌──────────┴──────────┐
                  ▼                     ▼
             Persistence             API/Stream
                  │                     │
                  └──────────┬──────────┘
                             ▼
                  ┌──────────────────────┐
                  │   React Dashboard    │
                  └──────────────────────┘
```

There must be no data path from the UniThreat detection system back into the
monitored network.

---

# 4. Traffic Ingestion

UniThreat supports two input modes.

## 4.1 PCAP Replay

PCAP replay is the primary and guaranteed demonstration mechanism.

```text
PCAP
 ↓
Passive metadata extraction
 ↓
Streaming events
 ↓
Feature processing
 ↓
Detection
```

PCAP replay provides:

- reproducible demonstrations
- deterministic testing
- repeatable ML evaluation
- controlled attack scenarios
- easier debugging
- measurable throughput and latency

PCAP replay must still be processed incrementally.

Loading an entire PCAP into memory and producing only an end-of-run result
does not satisfy the streaming requirement.

---

## 4.2 Mirrored / Live Interface

The system may also consume traffic from a passive mirrored interface or
equivalent one-way traffic source.

```text
Mirrored Interface
        ↓
Passive Capture
        ↓
Metadata Extraction
        ↓
Streaming Detection
```

The interface must be treated as read-only.

The application must not transmit packets through the monitoring interface.

The live interface is an optional demonstration capability if implementation
time permits. PCAP replay remains the guaranteed reproducible path.

---

# 5. Metadata Extraction

The prototype will use Zeek where practical for passive protocol and flow
metadata extraction.

The system may consume structured Zeek logs/events rather than implementing
all packet and protocol parsing from scratch.

Relevant metadata may include:

### Flow metadata

- source IP
- destination IP
- source port
- destination port
- protocol
- timestamp
- duration
- packet counts
- byte counts
- connection state where passively observable

### DNS metadata

- query name
- query type
- response information
- query/response timing
- query length
- response size

### TLS/QUIC metadata

- TLS version
- cipher metadata where observable
- JA3 / JA3S / JA4 where available
- packet sizes
- packet timing
- inter-arrival times
- connection duration
- connection frequency

Payload contents must not be required.

---

# 6. Feature Engineering

Raw metadata is transformed into features suitable for statistical analysis
and ML inference.

Features are divided into several groups.

## 6.1 Flow Features

Examples:

- packets/sec
- bytes/sec
- flows/sec
- flow duration
- packet count
- byte count
- protocol
- source/destination relationship

## 6.2 Temporal Features

Examples:

- inter-arrival time
- mean inter-arrival time
- variance
- standard deviation
- coefficient of variation
- periodicity
- burstiness
- activity persistence

## 6.3 Behavioral Features

Examples:

- unique destinations
- unique ports
- fan-out
- destination concentration
- connection frequency
- source diversity
- destination diversity
- baseline deviation

## 6.4 DNS Features

Examples:

- query length
- entropy
- digit ratio
- character diversity
- n-gram characteristics
- unique subdomains
- record-type distribution
- query frequency

## 6.5 Encrypted-Session Features

Examples:

- TLS/QUIC metadata
- fingerprint information where available
- packet-size sequences
- timing patterns
- connection frequency
- destination behavior

The feature set is expected to evolve during experimentation.

Features must be derived only from information passively observable by the
monitoring system.

---

# 7. Behavioral Context Layer

Individual flows are often insufficient to make a reliable threat decision.

UniThreat therefore maintains bounded behavioral context across time.

The context may be maintained for:

- hosts
- source IPs
- destination IPs
- destination ports
- DNS activity
- encrypted sessions
- repeated connections
- traffic volume
- temporal patterns

Example:

```text
Flow 1 ─┐
Flow 2 ─┤
Flow 3 ─┼──→ Host Behavioral State
Flow 4 ─┤
Flow 5 ─┘
             │
             ▼
       Temporal Pattern
             │
             ▼
       Detection Signal
```

The initial prototype should prefer bounded in-memory state where practical.

A dedicated state infrastructure such as Redis should not be introduced unless
performance testing demonstrates a real need.

State must have explicit bounds such as time windows, maximum tracked
entities, or expiry policies to prevent uncontrolled memory growth.

---

# 8. Detection Layer

Detection combines multiple forms of evidence.

The preferred architecture is:

```text
Features
   ↓
Behavioral Context
   ↓
Temporal Context
   ↓
Statistical Signals ─────┐
                         ├──→ Evidence Fusion
ML Prediction ───────────┘
                              ↓
                       Threat Hypothesis
```

The detector should not rely on one feature or one hard-coded threshold as
proof of malicious activity.

Rules and statistical detectors may be used to generate interpretable
evidence signals.

ML models provide learned classification or anomaly signals.

The evidence-fusion layer combines these signals into a final threat
hypothesis.

Detection components must distinguish between:

- observed anomaly
- suspicious behavior
- threat hypothesis
- confidence in the hypothesis

The system should avoid claiming definitive compromise when the available
evidence cannot support such a conclusion.

---

# 9. Machine Learning Layer

The ML intelligence layer is implemented in `src/unithreat/ml/` as a tabular supervised classifier complementing the statistical and behavioral detection engines.

For comprehensive architectural and methodology details, see [ML Architecture Documentation](ml-architecture.md).

### Key Architecture Components:
- **Baseline Model**: `RandomForestClassifier` (scikit-learn) with `SimpleImputer(strategy="median")`.
- **Feature Vector**: 37 canonical features extracted from `FeatureRecord.features` adhering strictly to `contracts/feature-schema.json`.
- **Taxonomy (8 Classes)**: `BENIGN`, `DDOS`, `C2_BEACONING`, `DGA`, `DNS_TUNNELING`, `RECONNAISSANCE`, `DATA_EXFILTRATION`, `ENCRYPTED_ANOMALY`.
- **Leakage Prevention**: Group/run-aware splitting (`split_dataset_by_group`) ensures entire multi-flow simulation runs are allocated exclusively to train, validation, or test sets.
- **Contract Strictness**: Single-flow predictions output directly to `contracts/ml-prediction-schema.json` with `calibrated: false` explicitly documented as an uncalibrated confidence index.
- **Passive Constraints**: Zero active networking, packet transmission, or payload decryption.

The ML pipeline is structured as:

```text
Synthetic / Ingested Flow
  ↓
FeatureExtractor (37 features)
  ↓
MLInferenceEngine (pre-loaded pipeline)
  ↓
MLPrediction (contracts/ml-prediction-schema.json)
```

Model artifacts are persisted to disk as `model.joblib` and `metadata.json`.


---

# 10. Threat Detection Coverage

The architecture must support all six SIH threat categories.

## DDoS

Uses traffic-rate, protocol, source-diversity, destination-concentration,
and temporal behavior.

## C2 Beaconing

Uses repeated destinations, connection frequency, inter-arrival timing,
periodicity, packet-size behavior, and persistence.

## DGA

Uses domain length, entropy, character distribution, n-grams, digit ratio,
and domain-structure characteristics.

## DNS Tunnelling

Uses query length, entropy, query frequency, unique subdomains,
record-type behavior, response characteristics, and temporal persistence.

## Encrypted Sessions

Uses TLS/QUIC metadata, fingerprints where available, packet sizes, timing,
connection frequency, and destination behavior without payload decryption.

## Reconnaissance

Uses destination/port diversity, fan-out, connection attempts, host
diversity, port diversity, and temporal scanning behavior.

## Data Exfiltration

Uses outbound volume, inbound/outbound ratios, sustained transfer behavior,
destination behavior, and deviation from normal host behavior.

Threat-specific detection methodology will be documented separately in:

`docs/detection-methodology.md`

---

# 11. Evidence Fusion

Evidence fusion is a key architectural component and the primary
differentiation direction.

Instead of:

```text
Flow → Classifier → Threat
```

the system should prefer:

```text
Flow
 ↓
Features
 ↓
Behavioral Context
 ↓
Temporal Context
 ↓
Multiple Evidence Signals
 ↓
ML Prediction
 ↓
Evidence Fusion
 ↓
Threat Hypothesis
 ↓
Confidence
 ↓
Explanation
 ↓
Alert
```

Example:

```text
DNS entropy ──────────────┐
Query length ─────────────┤
Query frequency ──────────┤
Subdomain behavior ───────┤
Record types ─────────────┤
Temporal persistence ─────┤
ML prediction ────────────┤
                           ▼
                    Evidence Fusion
                           │
                           ▼
                  DNS Tunnel Hypothesis
```

A single anomalous feature must not automatically be treated as proof of an
attack.

Evidence fusion methodology, weighting, thresholds, and calibration will be
defined in:

`docs/detection-methodology.md`

The exact fusion algorithm should be selected after experimentation rather
than assumed in advance.

---

# 12. Confidence and Severity

The system must distinguish:

### Confidence

How strongly the available evidence supports the threat hypothesis.

### Severity

The operational importance of the detected behavior.

They are separate concepts.

The system must not fabricate either value.

Confidence should be derived from actual model/statistical evidence and, where
appropriate, calibrated.

Severity should be determined using documented threat-specific criteria.

---

# 13. Alert Generation

The detector produces a standardized structured alert.

Minimum fields:

- timestamp
- flow identifier
- threat class
- confidence score
- supporting evidence

Preferred alert structure:

```json
{
  "alert_id": "ALT-000001",
  "timestamp": "2026-01-01T12:00:00Z",
  "flow_id": "flow-001",
  "source_ip": "10.0.0.10",
  "destination_ip": "10.0.0.20",
  "source_port": 54321,
  "destination_port": 443,
  "protocol": "TCP",
  "threat_class": "C2_BEACONING",
  "severity": "HIGH",
  "confidence": 0.93,
  "evidence": {},
  "model_version": "c2-v1"
}
```

The actual evidence object must contain computed evidence from the detection
pipeline.

The alert schema must be treated as a shared contract between:

- detection
- persistence
- backend
- dashboard
- testing
- demonstration

Breaking changes to the alert contract must be deliberate and coordinated.

---

# 13.1 Alert Fusion and Deduplication Architecture

Alert generation combines deterministic statistical/behavioral detectors with ML model inference via the `AlertFusionEngine` (`src/unithreat/alerts/fusion.py`) and suppresses redundant alarms via the `AlertDeduplicator` (`src/unithreat/alerts/dedup.py`).

### Alert Fusion Engine (Explicit Deterministic Cases)

Alert fusion reconciles statistical detector outputs (`DetectionResult`) and tabular ML predictions (`MLPrediction`). Rather than applying a blanket weighted-average formula across all predictions, the engine evaluates four mutually exclusive, deterministic cases:

1. **Case 1: Statistical Detection + ML Agree**
   - Both the statistical detector and ML classifier identify the same threat class.
   - The statistical threat class is preserved.
   - Confidence receives a modest supporting boost: `confidence = min(1.0, stat_conf + (1.0 - stat_conf) * 0.25 * ml_score)`.
   - An `EvidenceSignal` is appended with `direction="supporting"`, `reliability=0.85`, recording ML agreement.

2. **Case 2: Statistical Detection + ML Disagree**
   - The statistical detector identifies a threat, but ML classifies the flow as `BENIGN` or a different threat class.
   - The statistical threat class is preserved because statistical evidence is directly observable and interpretable.
   - Confidence is dampened: `confidence = stat_conf * 0.85`.
   - An `EvidenceSignal` is appended with `direction="contradicting"`, `reliability=0.50`, recording ML disagreement.

3. **Case 3: Statistical Detection Only**
   - No ML prediction is available (e.g. model not loaded or optional feature missing).
   - Statistical threat class, confidence, and severity are preserved completely unchanged.
   - No artificial ML confidence or evidence is introduced.

4. **Case 4: ML Detection Only (ML Hypothesis)**
   - Statistical detectors found no anomaly, but the ML classifier predicted a malicious class with score $\ge 0.75$.
   - Because the model is trained on synthetic data and produces an uncalibrated voting ratio (`calibrated: false`), this alert is explicitly treated as an *ML hypothesis*.
   - Confidence is conservatively computed: `confidence = min(0.75, ml_score * 0.80)`.
   - Severity is capped at `HIGH` (never `CRITICAL`).
   - An `EvidenceSignal` is attached with `signal_name="ml_hypothesis"`, `reliability=0.65`, and `direction="supporting"`.

### Bounded Alert Deduplication

To prevent alert fatigue and volumetric memory exhaustion:
- **Deduplication Key**: `(source_ip, destination_ip, threat_class)`.
- **Bounded LRU Cache**: Implemented with an `OrderedDict` capped at 10,000 keys.
- **Suppression Window**: Configurable duration (default 60 seconds). Duplicate alerts within this window are safely suppressed. Expired entries are pruned lazily.

### Bounded In-Memory Storage

For prototype operation without heavy external databases (Redis/PostgreSQL):
- `BoundedAlertStore`: Thread-safe ring buffer (`collections.deque(maxlen=1000)`). Stores alerts newest-first. Supports filtering by `threat_class`, `severity`, and `limit`.
- `BoundedFlowStore`: Thread-safe ring buffer (`collections.deque(maxlen=2000)`) indexed by `flow_id` for flow lookups.

### Measured Pipeline Performance Characteristics

Measured on the development/test environment (AMD Ryzen 5 PRO 4650U, 12 cores, Linux 7.1.5 x86_64, Python 3.14.6) using the end-to-end streaming detection pipeline with full feature extraction (37 features), 6 statistical detectors, Random Forest ML inference, alert fusion, deduplication, and bounded storage:

- **Throughput**: ~96 to 132 flows/sec under sustained mixed-threat traffic replay (evaluated up to 10,000 continuous flows).
- **Latency**: Mean processing latency of 7.6 to 10.4 ms per flow (P50: ~7.3 ms, P95: ~11.4 to 12.6 ms, P99: ~11.8 to 13.1 ms).
- **Bounded In-Memory Guarantees**: Strict ring-buffer bounds enforced across all components (`BoundedAlertStore` maxlen=1,000; `BoundedFlowStore` maxlen=2,000; `AlertDeduplicator` max_tracked_keys=10,000; window entity trackers max_tracked_entities=10,000). Peak resident memory remains strictly bounded (~329 MB peak RSS across 10,000 continuous flows with zero unbounded memory growth).

---

# 14. Backend and Streaming Architecture

## Backend

Preferred technology:
- FastAPI (`src/unithreat/api/app.py`, `src/unithreat/api/routes.py`)
- Uvicorn ASGI server

### REST API Endpoints:
- `GET /health` — Service health status, pipeline components, and model metadata.
- `GET /alerts` — List recent alerts with query parameters (`limit`, `threat_class`, `severity`), newest-first.
- `GET /alerts/{flow_id}` — Retrieve the specific alert associated with a flow identifier.
- `GET /flows/{flow_id}` — Retrieve raw flow metadata for forensic investigation.
- `GET /stats` — Real-time operational statistics (total flows, total alerts, alerts by threat class, alerts by severity).
- `POST /ingest/flow` — Ingest a single raw flow JSON record into the live processing pipeline. Returns processing status and generated alerts.

### Passive Boundary Guarantee for Ingest API:
`POST /ingest/flow` is strictly intended for local testing, dataset replay, and application ingestion.
- The endpoint performs **zero active network communication**.
- It does **not send packets, open sockets to external hosts, complete TCP handshakes, or establish return paths** to monitored network sources.
- Monitored traffic sources remain strictly isolated behind the passive capture boundary.

## Realtime Streaming (WebSocket)

Technology:
- WebSocket endpoint at `WS /ws/alerts` managed by `AlertStreamManager` (`src/unithreat/api/stream.py`).

### Bounded Streaming Queues:
- Each connected client is allocated a dedicated, bounded `asyncio.Queue(maxsize=100)`.
- If a client queue fills up due to slow consumption, a deterministic **drop-oldest** policy is enforced to prevent unbounded memory growth.
- Client disconnections are detected and cleaned up gracefully.

---

## Database

Preferred prototype database platform:

- Supabase
- PostgreSQL underneath Supabase

Supabase is used primarily for persistence and convenient managed database
infrastructure.

The detection engine should not depend on a successful database write before
producing an alert.

Conceptually:

```text
Detection
    │
    ├────────→ Alert/API stream
    │
    └────────→ Persistence
```

Database failure must not cause the detector to interact with the monitored
network.

Additional Supabase capabilities such as authentication, storage, or realtime
features should only be introduced if they provide a clear benefit to the
prototype.

---

# 15. Dashboard

Preferred technologies:

- React
- Vite

The dashboard is an intelligence visualization layer.

Minimum views:

### Overview

- total alerts
- alerts by severity
- alerts by threat class
- recent alerts
- detection activity

### Live Alerts

- timestamp
- threat class
- severity
- confidence
- source
- destination
- evidence summary

### Alert Details

- complete alert
- supporting evidence
- detector/model
- confidence
- severity
- relevant context/timeline

### Threat Timeline

- detection events over time

The dashboard must not implement traffic blocking, active response, or
network control.

---

# 16. Streaming Architecture

The system must process traffic incrementally.

Preferred logical flow:

```text
Traffic / PCAP
      ↓
Incremental Event
      ↓
Feature Update
      ↓
Behavioral State Update
      ↓
Detection
      ↓
Alert
```

The system should not require an entire PCAP or traffic session to finish
before producing detections when the relevant evidence is already available.

Detection latency must be measured.

PCAP replay should preserve event ordering and timing information sufficiently
to support meaningful streaming evaluation.

---

# 17. Performance Measurement

The prototype must report actual measured performance.

At minimum measure:

- throughput in flows/sec or Mbps
- detection latency
- inference latency
- CPU usage
- memory usage

Performance numbers must always identify:

- hardware
- traffic scenario
- traffic rate
- test duration
- relevant configuration

No performance number may be invented.

The final documented throughput target must be based on an actual tested
configuration.

---

# 18. Technology Stack

The initial preferred stack is:

### Network telemetry

- Zeek
- PCAP tools / passive capture utilities

### Core processing

- Python

### Machine learning

- scikit-learn

### Backend

- FastAPI

### Database

- Supabase / PostgreSQL

### Frontend

- React
- Vite

### Deployment

- Docker
- Docker Compose

### Version control

- Git
- GitHub

Additional technologies must have a clear technical justification.

Avoid introducing Kafka, Kubernetes, Spark, Redis, or other infrastructure
unless measured requirements demonstrate that they are necessary.

Technology choices may be revised if implementation/testing shows a simpler or
more reliable option.

---

# 19. Repository Responsibilities

The planned source structure is:

```text
src/
├── ingest/
├── metadata/
├── features/
├── behavioral/
├── detection/
├── ml/
├── alerts/
└── api/
```

Responsibilities:

### `src/ingest/`

Traffic input and PCAP replay.

### `src/metadata/`

Normalization of passive metadata from Zeek or equivalent sources.

### `src/features/`

Feature calculation and feature-vector generation.

### `src/behavioral/`

Bounded temporal and host/destination behavioral state.

### `src/detection/`

Statistical signals, ML outputs, and evidence fusion.

### `src/ml/`

Training, validation, serialization, and inference components.

### `src/alerts/`

Alert construction, validation, and delivery.

### `src/api/`

FastAPI endpoints and application interfaces.

The exact repository structure may be adjusted during implementation if a
simpler structure provides the same separation of responsibility.

---

# 20. Data Flow Contracts

Components must communicate through explicit, stable data structures.

Important contracts include:

```text
Raw metadata
     ↓
Normalized event
     ↓
Feature record
     ↓
Behavioral state
     ↓
Detection result
     ↓
Alert
```

Important contracts include:

- normalized metadata schema
- feature schema
- model input schema
- detection result schema
- alert schema

Changes to shared fields must be deliberate.

The alert schema is a particularly important contract because it is consumed
by persistence, API, dashboard, testing, and demonstration components.

---

# 21. Security Boundary

UniThreat is an observation system, not an inline security control.

The architecture must not contain:

```text
Detector → Target
Detector → Source
Detector → DNS server
Detector → External probe
Detector → Mitigation system
```

The only intended direction is:

```text
Observed Network
      ↓
UniThreat
      ↓
Detection Intelligence
      ↓
Dashboard / Evidence
```

No payload decryption is required.

No active scanning is required.

No mitigation action is performed.

---

# 22. Prototype Development Strategy

The first implementation milestone is a complete vertical slice.

```text
Controlled DDoS traffic
        ↓
PCAP
        ↓
Passive metadata extraction
        ↓
Flow records
        ↓
Feature extraction
        ↓
Labeled dataset
        ↓
ML training
        ↓
Validation
        ↓
Saved model
        ↓
Replay unseen traffic
        ↓
Inference
        ↓
Confidence
        ↓
Structured alert
```

This vertical slice must work before aggressively expanding the system.

After the first vertical slice is functional, the remaining threat categories,
behavioral context, evidence fusion, and dashboard capabilities can be
expanded incrementally.

The implementation should prioritize demonstrable functionality over
architectural completeness.

---

# 23. Design Priorities

When engineering decisions conflict, prioritize:

1. SIH requirement compliance
2. Strict passive/read-only architecture
3. Correctness
4. Demonstrable detection
5. Explainability
6. Measured performance
7. Maintainability
8. Development speed
9. Additional sophistication

Do not sacrifice correctness merely to make the architecture appear more
advanced.

---

# 24. Architectural Success Criteria

The architecture is successful when the implemented system can demonstrate:

- passive traffic observation
- no return path
- no active probing
- metadata-only encrypted-session analysis
- incremental processing
- feature extraction
- behavioral context
- statistical detection signals
- genuine ML inference
- evidence fusion
- all six threat categories
- confidence
- severity
- supporting evidence
- structured alerts
- dashboard visualization
- measured throughput
- measured detection latency
- reproducible replay

The implementation is considered successful only when these capabilities are
demonstrated through actual working components rather than placeholders or
mocked results.
