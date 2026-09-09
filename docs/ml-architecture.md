# UniThreat AI — Machine Learning Intelligence Layer

## 1. Overview & Objectives

The UniThreat AI Machine Learning (ML) intelligence layer is designed as a passive, tabular threat classifier complementing the existing statistical and behavioral detection engines.

It fulfills the requirements of SIH Problem Statement 26145:
- Strictly passive monitoring: no socket creation, active probing, firewall rules, or packet manipulation.
- Metadata-only inspection: operates on normalized flow features; zero payload decryption or private-key usage.
- Tabular supervised ML: uses scikit-learn without heavy deep-learning dependencies.
- Strict contract compliance: predictions conform to `contracts/ml-prediction-schema.json`.

---

## 2. Model Selection & Rationale

**Selected Model**: `RandomForestClassifier` (scikit-learn)

### Why RandomForestClassifier?
1. **Robust to Tabular Feature Distributions**: Network flow and window statistics contain heterogeneous distributions (heavy-tailed byte counts, discrete flag indicators, continuous rates, and bounded ratios). Tree ensembles handle non-linear decision boundaries and varying feature scales natively without requiring feature normalization or standard scaling.
2. **Missing Value Resilience**: Combined with `SimpleImputer(strategy="median")`, random forests gracefully handle optional metadata fields (such as DNS metrics absent in non-DNS traffic, or TLS metrics absent in plaintext traffic).
3. **Sub-Millisecond Single-Flow Inference**: With `n_jobs=1` configured for single-flow inference, individual predictions execute in approximately 1–3 ms per flow, comfortably meeting real-time streaming demands.
4. **Lightweight Explainability**: Feature importances (mean decrease in impurity / Gini importance) are natively calculated during training, providing transparent insights into what engineered features drive decisions across classes.
5. **Class Imbalance Handling**: Built-in support for `class_weight="balanced"` ensures minority threat classes receive proportional loss weighting during training.

---

## 3. Threat Taxonomy Coverage

The model classifies all 8 threat classes represented in UniThreat AI:

| Threat Class | Behavioral Profile | Primary Engineered Features |
|---|---|---|
| `BENIGN` | Normal web browsing, background DNS, API synchronization | Moderate byte/packet counts, standard ports, normal vowel ratios |
| `DDOS` | High-volume volumetric flood targeting infrastructure | `packets_per_sec`, `bytes_per_sec`, `dst_fan_in`, `duration < 0.05` |
| `C2_BEACONING` | Highly regular periodic outbound beaconing to remote C2 | `periodicity_score`, `mean_inter_arrival_time`, `inter_arrival_std` |
| `DGA` | Algorithmic pseudo-random domain queries | `dns_entropy`, `dns_vowel_ratio`, `dns_max_consonant_run`, `dns_ngram_score` |
| `DNS_TUNNELING` | Large-volume or high-entropy DNS data encapsulation | `dns_query_length`, `byte_count`, `has_dns`, `dns_entropy` |
| `RECONNAISSANCE` | Port scanning & horizontal host sweeps | `unique_dst_ports`, `unique_dst_hosts`, `src_fan_out`, `is_syn` |
| `DATA_EXFILTRATION` | Large-volume sustained outbound data transfer | `outbound_inbound_byte_ratio`, `byte_count`, `bytes_per_sec`, `duration` |
| `ENCRYPTED_ANOMALY` | Obsolete TLS/QUIC, direct IP in SNI, weak ciphers | `is_ip_sni`, `has_tls`, `has_quic`, `bytes_per_packet` |

---

## 4. Feature Selection & Vectorization

The feature space comprises **37 security-relevant engineered features** defined in `unithreat.ml.features.FEATURE_NAMES`, extracted directly from `contracts/feature-schema.json`:

1. **Volume & Rate Metrics (6)**: `duration`, `packet_count`, `byte_count`, `packets_per_sec`, `bytes_per_sec`, `bytes_per_packet`
2. **TCP & UDP Flags (8)**: `is_syn`, `is_ack`, `is_psh`, `is_fin`, `is_rst`, `is_urg`, `is_tcp`, `is_udp`
3. **DNS Lexical & Metadata (8)**: `has_dns`, `dns_query_length`, `dns_entropy`, `dns_vowel_ratio`, `dns_consonant_ratio`, `dns_max_consonant_run`, `dns_ngram_score`, `dns_digit_ratio`
4. **TLS & QUIC Metadata (3)**: `has_tls`, `has_quic`, `is_ip_sni`
5. **Behavioral Sliding Window Aggregations (12)**: `src_fan_out`, `unique_dst_hosts`, `unique_dst_ports`, `dst_fan_in`, `flow_rate`, `inter_arrival_time`, `mean_inter_arrival_time`, `inter_arrival_std`, `periodicity_score`, `protocol_tcp_ratio`, `protocol_udp_ratio`, `outbound_inbound_byte_ratio`

Missing optional values (e.g., DNS metrics for TLS flows) are represented as `NaN` and imputed with the median training value via `SimpleImputer`.

---

## 5. Dataset Generation & Data Leakage Prevention

### Multi-Run Simulation
To prevent temporal correlation and session data leakage:
- Rather than splitting a single continuous scenario session with random shuffle, `generate_labelled_dataset()` executes multiple independent simulation runs (e.g. 5 runs per class), each with distinct seeds and fresh streaming window trackers.
- Each generated flow is tagged with a unique `run_id` (e.g. `c2_beacon_run_0`).

### Group/Run-Aware Splitting
`split_dataset_by_group()` partitions flows strictly by `run_id`:
- 70% of runs allocated to Train
- 15% of runs allocated to Validation
- 15% of runs allocated to Test
- **Guarantee**: Entire simulation runs of a threat scenario are held out exclusively in train, validation, or test sets. No flows from a test run ever appear in the training partition.

### Limitations of Synthetic Data
While the synthetic generator provides diverse parameters (varying packet sizes, varied TLDs, varied cipher suites, and randomized timing jitter), synthetic data cannot fully model:
- Zero-day exploit patterns absent from training scenarios.
- Complex real-world multi-tenant campus networks with asymmetric routing.
- Adversarial evasions specifically targeted at random forest decision thresholds.

---

## 6. Pipeline Architecture & Serialization

```text
Feature Record (contracts/feature-schema.json)
               │
               ▼
     extract_feature_vector (37 floats)
               │
               ▼
┌─────────────────────────────────────────┐
│        Scikit-Learn Pipeline            │
│  1. SimpleImputer(strategy="median")    │
│  2. RandomForestClassifier(...)         │
└──────────────────┬──────────────────────┘
                   │
                   ▼
       Class Probabilities Vector
                   │
                   ▼
┌─────────────────────────────────────────┐
│  MLPrediction (contracts/ml-prediction) │
│  - flow_id: str                         │
│  - threat_class: str                    │
│  - score: float [0, 1]                  │
│  - model_version: "rf-baseline-v1"      │
│  - calibrated: false                    │
└─────────────────────────────────────────┘
```

The pipeline and metadata are persisted to disk using `joblib`:
- `model.joblib`: Serialized scikit-learn pipeline.
- `metadata.json`: Model version, training timestamp, hyperparameters, evaluation metrics, confusion matrix, and feature importances.

---

## 7. Model Score vs. Calibrated Probability

> [!IMPORTANT]
> The `score` field returned by `MLPrediction` reflects the random forest's ensemble tree voting proportion:
> \[\text{score} = \max_{c \in C} \frac{1}{N_{\text{trees}}} \sum_{t=1}^{N_{\text{trees}}} \mathbb{I}(h_t(x) = c)\]
> This is an **uncalibrated model score / confidence index**, not an empirical probability of compromise in production networks.
> `calibrated` is explicitly set to `False` in compliance with `contracts/ml-prediction-schema.json`.

---

## 8. Usage & CLI Demonstration

### Training a Model
```python
from unithreat.ml.train import train_model

result = train_model(
    model_dir="artifacts/models/rf-baseline-v1",
    model_version="rf-baseline-v1",
    seed=42,
    n_estimators=100,
    max_depth=15,
)
print("Trained Accuracy:", result["metrics"]["accuracy"])
```

### Running Single-Flow Inference
```python
from unithreat.ml.inference import MLInferenceEngine
from unithreat.features.models import FeatureRecord

engine = MLInferenceEngine(model_dir="artifacts/models/rf-baseline-v1")
record = FeatureRecord(
    flow_id="test-flow-001",
    timestamp="2026-09-06T12:00:00.000000Z",
    features={"packets_per_sec": 5000.0, "is_syn": True, "is_tcp": True},
)

prediction = engine.predict(record)
print(prediction.to_contract_dict())
# {
#   "flow_id": "test-flow-001",
#   "threat_class": "DDOS",
#   "score": 0.96,
#   "model_version": "rf-baseline-v1",
#   "calibrated": False
# }
```
