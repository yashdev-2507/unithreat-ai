# Phase 5.2 Lab Traffic Validation Summary

| Scenario | Input Type | Tool / Signature Model | Flows | Alerts | Detected? | Threat Classes | Mean Conf | Schema Valid |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `benign` | actual lab-generated | Live HTTP/TCP loopback client-server | 40 | 0 | ✅ YES | None | 0.00 | ✅ VALID |
| `ddos` | actual lab-generated | Live high-rate UDP socket flood | 40 | 40 | ✅ YES | DDOS | 0.96 | ✅ VALID |
| `port_scan` | actual lab-generated | Live TCP SYN port sweep (Nmap-style) | 40 | 1 | ✅ YES | RECONNAISSANCE | 0.75 | ✅ VALID |
| `c2_beacon` | synthetic/replayed | Modeled on Cobalt Strike / Sliver 30s jittered beaconing | 40 | 31 | ✅ YES | C2_BEACONING, ENCRYPTED_ANOMALY | 0.76 | ✅ VALID |
| `dns_tunnel` | synthetic/replayed | Modeled on dnscat2 / iodine (base32/hex TXT tunneling) | 40 | 1 | ✅ YES | DNS_TUNNELING | 0.98 | ✅ VALID |
| `dga` | synthetic/replayed | Modeled on Conficker / CryptoLocker algorithmic DGA | 40 | 15 | ✅ YES | DGA | 0.86 | ✅ VALID |
| `exfiltration` | actual lab-generated | Live high-volume TCP stream push (~2MB) | 5 | 2 | ✅ YES | C2_BEACONING, DATA_EXFILTRATION | 0.85 | ✅ VALID |
| `encrypted_anomaly` | synthetic/replayed | Modeled on obsolete SSL/TLS RC4 ciphers & direct-IP SNI | 40 | 45 | ✅ YES | DDOS, ENCRYPTED_ANOMALY | 0.74 | ✅ VALID |

- **Total Scenarios Evaluated**: 8
- **Total Flows Ingested**: 285
- **Total Standardized Alerts Generated**: 135
- **False Positives (Benign)**: 0
- **Detection Misses**: 0
- **Passive Boundary**: Verified strictly read-only.
