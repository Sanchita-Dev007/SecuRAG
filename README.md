# SecuRAG: Real-Time Network Packet Anomaly Detection & AI-Powered Incident Response Engine

SecuRAG is a hybrid, low-latency cybersecurity telemetry pipeline designed to detect anomalous network traffic and autonomously generate MITRE ATT&CK-aligned incident response playbooks for Security Operations Center (SOC) engineers.

---

## 🏗️ System Architecture

```text
               [ High-Throughput Network Packet Stream ]
                                   │
                                   ▼
        ┌─────────────────────────────────────────────────────┐
        │  Layer 1: C++ High-Performance Ingestion Engine     │
        │  - OOP Abstraction (NetworkPacket, TelemetryTable)  │
        │  - Low latency, zero-copy per-host state tracking   │
        └──────────────────────────┬──────────────────────────┘
                                   │ Aggregated Features (CSV)
                                   ▼
        ┌─────────────────────────────────────────────────────┐
        │  Layer 2: Unsupervised ML Anomaly Detection         │
        │  - Isolation Forest (n_estimators=150)              │
        │  - Behavioral fingerprinting (Port Scans, DoS)      │
        └──────────────────────────┬──────────────────────────┘
                                   │ Critical Threat Telemetry
                                   ▼
        ┌─────────────────────────────────────────────────────┐
        │  Layer 3: MITRE ATT&CK Threat Retrieval Engine      │
        │  - Knowledge base semantic retrieval (T1046, T1498) │
        │  - Industry-standard threat vector mapping          │
        └──────────────────────────┬──────────────────────────┘
                                   │ Retrieved Intelligence
                                   ▼
        ┌─────────────────────────────────────────────────────┐
        │  Layer 4: Autonomous Incident Playbook Responder    │
        │  - Instant executive SOC incident reports           │
        │  - Automated Linux firewall remediation (`iptables`)│
        └─────────────────────────────────────────────────────┘