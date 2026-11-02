import pandas as pd
import json
import os
from datetime import datetime

class SecuRAGIncidentEngine:
    def __init__(self, threat_db_path="data/mitre_threat_db.json"):
        if not os.path.exists(threat_db_path):
            raise FileNotFoundError(f"[-] Threat database not found at {threat_db_path}")
        
        with open(threat_db_path, "r") as f:
            self.threat_db = json.load(f)
        print(f"[+] SecuRAG Engine: Loaded {len(self.threat_db)} MITRE ATT&CK intelligence profiles.")

    def retrieve_threat_intel(self, threat_signature):
        """Semantic/Heuristic matching over MITRE ATT&CK threat database."""
        sig_lower = threat_signature.lower()
        if "port scan" in sig_lower or "reconnaissance" in sig_lower:
            return next(item for item in self.threat_db if item["technique_id"] == "T1046")
        elif "flood" in sig_lower or "denial of service" in sig_lower:
            return next(item for item in self.threat_db if item["technique_id"] == "T1498")
        else:
            return next(item for item in self.threat_db if item["technique_id"] == "T1071")

    def generate_incident_playbook(self, alert_row):
        """Generates an executive SOC report and automated firewall remediation rules."""
        src_ip = alert_row['src_ip']
        threat_sig = alert_row['threat_signature']
        score = alert_row['anomaly_score']
        rate = alert_row['packet_rate']
        ports = alert_row['unique_dest_ports']

        intel = self.retrieve_threat_intel(threat_sig)

        # Automated iptables firewall command generation
        firewall_cmd = f"sudo iptables -A INPUT -s {src_ip} -j DROP"

        playbook = f"""
================================================================================
[AUTOMATED INCIDENT PLAYBOOK - SECU-RAG SOC TELEMETRY]
Timestamp: {datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")}
Threat Target: Edge Ingress Gateway
================================================================================

[1. TELEMETRY DETAILS]
  - Malicious Source IP     : {src_ip}
  - Flagged Threat Signature: {threat_sig}
  - Anomaly Score           : {score:.4f} (Isolation Forest Metric)
  - Packet Arrival Rate     : {rate:.2f} pkts/sec
  - Unique Ports Scanned    : {ports}

[2. RETRIEVED THREAT INTEL (MITRE ATT&CK)]
  - Technique ID            : {intel['technique_id']} ({intel['technique_name']})
  - Tactic Category         : {intel['tactics']}
  - Vector Description      : {intel['description']}
  - Industry Best-Practice  : {intel['mitigation']}

[3. AUTONOMOUS REMEDIATION ACTION]
  - Enforced Policy         : {intel['default_action']}
  - Executable Shell Command:
      >>> {firewall_cmd}
  - Action Status           : READY_FOR_SOC_DEPLOYMENT
================================================================================
"""
        return playbook

def execute_rag_pipeline(alerts_path="data/threat_alerts.csv", output_report_dir="docs/reports"):
    if not os.path.exists(alerts_path):
        print(f"[-] Alerts file not found at {alerts_path}. Run ML detector first.")
        return

    os.makedirs(output_report_dir, exist_ok=True)
    engine = SecuRAGIncidentEngine()
    df_alerts = pd.read_csv(alerts_path)

    print(f"[*] Processing {len(df_alerts)} flagged anomalies through RAG Playbook Generator...\n")

    for idx, row in df_alerts.iterrows():
        playbook = engine.generate_incident_playbook(row)
        print(playbook)
        
        # Save individual incident reports
        report_file = os.path.join(output_report_dir, f"incident_{row['src_ip'].replace('.', '_')}.txt")
        with open(report_file, "w") as rf:
            rf.write(playbook)

    print(f"[✓] All automated incident playbooks generated in {output_report_dir}/")

if __name__ == "__main__":
    execute_rag_pipeline()