import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import os

def run_anomaly_pipeline(features_path="data/features_extracted.csv", output_path="data/threat_alerts.csv"):
    if not os.path.exists(features_path):
        print(f"[-] Error: {features_path} not found. Run C++ engine first.")
        return None

    print("[*] ML Engine: Loading aggregated network telemetry...")
    df = pd.read_csv(features_path)

    # Core mathematical features for anomaly clustering
    feature_cols = [
        'packet_count', 
        'total_bytes', 
        'avg_packet_size', 
        'unique_dest_ports', 
        'duration', 
        'packet_rate', 
        'byte_rate'
    ]

    X = df[feature_cols]

    # Contamination set to 0.08 (~8% anomalies expected in enterprise traffic)
    print("[*] ML Engine: Training Isolation Forest model...")
    model = IsolationForest(
        n_estimators=150,
        contamination=0.08,
        random_state=42
    )

    # Fit and predict: -1 = Anomaly, 1 = Normal
    df['prediction'] = model.fit_predict(X)
    # Decision function gives raw anomaly score (lower / negative = higher abnormality)
    df['anomaly_score'] = model.decision_function(X)

    # Filter out anomalous threat vectors
    anomalies = df[df['prediction'] == -1].copy()

    # Rule-based threat fingerprint classification
    def classify_threat_signature(row):
        if row['unique_dest_ports'] >= 10:
            return "Reconnaissance: Port Scan Sweep"
        elif row['packet_rate'] >= 300.0 or row['total_bytes'] >= 300000:
            return "Denial of Service: Volumetric Flood"
        else:
            return "Suspicious Host Deviation"

    anomalies['threat_signature'] = anomalies.apply(classify_threat_signature, axis=1)

    print(f"\n[+] ML Engine: Evaluation Complete!")
    print(f"    - Total Hosts Monitored: {len(df)}")
    print(f"    - Anomalous Hosts Flagged: {len(anomalies)}")

    # Display alerts cleanly on terminal
    print("\n--- [CRITICAL THREAT TELEMETRY ALERTS] ---")
    display_cols = ['src_ip', 'threat_signature', 'unique_dest_ports', 'packet_rate', 'anomaly_score']
    print(anomalies[display_cols].to_string(index=False))

    anomalies.to_csv(output_path, index=False)
    print(f"\n[✓] Threat alerts exported to {output_path}")
    return anomalies

if __name__ == "__main__":
    run_anomaly_pipeline()