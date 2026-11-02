import subprocess
import sys
import os
import time

def run_command(cmd, description):
    print(f"\n{'='*70}")
    print(f"[*] STEP: {description}")
    print(f"[*] Running: {cmd}")
    print(f"{'='*70}")
    start = time.time()
    
    result = subprocess.run(cmd, shell=True)
    if result.returncode != 0:
        print(f"[-] FAILED: {description}")
        sys.exit(1)
        
    print(f"[✓] COMPLETED in {time.time() - start:.3f}s")

def main():
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║                           SecuRAG                             ║
    ║      Real-Time Network Telemetry & Threat Defense Pipeline    ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)
    
    # 1. Telemetry Data Generation
    run_command("python data/generate_traffic.py", "Generating High-Throughput Network Traffic")

    # 2. Compile C++ Ingestion Engine if not compiled
    if not os.path.exists("cpp_engine/flow_engine.exe"):
        run_command("g++ cpp_engine/FlowEngine.cpp -o cpp_engine/flow_engine.exe", "Compiling C++ OOP Parsing Engine")

    # 3. Execute C++ Ingestion Engine
    run_command(r"cpp_engine\flow_engine.exe", "Executing C++ Feature Extraction Engine")

    # 4. ML Anomaly Detection Layer
    run_command("python ml_engine/anomaly_detector.py", "Running Isolation Forest Anomaly Detection")

    # 5. RAG Incident Responder Layer
    run_command("python rag_engine/incident_responder.py", "Generating MITRE ATT&CK Incident Playbooks")

    print("\n" + "#"*70)
    print("[🎉] PIPELINE EXECUTION SUCCESSFUL!")
    print("[*] Generated Reports: Check 'docs/reports/' directory")
    print("#"*70 + "\n")

if __name__ == "__main__":
    main()