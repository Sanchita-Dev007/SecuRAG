import csv
import random

def generate_network_stream(filename="data/raw_stream.csv", total_events=5000):
    protocols = ["TCP", "UDP"]
    common_dest_ips = ["10.0.0.1", "10.0.0.2", "10.0.0.5"]
    standard_ports = [80, 443, 53, 22, 8080]
    
    records = []
    base_time = 1700000000.0

    print("[*] Generating synthetic normal and anomalous network traffic...")

    # 1. Normal enterprise traffic (85%)
    for i in range(int(total_events * 0.85)):
        src_ip = f"192.168.1.{random.randint(10, 50)}"
        dest_ip = random.choice(common_dest_ips)
        src_port = random.randint(30000, 65000)
        dest_port = random.choice(standard_ports)
        proto = "TCP" if dest_port != 53 else "UDP"
        packet_size = random.randint(128, 1500)
        timestamp = base_time + (i * random.uniform(0.01, 0.05))

        records.append([src_ip, dest_ip, src_port, dest_port, proto, packet_size, round(timestamp, 4)])

    # 2. Attack A: Port Reconnaissance Scan (from IP 192.168.1.99)
    scan_start = base_time + 100.0
    for port in range(20, 120):
        records.append(["192.168.1.99", "10.0.0.1", random.randint(40000, 50000), port, "TCP", 64, round(scan_start + (port * 0.005), 4)])

    # 3. Attack B: Volumetric Packet Flood (from IP 192.168.1.200)
    flood_start = base_time + 150.0
    for k in range(500):
        records.append(["192.168.1.200", "10.0.0.2", random.randint(50000, 60000), 80, "TCP", 40, round(flood_start + (k * 0.001), 4)])

    # Chronological sort
    records.sort(key=lambda x: x[6])

    # Write to CSV
    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["src_ip", "dest_ip", "src_port", "dest_port", "protocol", "packet_size", "timestamp"])
        writer.writerows(records)

    print(f"[+] Successfully wrote {len(records)} events to {filename}")

if __name__ == "__main__":
    generate_network_stream()