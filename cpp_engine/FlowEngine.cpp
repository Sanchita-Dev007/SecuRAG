#include "Packet.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <unordered_map>
#include <unordered_set>

struct HostTelemetry {
    int total_packets = 0;
    long long total_bytes = 0;
    std::unordered_set<int> targeted_ports;
    std::unordered_set<std::string> targeted_ips;
    double first_seen = 0.0;
    double last_seen = 0.0;
};

class TelemetryAggregator {
private:
    std::unordered_map<std::string, HostTelemetry> state_table;

public:
    void ingest(const NetworkPacket& packet) {
        auto& record = state_table[packet.getSrcIP()];

        if (record.total_packets == 0) {
            record.first_seen = packet.getTimestamp();
        }

        record.total_packets++;
        record.total_bytes += packet.getPacketSize();
        record.targeted_ports.insert(packet.getDestPort());
        record.targeted_ips.insert(packet.getDestIP());
        record.last_seen = packet.getTimestamp();
    }

    void exportToCSV(const std::string& output_path) const {
        std::ofstream out(output_path);
        if (!out.is_open()) {
            std::cerr << "[-] Error opening output file: " << output_path << std::endl;
            return;
        }

        out << "src_ip,packet_count,total_bytes,avg_packet_size,unique_dest_ports,unique_dest_ips,duration,packet_rate,byte_rate\n";

        for (const auto& entry : state_table) {
            const std::string& ip = entry.first;
            const HostTelemetry& data = entry.second;

            double duration = data.last_seen - data.first_seen;
            if (duration <= 0.0001) duration = 0.001;

            double avg_size = static_cast<double>(data.total_bytes) / data.total_packets;
            double packet_rate = static_cast<double>(data.total_packets) / duration;
            double byte_rate = static_cast<double>(data.total_bytes) / duration;

            out << ip << ","
                << data.total_packets << ","
                << data.total_bytes << ","
                << avg_size << ","
                << data.targeted_ports.size() << ","
                << data.targeted_ips.size() << ","
                << duration << ","
                << packet_rate << ","
                << byte_rate << "\n";
        }

        out.close();
        std::cout << "[+] Features successfully exported to " << output_path << std::endl;
    }
};

int main() {
    std::string input_csv = "data/raw_stream.csv";
    std::string output_csv = "data/features_extracted.csv";

    std::ifstream file(input_csv);
    if (!file.is_open()) {
        std::cerr << "[-] Could not open " << input_csv << ". Run Python generator first!" << std::endl;
        return 1;
    }

    TelemetryAggregator aggregator;
    std::string line;

    // Skip header
    std::getline(file, line);

    std::cout << "[*] C++ Engine: Parsing raw packet streams..." << std::endl;

    while (std::getline(file, line)) {
        if (line.empty()) continue;

        std::stringstream ss(line);
        std::string src_ip, dest_ip, proto_str, temp;
        int src_port, dest_port, size;
        double ts;

        std::getline(ss, src_ip, ',');
        std::getline(ss, dest_ip, ',');
        std::getline(ss, temp, ','); src_port = std::stoi(temp);
        std::getline(ss, temp, ','); dest_port = std::stoi(temp);
        std::getline(ss, proto_str, ',');
        std::getline(ss, temp, ','); size = std::stoi(temp);
        std::getline(ss, temp, ','); ts = std::stod(temp);

        aggregator.ingest(NetworkPacket(src_ip, dest_ip, src_port, dest_port, proto_str, size, ts));
    }

    file.close();
    aggregator.exportToCSV(output_csv);
    return 0;
}