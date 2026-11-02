#ifndef PACKET_HPP
#define PACKET_HPP

#include <string>
#include <iostream>

class NetworkPacket {
private:
    std::string src_ip;
    std::string dest_ip;
    int src_port;
    int dest_port;
    std::string protocol;
    int packet_size;
    double timestamp;

public:
    NetworkPacket(std::string s_ip, std::string d_ip, int s_port, int d_port,
                  std::string proto, int size, double ts)
        : src_ip(std::move(s_ip)), dest_ip(std::move(d_ip)),
          src_port(s_port), dest_port(d_port),
          protocol(std::move(proto)), packet_size(size), timestamp(ts) {}

    const std::string& getSrcIP() const { return src_ip; }
    const std::string& getDestIP() const { return dest_ip; }
    int getSrcPort() const { return src_port; }
    int getDestPort() const { return dest_port; }
    const std::string& getProtocol() const { return protocol; }
    int getPacketSize() const { return packet_size; }
    double getTimestamp() const { return timestamp; }
};

#endif