// pingNetInfo.cpp

#include <iostream>
#include <iomanip>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <cerrno>
#include <cfloat>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/time.h>

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define ABS(a) ((a) < 0 ? (-(a)) : (a))

#define MAX_HOPS 64
#define MIN_DATA_SIZE 100
#define MAX_DATA_SIZE 500
#define PACKET_SIZE 4096
#define MAX_WAIT_TIME 2
#define TIMEOUT 1000
#define ICMP_HDR_SIZE sizeof(struct icmp)

struct PingProbe
{
    struct sockaddr_in addr;
    int sock_fd;
    int ttl;
    int received_count;
};

unsigned short calculate_checksum(unsigned short *paddress, int len);
void send_ping(PingProbe *probe, struct sockaddr_in addr, int packet_size);
void send_packet(int sockfd, struct sockaddr_in dest_addr, int ttl, int packet_size);
int receive_packet(int sockfd, struct sockaddr_in *addr, char *recv_buf);

void print_header(struct icmp *icmph, int bytes)
{
    std::cout << "ICMP Header: type " << static_cast<int>(icmph->icmp_type)
              << ", code " << static_cast<int>(icmph->icmp_code)
              << ", checksum " << std::hex << ntohs(icmph->icmp_cksum)
              << ", id " << ntohs(icmph->icmp_id)
              << ", sequence " << ntohs(icmph->icmp_seq)
              << ", bytes " << bytes << std::dec << std::endl;
}

void print_data(char *buf, int bytes)
{
    struct icmp *hdr = reinterpret_cast<struct icmp *>(buf);
    for (int i = sizeof(struct ip) + ICMP_HDR_SIZE; i < bytes; i++)
    {
        std::cout << buf[i];
    }
    std::cout << std::endl;
}

int main(int argc, char *argv[])
{
    if (argc != 4)
    {
        std::cerr << "Usage: " << argv[0] << " <address> <packet_count> <time_difference>\n";
        return 1;
    }

    char *address = argv[1];
    int n = std::atoi(argv[2]);
    int T = std::atoi(argv[3]);

    struct hostent *host = gethostbyname(address);
    if (!host)
    {
        std::cerr << "Could not resolve " << address << std::endl;
        return 1;
    }

    std::cout << "Pinging " << address << " (" << inet_ntoa(*(struct in_addr *)host->h_addr_list[0]) << "):\n";

    int sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock_fd < 0)
    {
        perror("socket creation failed\n");
        return 1;
    }

    std::cout << MAX_HOPS << " max hops, " << PACKET_SIZE << " bytes packets\n\n";

    struct timeval timeout = {MAX_WAIT_TIME, 0};
    setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));

    int ttl = 1;
    setsockopt(sock_fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));

    int hop_count = 0, reached = 0;

    PingProbe probe = {};
    probe.sock_fd = sock_fd;
    probe.ttl = ttl;

    struct sockaddr_in dest_addr = {}, addr, prev_addr = {}, node_addr = {};
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr = *(struct in_addr *)host->h_addr_list[0];
    probe.addr = dest_addr;
    node_addr = dest_addr;
    prev_addr = dest_addr;
    inet_aton("127.0.0.1", &prev_addr.sin_addr);

    double old_rtt[10] = {0.0};

    while (ttl <= MAX_HOPS && !reached)
    {
        probe.received_count = 0;

        probe.addr = dest_addr;
        send_ping(&probe, addr, 0);

        std::cout << std::endl;

        if (probe.received_count == 0)
        {
            ttl++;
            hop_count++;
            setsockopt(sock_fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
            probe.ttl = ttl;
            continue;
        }

        node_addr.sin_addr = probe.addr.sin_addr;

        std::cout << "LINK \t " << inet_ntoa(prev_addr.sin_addr) << " *\t*\t* ";
        std::cout << inet_ntoa(node_addr.sin_addr) << "\t\t\t\t\t\t\t<------(link x-y)\n\n";

        sleep(1);

        prev_addr = probe.addr;

        double min_latency = DBL_MAX, max_latency = 0.0, total_latency = 0.0;
        double total_bandwidth = 0.0;
        double new_rtt = 0.0, new_rtt0 = 0.0;

        for (int i = 0; i <= MAX_DATA_SIZE; i += 100)
        {
            char send_buf[PACKET_SIZE];
            char recv_buf[PACKET_SIZE];
            int seq_num = 0;
            int num_received = 0;

            std::cout << "\nDatasize: " << i;

            for (int j = 0; j < n; j++)
            {
                struct icmp *icmp_hdr = reinterpret_cast<struct icmp *>(send_buf);
                icmp_hdr->icmp_type = ICMP_ECHO;
                icmp_hdr->icmp_code = 0;
                icmp_hdr->icmp_id = getpid() & 0xffff;
                icmp_hdr->icmp_seq = seq_num++;
                std::memset(icmp_hdr->icmp_data, 0xa5, i);
                icmp_hdr->icmp_cksum = 0;
                icmp_hdr->icmp_cksum = calculate_checksum(reinterpret_cast<uint16_t *>(icmp_hdr), sizeof(struct icmp) + i);

                for (int i = 0; i < PACKET_SIZE; i++)
                    recv_buf[i] = '\0';

                struct timeval start_time, end_time;
                gettimeofday(&start_time, NULL);

                int bytes_sent = sendto(sock_fd, send_buf, sizeof(struct icmp) + i, 0, (struct sockaddr *)&probe.addr, sizeof(struct sockaddr));
                if (bytes_sent < 0)
                {
                    perror("Error sending packet");
                    continue;
                }

                int bytes_received = receive_packet(sock_fd, &addr, recv_buf);
                if (bytes_received <= 0)
                {
                    continue;
                }

                gettimeofday(&end_time, NULL);

                std::cout << "\n"
                          << j + 1 << ". ";
                struct ip *ip_hdr = reinterpret_cast<struct ip *>(recv_buf);
                int ip_hdr_len = ip_hdr->ip_hl * 4;
                struct icmp *icmp_hdr1 = reinterpret_cast<struct icmp *>(recv_buf + ip_hdr_len);
                print_header(icmp_hdr1, bytes_received);

                if (icmp_hdr1->icmp_type == 11 && icmp_hdr1->icmp_code == 0)
                {
                }
                else if (icmp_hdr1->icmp_type == ICMP_ECHOREPLY && icmp_hdr1->icmp_code == 0)
                {
                }
                else
                {
                    print_data(recv_buf, bytes_received);
                }

                double rtt = (double)(end_time.tv_sec - start_time.tv_sec) * 1000.0 + (double)(end_time.tv_usec - start_time.tv_usec) / 1000.0;
                if (j == 0)
                    new_rtt = rtt;
                else
                {
                    new_rtt = 0.8 * new_rtt + 0.2 * rtt;
                }

                std::cout << "rtt: " << rtt << " ms\n";

                num_received++;
                sleep(T);
            }

            if (num_received == 0)
                continue;

            double prev_rtt = old_rtt[(i / MIN_DATA_SIZE)];
            old_rtt[(i / MIN_DATA_SIZE)] = new_rtt;

            if (i == 0)
            {
                new_rtt0 = new_rtt;
                total_latency = ABS(new_rtt - prev_rtt) / 2.0;
                continue;
            }

            double bandwidth = (double)(i * 8) / ABS((ABS(new_rtt - prev_rtt) / 2.0 - total_latency) / 1000.0 * 1024.0 * 1024.0);
            if (bandwidth > total_bandwidth)
                total_bandwidth = bandwidth;
        }

        std::cout << "\n\nLatency: " << total_latency << " ms\n";
        std::cout << "Bandwidth: " << total_bandwidth << " mbps\n\n";

        if (node_addr.sin_addr.s_addr == dest_addr.sin_addr.s_addr)
        {
            std::cout << "DESTINATION REACHED\n\n";
            break;
        }

        ttl++;
        hop_count++;
        setsockopt(sock_fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
        probe.ttl = ttl;
    }
    return 0;
}

unsigned short calculate_checksum(unsigned short *paddress, int len)
{
    int nleft = len;
    int sum = 0;
    unsigned short *w = paddress;
    unsigned short answer = 0;

    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1)
    {
        *(unsigned char *)(&answer) = *(unsigned char *)w;
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    answer = ~sum;
    return answer;
}

void send_ping(PingProbe *probe, struct sockaddr_in addr, int data_size)
{
    int flag, msg_count = 0, msg_received_count = 0;
    struct timeval start_time, end_time;

    for (int j = 0; j < 5; j++)
    {
        sleep(1);
        struct icmp icmp_hdr;
        int packet_size = ICMP_HDR_SIZE + data_size;
        char packet[packet_size];
        int sent_bytes;

        icmp_hdr.icmp_type = ICMP_ECHO;
        icmp_hdr.icmp_code = 0;
        icmp_hdr.icmp_id = getpid();
        icmp_hdr.icmp_seq = msg_count++;
        std::memset(&icmp_hdr.icmp_dun, 0, sizeof(icmp_hdr.icmp_dun));

        std::memcpy(packet, &icmp_hdr, ICMP_HDR_SIZE);
        std::memset(packet + ICMP_HDR_SIZE, 'A', data_size);

        icmp_hdr.icmp_cksum = calculate_checksum(reinterpret_cast<unsigned short *>(packet), packet_size);
        std::memcpy(packet, &icmp_hdr, ICMP_HDR_SIZE);
        flag = 1;

        setsockopt(probe->sock_fd, IPPROTO_IP, IP_TTL, &probe->ttl, sizeof(probe->ttl));

        gettimeofday(&start_time, NULL);
        sent_bytes = sendto(probe->sock_fd, packet, packet_size, 0, (struct sockaddr *)&probe->addr, sizeof(struct sockaddr));
        if (sent_bytes <= 0)
        {
            perror("sendto error");
            flag = 0;
        }

        int bytes = 0;
        char recv_buf[PACKET_SIZE] = {0};

        socklen_t len = sizeof(struct sockaddr_in);

        char recv_packet[PACKET_SIZE];
        struct sockaddr_in recv_addr = {};
        socklen_t addr_len = sizeof(recv_addr);

        int recv_bytes = recvfrom(probe->sock_fd, recv_packet, PACKET_SIZE, 0, (struct sockaddr *)&recv_addr, &addr_len);
        if (recv_bytes <= 0)
        {
            std::cout << probe->ttl << ".\t*\n";
            continue;
        }

        struct in_addr source_ip, dest_ip;

        struct ip *ip_hdr = reinterpret_cast<struct ip *>(recv_packet);
        int ip_hdr_len = ip_hdr->ip_hl * 4;
        source_ip.s_addr = ip_hdr->ip_src.s_addr;
        dest_ip.s_addr = ip_hdr->ip_dst.s_addr;

        std::cout << "Ip src: " << inet_ntoa(source_ip) << ",\t";
        std::cout << "Ip dest: " << inet_ntoa(dest_ip) << ",\tttl: " << ip_hdr->ip_ttl << std::endl;
        struct icmp *icmp_hdr1 = reinterpret_cast<struct icmp *>(recv_packet + ip_hdr_len);
        print_header(icmp_hdr1, recv_bytes);

        if (icmp_hdr1->icmp_type == ICMP_TIMXCEED && icmp_hdr1->icmp_code == ICMP_TIMXCEED_INTRANS)
        {
            std::cout << probe->ttl << ".\t" << inet_ntoa(recv_addr.sin_addr) << std::endl;
        }

        if (icmp_hdr1->icmp_type == ICMP_ECHOREPLY && icmp_hdr1->icmp_code == 0)
        {
            std::cout << probe->ttl << ".\t" << inet_ntoa(recv_addr.sin_addr) << std::endl;
            msg_received_count++;
        }

        if (icmp_hdr1->icmp_type == ICMP_UNREACH && icmp_hdr1->icmp_code == 3)
        {
            std::cout << probe->ttl << ".\t" << inet_ntoa(recv_addr.sin_addr) << std::endl;
            break;
        }
        probe->addr = recv_addr;
        probe->received_count++;
        break;
    }
}

void send_packet(int sockfd, struct sockaddr_in dest_addr, int ttl, int packet_size)
{
    auto *icmp_packet = reinterpret_cast<struct icmp *>(malloc(sizeof(struct icmp) + packet_size));
    icmp_packet->icmp_type = 8;
    icmp_packet->icmp_code = 0;
    icmp_packet->icmp_id = htons(getpid());
    icmp_packet->icmp_seq = htons(ttl);
    std::memset(icmp_packet->icmp_data, 0xa5, packet_size);
    std::memset(icmp_packet->icmp_data, 'A', packet_size);
    icmp_packet->icmp_cksum = calculate_checksum(reinterpret_cast<unsigned short *>(icmp_packet), sizeof(struct icmp) + packet_size);

    int sendbytes;

    if ((sendbytes = sendto(sockfd, icmp_packet, sizeof(struct icmp) + packet_size, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr))) <= 0)
    {
        perror("sendto failed\n");
    }
    std::cout << sendbytes << " bytes sent to " << inet_ntoa((struct in_addr)dest_addr.sin_addr) << std::endl;

    free(icmp_packet);
}

int receive_packet(int sockfd, struct sockaddr_in *addr, char *recv_buf)
{
    int recv_bytes = 0;

    socklen_t len = sizeof(struct sockaddr_in);

    if ((recv_bytes = recvfrom(sockfd, recv_buf, PACKET_SIZE, 0, (struct sockaddr *)addr, &len)) < 0)
    {
        if (errno == EWOULDBLOCK)
        {
            std::cout << "Request timed out.\n";
        }
        else
        {
            perror("recvfrom failed\n");
        }
    }

    return recv_bytes;
}
