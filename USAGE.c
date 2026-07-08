#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define RED     "\033[1;31m"
#define GREEN   "\033[1;32m"
#define YELLOW  "\033[1;33m"
#define BLUE    "\033[1;34m"
#define CYAN    "\033[1;36m"
#define WHITE   "\033[1;37m"
#define DIM     "\033[2m"
#define RESET   "\033[0m"
#define BOLD    "\033[1m"

void print_banner() {
    printf("\n");
    printf("  %s╔══════════════════════════════════════════════════════╗%s\n", CYAN, RESET);
    printf("  %s║                   %sByte v2.0%s                        %s║%s\n", CYAN, WHITE, CYAN, CYAN, RESET);
    printf("  %s║        %sNetwork Stress Testing Tool%s                  %s║%s\n", CYAN, DIM, CYAN, CYAN, RESET);
    printf("  %s╚══════════════════════════════════════════════════════╝%s\n", CYAN, RESET);
    printf("\n");
}

void print_divider() {
    printf("  %s────────────────────────────────────────────────────%s\n", DIM, RESET);
}

void print_header(const char *title) {
    printf("\n  %s▸ %s%s%s\n", YELLOW, WHITE, title, RESET);
    print_divider();
}

void print_example(const char *prefix, const char *cmd, const char *desc) {
    printf("  %s$%s %s%-60s%s %s%s\n", GREEN, RESET, CYAN, cmd, RESET, DIM, desc);
}

void print_mode_table() {
    printf("\n");
    printf("  %sMODE            ROOT    DESCRIPTION%s\n", WHITE, RESET);
    printf("  %s────            ────    ───────────%s\n", DIM, RESET);
    printf("  %stcp-syn%s         %sYES%s    SYN flood — spoofed IPs, exhausts connection table\n", BLUE, RESET, RED, RESET);
    printf("  %stcp-ack%s         %sYES%s    ACK flood — CPU exhaustion on firewalls/LBs\n", BLUE, RESET, RED, RESET);
    printf("  %sudp-flood%s       %sNO%s     Bandwidth saturation with random UDP payloads\n", BLUE, RESET, GREEN, RESET);
    printf("  %shttp-get%s        %sNO%s     HTTP GET requests with randomized paths\n", BLUE, RESET, GREEN, RESET);
    printf("  %sslowloris%s       %sNO%s     Connection pool exhaustion via slow headers\n", BLUE, RESET, GREEN, RESET);
    printf("  %sicmp%s           %sYES%s    ICMP echo flood (ping flood)\n", BLUE, RESET, RED, RESET);
    printf("\n");
}

void print_modes_root() {
    print_header("MODES THAT REQUIRE ROOT (RAW SOCKETS)");

    printf("\n");
    print_example(" ", "sudo ./byte 192.168.1.1 80 tcp-syn 200", "SYN flood to port 80");
    print_example(" ", "sudo ./byte 10.0.0.5 443 tcp-syn 500", "SYN flood to HTTPS port");
    print_example(" ", "sudo ./byte 192.168.1.1 443 tcp-ack 200", "ACK flood to HTTPS port");
    print_example(" ", "sudo ./byte 10.0.0.1 22 tcp-ack 100", "ACK flood to SSH port");
    print_example(" ", "sudo ./byte 192.168.1.1 0 icmp 100", "ICMP ping flood");
    print_example(" ", "sudo ./byte 10.0.0.5 0 icmp 250", "High-rate ICMP flood");
    printf("\n");
}

void print_modes_user() {
    print_header("MODES THAT WORK WITHOUT ROOT");

    printf("\n");
    print_example(" ", "./byte 192.168.1.1 80 udp-flood 200", "UDP flood to port 80");
    print_example(" ", "./byte 10.0.0.5 53 udp-flood 300", "UDP flood to DNS port");
    print_example(" ", "./byte 192.168.1.1 80 http-get 500", "HTTP GET flood");
    print_example(" ", "./byte 10.0.0.5 443 http-get 300", "HTTPS GET flood");
    print_example(" ", "./byte 10.0.0.5 8080 http-get 400", "HTTP on custom port");
    print_example(" ", "./byte 192.168.1.1 80 slowloris 1000 /", "Slowloris on root path");
    print_example(" ", "./byte 10.0.0.5 80 slowloris 500 /api", "Slowloris on /api path");
    printf("\n");
}

void print_expert_tips() {
    print_header("EXPERT TIPS");

    printf("\n");
    printf("  %s•%s  Increase open file limit for high thread counts:\n", YELLOW, RESET);
    printf("     %s$ ulimit -n 65535%s\n", GREEN, RESET);
    printf("\n");
    printf("  %s•%s  Grant raw socket capability to avoid sudo:\n", YELLOW, RESET);
    printf("     %s$ sudo setcap cap_net_raw+ep ./byte%s\n", GREEN, RESET);
    printf("     %s$ sudo setcap cap_net_admin+ep ./byte%s (for spoofed IPs)\n", GREEN, RESET);
    printf("\n");
    printf("  %s•%s  Monitor traffic with tcpdump:\n", YELLOW, RESET);
    printf("     %s$ sudo tcpdump -i eth0 -n host <target_ip>%s\n", GREEN, RESET);
    printf("\n");
    printf("  %s•%s  Compile with maximum optimization:\n", YELLOW, RESET);
    printf("     %s$ gcc -O3 -Wall -pthread -o byte byte.c && strip byte%s\n", GREEN, RESET);
    printf("\n");
    printf("  %s•%s  Stop attack at any time with %sCtrl+C%s\n", YELLOW, RESET, WHITE, RESET);
    printf("\n");
}

void print_authorization() {
    printf("  %s╔══════════════════════════════════════════════════════╗%s\n", GREEN, RESET);
    printf("  %s║     %s✓ AUTHORIZED PENTEST — SCOPE CONFIRMED%s         %s║%s\n", GREEN, WHITE, GREEN, GREEN, RESET);
    printf("  %s╚══════════════════════════════════════════════════════╝%s\n", GREEN, RESET);
    printf("\n");
}

int main(int argc, char **argv) {
    /* Optional: show specific section if argument passed */
    if (argc > 1) {
        if (strcmp(argv[1], "root") == 0) {
            print_banner();
            print_authorization();
            print_modes_root();
            return 0;
        }
        if (strcmp(argv[1], "user") == 0) {
            print_banner();
            print_authorization();
            print_modes_user();
            return 0;
        }
        if (strcmp(argv[1] , "help") == 0 || strcmp(argv[1], "-h") == 0) {
            printf("Usage: ./byte-helper [section]\n");
            printf("Sections: root, user, all (default), help\n");
            return 0;
        }
    }

    /* Default: print everything */
    print_banner();
    print_authorization();
    print_mode_table();
    print_modes_root();
    print_modes_user();
    print_expert_tips();

    return 0;
}
