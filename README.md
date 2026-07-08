# Byte-DDOS
Byte IP Level DDoS Simulation Tool
Version: v1.0
Purpose: authorized network resilience testing
classification: internal penetration testing tool

# Overview
byte is a high performance, multivector network stress testing utility engineered for cybersecurity professionals conducting authorized infrastructure resilience assessments. It operates at both Layer 3/4 (IP/TCP/UDP/ICMP) and Layer 7 (HTTP) to comprehensively evaluate target robustness under various attack scenarios

built in pure C with raw socket access, Byte delivers maximum packet throughput with minimal overhead, capable of saturating gigabit links from modest hardware.
# Attack Vectors and capabilities 
# 1. TCP SYN flood:
Spoofed SYN packets exhaust connection backlog (L4)
# 2. TCP ACK flood:
Spoofed ACK packets stress stateful firewalls (L4)
# 3. UDP flood:
High volume UDP datagrams saturate bandwidth  (L4)
# 4. ICMP flood:
Ping flood consumes ICMP processing capacity (L3)
# 5. HTTP GET Flood:
Rapid HTTP requests overwhelm application servers (L7)
# 6. Slowloris Partial HTTP headers hold connections open indefinitely (L7)
# Technical Specifications
1. Raw socket construction for maximum performance (SYN, ACK, ICMP)
2. IP spoofing — fully randomized source addresses on all raw socket modes
3. Pseudo-header checksums — proper TCP/UDP checksum calculation for evasion
4. Configurable thread pool — up to 512 concurrent worker threads
5. Per-connection randomization — random source ports, sequence numbers, TTL values
6. HTTP randomization — random URI paths, custom User-Agent strings, varied headers
7. Slowloris persistence — sends headers at 50-150ms intervals to hold connections for minutes
8. No external dependencies — compiles with gcc and standard libraries only
# INSTALLATION
must have git installed
execute "git clone https://github.com/Rax-Rax/Byte-DDOS.git"
# tool usage (byte)
for acknowledging (byte) usage please execute/inject the compiled C file (USAGE)
ex: run "./USAGE"
if error compile the C files to match it with ur system using clang/gcc
example: gcc -o Byte Byte.c
same with usage.c
# NOTE
perfomance files can reach up to more than 500k-2m packets per sec 
# LEGAL NOTICE
Authorized use only.. This tool performs network stress testing and must only be deployed against systems you own or have explicit written authorization to test. Unauthorized use violates computer fraud and abuse laws worldwide.
