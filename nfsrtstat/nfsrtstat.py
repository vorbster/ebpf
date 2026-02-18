#!/usr/bin/env python3
from bcc import BPF
import socket
import struct
import time
import curses
import argparse


def human_bits_per_sec(num_bytes):
    num = num_bytes * 8
    for unit in ["b/s", "Kb/s", "Mb/s", "Gb/s", "Tb/s"]:
        if num < 1000:
            return f"{num:6.1f} {unit}"
        num /= 1000.0
    return f"{num:.1f} Pb/s"


def ip_to_str(ip):
    return socket.inet_ntoa(struct.pack("I", ip))


def draw_title(stdscr, text):
    h, w = stdscr.getmaxyx()
    x = (w - len(text)) // 2
    stdscr.attron(curses.A_BOLD)
    stdscr.addstr(0, x, text)
    stdscr.attroff(curses.A_BOLD)


def draw_table(stdscr, start_row, table):
    for i, row in enumerate(table):
        line = f"{row[0]:<20} {row[1]:>12} {row[2]:>12}"
        stdscr.addstr(start_row + i, 2, line)


parser = argparse.ArgumentParser(
    description="Monitor TCP/UDP traffic on a given port"
)

parser.add_argument(
    "-p", "--port", type=int, default=2049, help="port to monitor (default: 2049 for NFS)"
)
parser.add_argument(
    "-n", "--no-resolve", action="store_true", help="do not resolve IP addresses to hostnames"
)

args = parser.parse_args()

port = args.port

bpf_program = f"""
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct key_t {{
    u32 client_ip;
}};

struct val_t {{
    u64 rx_bytes;
    u64 tx_bytes;
}};

BPF_HASH(traffic, struct key_t, struct val_t);
BPF_HASH(active_sk, u64, struct sock *);

static inline int handle_send(struct sock *sk, size_t size) {{
    u16 lport = sk->__sk_common.skc_num;

    if (lport != {port})
        return 0;

    u32 client_ip = sk->__sk_common.skc_daddr;

    struct key_t key = {{ .client_ip = client_ip }};
    struct val_t zero = {{}};
    struct val_t *val;

    val = traffic.lookup_or_try_init(&key, &zero);
    if (!val)
        return 0;

    __sync_fetch_and_add(&val->tx_bytes, size);
    return 0;
}}

int kprobe__tcp_sendmsg(struct pt_regs *ctx,
                         struct sock *sk,
                         struct msghdr *msg,
                         size_t size)
{{
    return handle_send(sk, size);
}}

int kprobe__tcp_recvmsg(struct pt_regs *ctx,
                         struct sock *sk)
{{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    active_sk.update(&pid_tgid, &sk);
    return 0;
}}

int kretprobe__tcp_recvmsg(struct pt_regs *ctx)
{{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct sock **skpp = active_sk.lookup(&pid_tgid);
    if (!skpp)
        return 0;

    struct sock *sk = *skpp;
    active_sk.delete(&pid_tgid);

    int copied = PT_REGS_RC(ctx);
    if (copied <= 0)
        return 0;

    u16 lport = sk->__sk_common.skc_num;
    if (lport != {port})
        return 0;

    u32 client_ip = sk->__sk_common.skc_daddr;

    struct key_t key = {{ .client_ip = client_ip }};
    struct val_t zero = {{}};
    struct val_t *val;

    val = traffic.lookup_or_try_init(&key, &zero);
    if (!val)
        return 0;

    __sync_fetch_and_add(&val->rx_bytes, copied);
    return 0;
}}
"""


b = BPF(text=bpf_program)
traffic = b["traffic"]

stdscr = curses.initscr()
curses.curs_set(0)
stdscr.nodelay(True)
stdscr.timeout(1000)


while True:
    time.sleep(1)
    stdscr.clear()
    client = draw_title(
        stdscr, "Server Network Traffic (port " + str(args.port) + ")")
    draw_table(stdscr, 2, [("Client IP", "RX", "TX")])
    client_items = 0
    for k, v in traffic.items():
        if args.no_resolve:
            client = ip_to_str(k.client_ip)
        else:
            try:
                client = socket.gethostbyaddr(ip_to_str(k.client_ip))[0]
            except socket.herror:
                client = ip_to_str(k.client_ip)
        draw_table(stdscr, 4 + client_items, [(client, human_bits_per_sec(v.rx_bytes), human_bits_per_sec(v.tx_bytes))
                                              ])
        client_items += 1
    stdscr.refresh()
    key = stdscr.getch()
    if key == ord('q'):
        stdscr.addstr(1, 2, "Exiting...")
        stdscr.refresh()
        break

    traffic.clear()
curses.endwin()
