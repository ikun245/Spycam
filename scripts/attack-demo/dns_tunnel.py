#!/usr/bin/env python3
"""演示规则 1000005：DNS 隧道（dns.query 以 >=40 位 [a-z0-9] 长标签开头）。

方向性：规则是 dns $HOME_NET any -> any 53，源必须在 HOME_NET。
因此本脚本要在【被监控的服务器本机】上运行，模拟失陷主机通过超长子域名
外带数据。向一个 DNS 服务器（默认 8.8.8.8:53）发送带超长标签的查询。

原理：标准库 socket 构造一个最简 DNS 查询报文，QNAME 的首标签是一串
长随机 [a-z0-9]，正好命中规则的 pcre。不依赖 dnspython。

用法（在服务器上）：python3 dns_tunnel.py [--resolver 8.8.8.8] [-d 30]
"""
import argparse
import os
import socket
import struct
import time

from common import Deadline, guard_keyboard, sleep_rate

ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"


def rand_label(n=52):
    raw = os.urandom(n)
    return "".join(ALPHABET[b % len(ALPHABET)] for b in raw)


def build_query(qname):
    tid = struct.pack(">H", int(time.time() * 1000) & 0xFFFF)
    header = tid + b"\x01\x00" + struct.pack(">HHHH", 1, 0, 0, 0)
    q = b""
    for part in qname.split("."):
        q += bytes([len(part)]) + part.encode("ascii")
    q += b"\x00" + struct.pack(">HH", 1, 1)  # QTYPE=A, QCLASS=IN
    return header + q


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--resolver", default="8.8.8.8", help="DNS 服务器，默认 8.8.8.8")
    parser.add_argument("--domain", default="example.com", help="隧道基础域名")
    parser.add_argument("-d", "--duration", type=float, default=30)
    parser.add_argument("--rate", type=float, default=0.3)
    args = parser.parse_args()

    print(f"==== DNS 隧道 (sid 1000005) -> {args.resolver}:53 ====", flush=True)
    print("请在【被监控的服务器本机】运行；仅用于授权测试。", flush=True)

    def run():
        dl = Deadline(args.duration, "dns-tunnel")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)
        while dl.running():
            qname = f"{rand_label()}.{args.domain}"
            try:
                sock.sendto(build_query(qname), (args.resolver, 53))
                try:
                    sock.recvfrom(512)
                except socket.timeout:
                    pass
            except OSError:
                pass
            dl.tick()
            sleep_rate(args.rate)
        sock.close()
        dl.done()

    guard_keyboard(run)


if __name__ == "__main__":
    main()
