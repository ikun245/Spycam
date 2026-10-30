#!/usr/bin/env python3
"""演示规则 1000001：SYN 端口扫描（10s 内同源 >=20 个 SYN 到低端口）。

原理：对目标的 1-200 低端口反复发起 TCP connect。connect() 会发出 SYN，
无需 root。规则排除了 22、80，所以这里跳过它们，避免与爆破/Web 规则重叠。

用法：python3 port_scan.py <目标IP> [-d 30]
"""
import socket

from common import Deadline, banner, base_parser, guard_keyboard, sleep_rate

# 规则匹配的端口集合 [1:21,23:79,81:200]
PORTS = list(range(1, 22)) + list(range(23, 80)) + list(range(81, 201))


def main():
    args = base_parser(__doc__).parse_args()
    banner("端口扫描 (sid 1000001)", args.target)

    def run():
        dl = Deadline(args.duration, "port-scan")
        while dl.running():
            for port in PORTS:
                if not dl.running():
                    break
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.3)
                try:
                    s.connect((args.target, port))
                except OSError:
                    pass  # 端口关闭/超时都无所谓，SYN 已经发出
                finally:
                    s.close()
                dl.tick()
                sleep_rate(args.rate)
        dl.done()

    guard_keyboard(run)


if __name__ == "__main__":
    main()
