#!/usr/bin/env python3
"""演示规则 1000002：SSH 爆破（60s 内同源对 22 端口 >=10 次 SYN）。

原理：反复向目标 22 端口发起 TCP connect（每次 connect 发一个 SYN），
模拟爆破登录时的高频连接。不进行任何真实的口令尝试，只建立/断开连接。

用法：python3 ssh_bruteforce.py <目标IP> [-d 30]
"""
import socket

from common import Deadline, banner, base_parser, guard_keyboard, sleep_rate


def main():
    args = base_parser(__doc__).parse_args()
    banner("SSH 爆破 (sid 1000002)", args.target)

    def run():
        dl = Deadline(args.duration, "ssh-brute")
        while dl.running():
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            try:
                s.connect((args.target, 22))
            except OSError:
                pass
            finally:
                s.close()
            dl.tick()
            sleep_rate(args.rate or 0.2)  # 默认略放缓，60s 内远超 10 次即可
        dl.done()

    guard_keyboard(run)


if __name__ == "__main__":
    main()
