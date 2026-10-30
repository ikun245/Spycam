#!/usr/bin/env python3
"""一键演示：并行运行 4 个【外部可触发】的攻击脚本，持续约 30s。

包含：端口扫描(1000001)、SSH 爆破(1000002)、SQLi(1000003)、XSS(1000004)。
这些从攻击机打向被监控服务器即可触发。

DNS 隧道(1000005) 与 C2 心跳(1000006) 因规则要求源在 HOME_NET，
必须在【服务器本机】单独运行 dns_tunnel.py / c2_beacon.py，故不在此脚本内。

用法：python3 run_all.py <目标IP> [--http-port 80] [-d 30]
"""
import argparse
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", help="被监控的服务器 IP")
    parser.add_argument("--http-port", type=int, default=80)
    parser.add_argument("-d", "--duration", type=float, default=30)
    args = parser.parse_args()

    jobs = [
        ["port_scan.py", args.target, "-d", str(args.duration)],
        ["ssh_bruteforce.py", args.target, "-d", str(args.duration)],
        ["web_sqli.py", args.target, "-d", str(args.duration), "--http-port", str(args.http_port)],
        ["web_xss.py", args.target, "-d", str(args.duration), "--http-port", str(args.http_port)],
    ]

    print(f"并行启动 4 个攻击，目标 {args.target}，持续约 {args.duration:0.0f}s ...", flush=True)
    procs = [subprocess.Popen([sys.executable, os.path.join(HERE, j[0])] + j[1:]) for j in jobs]
    try:
        for p in procs:
            p.wait()
    except KeyboardInterrupt:
        for p in procs:
            p.terminate()
        print("\n已停止全部子进程。", flush=True)
        return
    print("全部完成，请在 Spycam 告警列表查看 4 类告警。", flush=True)


if __name__ == "__main__":
    main()
