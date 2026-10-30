#!/usr/bin/env python3
"""演示规则 1000006：C2 心跳（HOME_NET 向外部高频 POST /api/collect）。

方向性：规则是 http $HOME_NET -> $EXTERNAL_NET $HTTP_PORTS，源必须在
HOME_NET，目的在外部。因此本脚本要在【被监控的服务器本机】上运行，
模拟失陷主机周期性向 C2 回连上报。60s 内 >=10 次即触发。

原理：向一个【外部】HTTP 主机的 /api/collect 反复 POST 小数据。
目的主机需在 HTTP_PORTS（默认 80）上可连通，这样 TCP 握手完成、
HTTP 请求能被引擎解析。默认打到 example.com:80（会返回 404，但请求可见）。

用法（在服务器上）：python3 c2_beacon.py [--dest example.com] [--port 80] [-d 30]
"""
import argparse
import http.client

from common import Deadline, guard_keyboard, sleep_rate

# $HTTP_PORTS = 80,81,443,3000,8000,8008,8080,8081,8443（取明文可解析的）
HTTP_PORTS = {80, 81, 3000, 8000, 8008, 8080, 8081}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dest", default="example.com",
                        help="外部 C2 主机（必须是公网/外部地址），默认 example.com")
    parser.add_argument("--port", type=int, default=80, help="目的端口，默认 80")
    parser.add_argument("-d", "--duration", type=float, default=30)
    parser.add_argument("--rate", type=float, default=1.0)
    args = parser.parse_args()

    if args.port not in HTTP_PORTS:
        print(f"警告：端口 {args.port} 不在规则的明文 HTTP_PORTS 内，可能无法触发。", flush=True)

    print(f"==== C2 心跳 (sid 1000006) -> {args.dest}:{args.port}/api/collect ====", flush=True)
    print("请在【被监控的服务器本机】运行，目的地址须为外部主机；仅用于授权测试。", flush=True)

    def run():
        dl = Deadline(args.duration, "c2-beacon")
        while dl.running():
            try:
                conn = http.client.HTTPConnection(args.dest, args.port, timeout=3)
                conn.request("POST", "/api/collect", body=b'{"id":"demo","beat":1}',
                             headers={"User-Agent": "spycam-demo-c2",
                                      "Content-Type": "application/json"})
                conn.getresponse().read()
                conn.close()
            except OSError:
                pass
            dl.tick()
            sleep_rate(args.rate)
        dl.done()

    guard_keyboard(run)


if __name__ == "__main__":
    main()
