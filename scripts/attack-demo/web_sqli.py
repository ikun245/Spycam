#!/usr/bin/env python3
"""演示规则 1000003：SQL 注入（http.uri 含 UNION ... SELECT）。

原理：对目标 Web 端口反复发送 URI 带 UNION SELECT 特征的 GET 请求。
只读取响应，不提交真实数据。Suricata 解析 HTTP 后匹配 http.uri 规则。

注意：规则作用在明文 HTTP（默认 80 端口）。HTTPS 流量是加密的，
引擎看不到 URI，因此演示要走 http:// 而非 https://。

用法：python3 web_sqli.py <目标IP> [--http-port 80] [-d 30]
"""
import http.client

from common import Deadline, banner, base_parser, guard_keyboard, sleep_rate

PAYLOADS = [
    "/?id=1%20UNION%20SELECT%20username,password%20FROM%20users",
    "/search?q=x%27%20UNION%20SELECT%201,2,3--",
    "/product?pid=9%20UNION%20ALL%20SELECT%20NULL,version()",
]


def main():
    parser = base_parser(__doc__)
    parser.add_argument("--http-port", type=int, default=80, help="目标 HTTP 端口，默认 80")
    args = parser.parse_args()
    banner("SQL 注入 (sid 1000003)", args.target)

    def run():
        dl = Deadline(args.duration, "sqli")
        i = 0
        while dl.running():
            path = PAYLOADS[i % len(PAYLOADS)]
            i += 1
            try:
                conn = http.client.HTTPConnection(args.target, args.http_port, timeout=3)
                conn.request("GET", path, headers={"User-Agent": "spycam-demo-sqli"})
                conn.getresponse().read()
                conn.close()
            except OSError:
                pass
            dl.tick()
            sleep_rate(args.rate or 0.3)
        dl.done()

    guard_keyboard(run)


if __name__ == "__main__":
    main()
