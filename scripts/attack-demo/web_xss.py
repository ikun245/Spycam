#!/usr/bin/env python3
"""演示规则 1000004：反射型 XSS（http.uri 含 <script ... onerror）。

原理：对目标 Web 端口反复发送 URI 带 URL 编码 <script onerror 特征的 GET
请求。Suricata 规范化 URI 后用 pcre 匹配。只读取响应，不做真实注入。

注意：与 SQLi 相同，规则作用在明文 HTTP（默认 80 端口），演示要走 http://。

用法：python3 web_xss.py <目标IP> [--http-port 80] [-d 30]
"""
import http.client

from common import Deadline, banner, base_parser, guard_keyboard, sleep_rate

PAYLOADS = [
    "/?q=%3Cscript%3Eimg%20onerror%3Dalert(1)%3C/script%3E",
    "/search?x=%3Cscript%20src=x%20onerror=alert(document.cookie)%3E",
    "/view?name=%3Cscript%3Enew%20Image().onerror=1%3C/script%3E",
]


def main():
    parser = base_parser(__doc__)
    parser.add_argument("--http-port", type=int, default=80, help="目标 HTTP 端口，默认 80")
    args = parser.parse_args()
    banner("反射型 XSS (sid 1000004)", args.target)

    def run():
        dl = Deadline(args.duration, "xss")
        i = 0
        while dl.running():
            path = PAYLOADS[i % len(PAYLOADS)]
            i += 1
            try:
                conn = http.client.HTTPConnection(args.target, args.http_port, timeout=3)
                conn.request("GET", path, headers={"User-Agent": "spycam-demo-xss"})
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
