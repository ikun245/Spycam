"""攻击演示脚本的公共参数与计时工具（仅标准库，无需 root）。

这些脚本用于演示 rules/spycam.rules 的检测效果，面向已开启实时抓包
（spycam-suricata-live）的目标主机。只产生匹配规则的良性请求，不做任何
真正的破坏性操作；请仅对自己拥有或已获授权的主机运行。
"""
import argparse
import sys
import time


def base_parser(desc, default_duration=30):
    p = argparse.ArgumentParser(description=desc)
    p.add_argument("target", help="目标主机 IP 或域名（被监控的那台服务器）")
    p.add_argument("-d", "--duration", type=float, default=default_duration,
                   help="持续攻击秒数，默认 %(default)s")
    p.add_argument("--rate", type=float, default=0.0,
                   help="每次动作之间的间隔秒数，默认 0（尽量快）")
    return p


class Deadline:
    """控制循环运行约 duration 秒，并周期性打印进度。"""

    def __init__(self, duration, label):
        self.end = time.time() + duration
        self.label = label
        self.count = 0
        self._last = 0.0

    def running(self):
        return time.time() < self.end

    def tick(self):
        self.count += 1
        now = time.time()
        if now - self._last >= 1.0:
            remain = max(0, self.end - now)
            print(f"[{self.label}] 已发送 {self.count} 次，剩余 {remain:0.0f}s",
                  flush=True)
            self._last = now

    def done(self):
        print(f"[{self.label}] 完成，共发送 {self.count} 次。"
              f"请在 Spycam 告警列表查看对应告警。", flush=True)


def sleep_rate(rate):
    if rate > 0:
        time.sleep(rate)


def banner(label, target):
    print(f"==== {label} -> {target} ====", flush=True)
    print("仅用于授权测试；按 Ctrl+C 可随时停止。", flush=True)


def guard_keyboard(fn):
    try:
        fn()
    except KeyboardInterrupt:
        print("\n已手动停止。", flush=True)
        sys.exit(130)
