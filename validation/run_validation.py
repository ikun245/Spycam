"""数据自验入口（P2 实现；骨架期输出占位说明）。

完整流程（架构设计 §8）：生成场景 pcap → 上传回放 → 经 API 取原始告警 →
对照 ground truth → 输出 report.json + report.md。
评测程序只走公开 API，不直接读数据库或 Suricata 日志。
"""
import os


def main() -> None:
    api = os.environ.get("API_BASE_URL", "http://api:8081")
    print(f"[validator] skeleton placeholder; API_BASE_URL={api}")
    print("[validator] scenarios / ground truth / TP-FP-FN evaluation come in P2")
    print("[validator] see docs/需求梳理.md §5 for the judging criteria")


if __name__ == "__main__":
    main()
