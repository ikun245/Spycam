"""P0 冒烟数据：SYN 扫描 pcap（配合规则 1000001：10s 内同源 ≥20 个 SYN 到 1-200 端口）。

固定时间戳保证 ground truth 可复现（需求梳理 §5.2）。
"""
from scapy.all import IP, TCP, RandShort, wrpcap

SRC = "10.0.0.66"
DST = "10.0.0.5"
BASE_TS = 1767000000.0  # 固定基准时间

pkts = []
# 100 个端口的 SYN 扫描，间隔 0.05s（总窗口 5s，落在规则 10s 窗口内）
for i, port in enumerate(range(20, 120)):
    p = IP(src=SRC, dst=DST) / TCP(sport=RandShort(), dport=port, flags="S")
    p.time = BASE_TS + i * 0.05
    pkts.append(p)

wrpcap("syn_scan_smoke.pcap", pkts)
print(f"generated {len(pkts)} packets -> syn_scan_smoke.pcap")
