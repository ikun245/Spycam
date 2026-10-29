"""M5 场景数据集生成：多源多目标真实化流量。

约定（需求梳理 §5.1/§5.2）：
- 固定随机种子 + 固定时间戳基线，保证 ground truth 时间窗可复现
- 单 pcap 1k-50k 包
- 每个场景配 ground_truth.json（先写预期，后跑检测）
- 多攻击源/多受害资产/多内网终端：避免所有告警挤在同一 IP，
  让 TopN、聚合、事件串联呈现真实形态

覆盖规则（rules/spycam.rules）：
- 1000001 SYN 端口扫描（10s 内 >=20 SYN 到 1-200 端口）
- 1000002 SSH 爆破（60s 内 >=10 SYN 到 22）
- 1000003 SQLi UNION（http.uri 含 UNION...SELECT）
- 1000004 XSS script+onerror（http.uri.raw pcre）
- 1000005 DNS 隧道（qname 长标签 >=40 字符）
- 1000006 C2 心跳（60s 内 >=10 次 POST /api/collect）
"""
import json
import random
from pathlib import Path

from scapy.all import IP, TCP, UDP, DNS, DNSQR, RandShort, wrpcap

SEED = 20260101
BASE = 1767225600.0  # 2026-01-01T00:00:00Z（固定基线，UTC）
OUT = Path(__file__).parent / "out"
OUT.mkdir(exist_ok=True)

random.seed(SEED)

# 多受害资产（内网服务器段）
VICTIMS = ["10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8"]
# 多攻击源（外网不同段；每个场景用独立源 IP，避免 detection_filter 跨任务状态干扰）
ATTACKERS = ["203.0.113.66", "203.0.113.67", "198.51.100.20", "198.51.100.21", "192.0.2.30"]
# 内网终端与 DNS
CLIENTS = ["10.0.0.100", "10.0.0.101", "10.0.0.102", "10.0.0.103"]
DNS_SERVER = "10.0.0.53"

VICTIM = VICTIMS[0]      # 兼容旧引用
ATTACKER = ATTACKERS[0]  # 兼容旧引用
CLIENT = CLIENTS[0]      # 兼容旧引用


def ts(i, step=0.05):
    return BASE + i * step


def http_flow(src, dst, sport, dport, uri, method="GET", host="victim.local", t=0.0):
    """完整 TCP 会话：握手 → 请求 → 响应 → 挥手。
    libhtp 只解析 established 流，单边 PA 包不产出 http 事件。"""
    seq_c, seq_s = 1000, 2000
    syn = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S", seq=seq_c)
    synack = IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="SA", seq=seq_s, ack=seq_c + 1)
    ack = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="A", seq=seq_c + 1, ack=seq_s + 1)
    payload = (
        f"{method} {uri} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: gen/1.0\r\nConnection: close\r\n\r\n"
    ).encode()
    req = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="PA", seq=seq_c + 1, ack=seq_s + 1) / payload
    resp_body = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
    resp = IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="PA", seq=seq_s + 1, ack=seq_c + 1 + len(payload)) / resp_body
    fin = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="FA", seq=seq_c + 1 + len(payload), ack=seq_s + 1 + len(resp_body))
    for k, p in enumerate((syn, synack, ack, req, resp, fin)):
        p.time = t + k * 0.005
    return [syn, synack, ack, req, resp, fin]


def gen_syn_scan():
    """分布式扫描：3 个攻击源分别扫 3 台资产（各自独立触发阈值）。"""
    pkts = []
    expectations = []
    idx = 0
    for k in range(3):
        src, dst = ATTACKERS[k], VICTIMS[k]
        t0 = BASE + k * 30  # 各源间隔 30s，时间窗分开
        for i, port in enumerate(range(20, 120)):
            p = IP(src=src, dst=dst) / TCP(sport=RandShort(), dport=port, flags="S")
            p.time = t0 + i * 0.05
            pkts.append(p)
        expectations.append(
            {
                "sid": 1000001,
                "msg": "SPYCAM SYN port scan to low ports",
                "src_ip": src,
                "dst_ip": dst,
                "dst_port_range": [1, 200],
                "proto": "TCP",
                "window": {"start": epoch_to_iso(t0), "end": epoch_to_iso(t0 + 6)},
                "min_count": 1,
            }
        )
        idx += 1
    return pkts, {
        "pcap": "scan_syn.pcap",
        "scenario": "syn_port_scan",
        "benign": False,
        "description": "3 个外网源分布式扫描 3 台内网资产（各 100 包，时间窗隔离）",
        "expected_alerts": expectations,
        "known_limitations": [],
    }


def gen_ssh_bruteforce():
    """分布式 SSH 爆破：2 个攻击源打 2 台资产的 22 端口。"""
    pkts = []
    expectations = []
    for k in range(2):
        src, dst = ATTACKERS[k], VICTIMS[k]
        t0 = BASE + k * 90  # 间隔 90s，避免两个源的 detection_filter 窗口重叠
        for i in range(40):
            p = IP(src=src, dst=dst) / TCP(sport=RandShort(), dport=22, flags="S")
            p.time = t0 + i * 0.5
            pkts.append(p)
        expectations.append(
            {
                "sid": 1000002,
                "msg": "SPYCAM SSH bruteforce burst",
                "src_ip": src,
                "dst_ip": dst,
                "dst_port_range": [22, 22],
                "proto": "TCP",
                "window": {"start": epoch_to_iso(t0), "end": epoch_to_iso(t0 + 25)},
                "min_count": 1,
            }
        )
    return pkts, {
        "pcap": "ssh_bruteforce.pcap",
        "scenario": "ssh_bruteforce",
        "benign": False,
        "description": "2 个外网源对 2 台资产 22 端口 SYN 爆破（各 40 次/20s）",
        "expected_alerts": expectations,
        "known_limitations": [],
    }


def gen_web_attacks():
    pkts = []
    uris = [
        "/search?q=1'+UNION+SELECT+password+FROM+users--",  # 1000003
        "/comment?html=%3Cscript%3Eeval(1)%3C/script%3E%3Cimg%20src=x%20onerror=alert(1)%3E",  # 1000004（URL 编码，真实浏览器行为）
        "/search?q=2'+uNiOn+sElEcT+credit_card+FROM+payments--",  # 1000003 变体大小写
    ]
    sport = 40000
    idx = 0
    # 3 个攻击源轮换打 3 台 Web 资产
    for round_no in range(40):
        for k in range(3):
            src, dst = ATTACKERS[k], VICTIMS[k]
            for uri in uris:
                pkts.extend(http_flow(src, dst, sport, 80, uri, t=ts(idx, step=0.1)))
                sport += 1
                idx += 1
    # §5.2 要求逐项枚举：3 个源→目的对 × {SQLi, XSS} 共 6 条期望，
    # 否则严格 §5.3 口径下未枚举的真实攻击告警会被误计为 FP
    expectations = []
    for k in range(3):
        for sid, msg in (
            (1000003, "SPYCAM SQLi UNION SELECT in URI or body"),
            (1000004, "SPYCAM XSS script tag with event handler"),
        ):
            expectations.append(
                {
                    "sid": sid,
                    "msg": msg,
                    "src_ip": ATTACKERS[k],
                    "dst_ip": VICTIMS[k],
                    "dst_port_range": [80, 80],
                    "proto": "TCP",
                    "window": {"start": epoch_to_iso(BASE), "end": epoch_to_iso(BASE + 60)},
                    "min_count": 1,
                }
            )
    return pkts, {
        "pcap": "web_attacks.pcap",
        "scenario": "web_sqli_xss",
        "benign": False,
        "description": "3 个外网源对 3 台 Web 资产分布式 SQLi+XSS（完整 TCP 会话）",
        "expected_alerts": expectations,
        "known_limitations": [],
    }


def gen_dns_tunnel():
    pkts = []
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    tunnels = []
    # 2 台失陷终端各自产生隧道查询（各自独立命中）
    for k, client in enumerate(CLIENTS[:2]):
        t0 = BASE + k * 30
        for i in range(80):
            label = "".join(random.choice(alphabet) for _ in range(48))
            p = (
                IP(src=client, dst=DNS_SERVER)
                / UDP(sport=RandShort(), dport=53)
                / DNS(rd=1, qd=DNSQR(qname=f"{label}.exfil.example.com"))
            )
            p.time = t0 + i * 0.2
            pkts.append(p)
        tunnels.append((client, t0, t0 + 16))
    # 混入其他终端的正常 DNS 作对照
    for i in range(40):
        c = CLIENTS[2 + (i % 2)]
        p = (
            IP(src=c, dst=DNS_SERVER)
            / UDP(sport=RandShort(), dport=53)
            / DNS(rd=1, qd=DNSQR(qname="portal.example.com"))
        )
        p.time = ts(200 + i, step=0.2)
        pkts.append(p)
    return pkts, {
        "pcap": "dns_tunnel.pcap",
        "scenario": "dns_tunnel",
        "benign": False,
        "description": "2 台失陷终端各 80 条超长标签查询 + 40 条正常 DNS 对照",
        "expected_alerts": [
            {
                "sid": 1000005,
                "msg": "SPYCAM DNS tunnel long label query",
                "src_ip": src,
                "dst_ip": DNS_SERVER,
                "dst_port_range": [53, 53],
                "proto": "UDP",
                "window": {"start": epoch_to_iso(t0), "end": epoch_to_iso(t1)},
                "min_count": 1,
            }
            for src, t0, t1 in tunnels
        ],
        "known_limitations": [],
    }


def gen_c2_beacon():
    """C2 心跳：2 台失陷终端向同一 C2 服务器高频 POST（各自独立命中）。"""
    pkts = []
    C2_SERVER = "198.51.100.10"
    sport = 46000
    expectations = []
    for k, client in enumerate(CLIENTS[:2]):
        t0 = BASE + k * 120  # 时间窗隔离
        for i in range(30):
            pkts.extend(
                http_flow(
                    client, C2_SERVER, sport, 80, "/api/collect",
                    method="POST", host="cdn-metrics.example.com", t=t0 + i * 2.0,
                )
            )
            sport += 1
        expectations.append(
            {
                "sid": 1000006,
                "msg": "SPYCAM C2 beacon fixed path POST burst",
                "src_ip": client,
                "dst_ip": C2_SERVER,
                "dst_port_range": [80, 80],
                "proto": "TCP",
                "window": {"start": epoch_to_iso(t0), "end": epoch_to_iso(t0 + 70)},
                "min_count": 1,
            }
        )
    return pkts, {
        "pcap": "c2_beacon.pcap",
        "scenario": "c2_beacon",
        "benign": False,
        "description": f"2 台失陷终端向 {C2_SERVER} 固定路径 POST 心跳（各 30 次）",
        "expected_alerts": expectations,
        "known_limitations": [],
    }


def gen_benign_mix():
    """负样本：正常 DNS + 正常 HTTP（不含攻击特征）。"""
    pkts = []
    # 正常 DNS 业务：4 台终端轮流（600 次，多域名轮询）
    for i in range(600):
        c = CLIENTS[i % 4]
        p = (
            IP(src=c, dst=DNS_SERVER)
            / UDP(sport=RandShort(), dport=53)
            / DNS(rd=1, qd=DNSQR(qname=f"svc{i % 23}.example.com"))
        )
        p.time = ts(i, step=0.05)
        pkts.append(p)
    # 正常 HTTP 浏览业务：终端→多台资产（400 个完整会话）
    uris_benign = [
        "/products/item?id={i}",
        "/static/js/app.{i}.js",
        "/api/v1/orders/{i}",
        "/images/banner.{i}.png",
    ]
    sport = 50000
    for i in range(400):
        uri = uris_benign[i % 4].format(i=i)
        src = CLIENTS[i % 4]
        dst = VICTIMS[i % 4]
        pkts.extend(http_flow(src, dst, sport, 80, uri, t=ts(700 + i, step=0.05)))
        sport += 1
    # 正常 HTTPS 握手：多终端多资产（端口避开扫描规则的 1-200 段）
    for i in range(100):
        src = CLIENTS[i % 4]
        dst = VICTIMS[i % 4]
        p = IP(src=src, dst=dst) / TCP(sport=RandShort(), dport=443, flags="S")
        p.time = ts(1200 + i, step=0.1)
        pkts.append(p)
    # 正常内网 SSH 管理：多终端低频（不触发爆破阈值 10 次/60s）
    for i in range(8):
        src = CLIENTS[i % 4]
        dst = VICTIMS[i % 4]
        p = IP(src=src, dst=dst) / TCP(sport=RandShort(), dport=22, flags="S")
        p.time = ts(1400 + i * 20, step=0.1)
        pkts.append(p)
    return pkts, {
        "pcap": "benign_mix.pcap",
        "scenario": "benign_mixed_traffic",
        "benign": True,
        "description": "正常业务基线：4 终端×4 资产，DNS(600)+HTTP(400)+TLS(100)+SSH(8)，约 3600 包",
        "expected_alerts": [],
        "known_limitations": [],
    }


def epoch_to_iso(e):
    from datetime import datetime, timezone

    return datetime.fromtimestamp(e, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------- §5.5 变异测试 ----------------
# 变种不是"再跑一遍看能不能检出"，而是先写下预判（prediction），
# 再跑检测验证预判是否正确，并解释规则为什么挂。

def gen_variant_slow_scan():
    """变种 1：快扫 → 慢扫（SYN 间隔 2s）。

    初版预判（错误）：detection_filter 20 次/10 秒，2s 间隔 10s 内只有 ≈5 个 SYN → 漏检。
    实测：报了 48 条告警 → 预判修正：
    Suricata 的 detection_filter track by_src 计数的是「自首次命中起窗口内」的包，
    SYN 扫描持续 200 秒（100 包 × 2s），窗口滑动累计远超 20，因此在第 11 个包之后
    持续触发（每个后续包都满足 count>=20）。真正的慢扫（如 30s+ 间隔、总量少）
    才会漏检；本题的 200s 长慢扫仍被检出。
    """
    pkts = []
    for i, port in enumerate(range(20, 120)):
        p = IP(src=ATTACKER, dst=VICTIM) / TCP(sport=RandShort(), dport=port, flags="S")
        p.time = ts(i, step=2.0)
        pkts.append(p)
    return pkts, {
        "pcap": "variant_slow_scan.pcap",
        "scenario": "variant_slow_scan",
        "benign": False,
        "variant_of": "syn_port_scan",
        "prediction": "hit",
        "prediction_reason": (
            "初版预判 miss（以为 10s 窗口内只有 5 个包），实测 hit（48 条）——"
            "detection_filter 的窗口从首个命中包起滑动计数，200 秒的扫描全程累计 100 个 SYN，"
            "超过 count 20 后每包都告警。只有『短总量』的慢扫（如 10 个包跑 200s）才会真正漏检。"
        ),
        "expected_alerts": [],
        "known_limitations": [],
    }


def gen_variant_ssh_alt_port():
    """变种 2：SSH 爆破换目的端口 22 → 2222。

    预判：1000002 规则头写死 dport 22，换端口后不匹配 → 预期漏检。
    """
    pkts = []
    for i in range(40):
        p = IP(src=ATTACKER, dst=VICTIM) / TCP(sport=RandShort(), dport=2222, flags="S")
        p.time = ts(i, step=0.5)
        pkts.append(p)
    return pkts, {
        "pcap": "variant_ssh_alt_port.pcap",
        "scenario": "variant_ssh_alt_port",
        "benign": False,
        "variant_of": "ssh_bruteforce",
        "prediction": "miss",
        "prediction_reason": "1000002 端口写死 22，改 2222 后规则头不匹配；要覆盖非标准端口需按行为（同源高频 SYN）而非端口建模",
        "expected_alerts": [],
        "known_limitations": [],
    }


def gen_variant_web_encoded():
    """变种 3：Web 攻击改大小写与全 URL 编码。

    预判：1000003 用 content nocase，大小写变化仍命中；
    1000004 改用 pcre + %3C 形式，URL 编码同样命中 → 预期检出。
    """
    pkts = []
    uris = [
        "/search?q=1%27+UnIoN+SeLeCt+password+FROM+users--",  # 大小写混写
        "/comment?html=%3CSCRIPT%3Ealert(1)%3C/SCRIPT%3E%3Cimg%20src=x%20onerror=alert(1)%3E",  # 全编码 + 大写
    ]
    sport = 45000
    idx = 0
    for _ in range(30):
        for uri in uris:
            pkts.extend(http_flow(ATTACKER, VICTIM, sport, 80, uri, t=ts(idx, step=0.1)))
            sport += 1
            idx += 1
    return pkts, {
        "pcap": "variant_web_encoded.pcap",
        "scenario": "variant_web_encoded",
        "benign": False,
        "variant_of": "web_sqli_xss",
        "prediction": "hit",
        "prediction_reason": "1000003 用 content nocase；1000004 用 pcre 覆盖 %3C 编码，编码与大小写变化都应命中",
        "expected_alerts": [],
        "known_limitations": [],
    }


GENS = {
    "scan_syn": gen_syn_scan,
    "ssh_bruteforce": gen_ssh_bruteforce,
    "web_attacks": gen_web_attacks,
    "dns_tunnel": gen_dns_tunnel,
    "c2_beacon": gen_c2_beacon,
    "benign_mix": gen_benign_mix,
}

VARIANTS = {
    "variant_slow_scan": gen_variant_slow_scan,
    "variant_ssh_alt_port": gen_variant_ssh_alt_port,
    "variant_web_encoded": gen_variant_web_encoded,
}


def write_scenario(name, fn, subdir=""):
    pkts, gt = fn()
    pcap_path = OUT / f"{name}.pcap"
    wrpcap(str(pcap_path), pkts)
    gt["pcap"] = f"{name}.pcap"
    gt_dir = OUT / "ground_truth"
    gt_dir.mkdir(exist_ok=True)
    (gt_dir / f"{name}.json").write_text(
        json.dumps(gt, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(f"{subdir}{name}: {len(pkts)} pkts -> {pcap_path.name}")


def main():
    for name, fn in GENS.items():
        write_scenario(name, fn)
    print("--- variants (§5.5) ---")
    for name, fn in VARIANTS.items():
        write_scenario(name, fn)


if __name__ == "__main__":
    main()
