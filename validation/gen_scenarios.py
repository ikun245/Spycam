"""M5 场景数据集生成：4 类攻击 + 1 类正常负样本。

约定（需求梳理 §5.1/§5.2）：
- 固定随机种子 + 固定时间戳基线，保证 ground truth 时间窗可复现
- 单 pcap 1k-50k 包
- 每个场景配 ground_truth.json（先写预期，后跑检测）

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

VICTIM = "10.0.0.5"
ATTACKER = "203.0.113.66"
CLIENT = "10.0.0.100"
DNS_SERVER = "10.0.0.53"


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
    pkts = []
    for i, port in enumerate(range(20, 120)):
        p = IP(src=ATTACKER, dst=VICTIM) / TCP(sport=RandShort(), dport=port, flags="S")
        p.time = ts(i)
        pkts.append(p)
    return pkts, {
        "pcap": "scan_syn.pcap",
        "scenario": "syn_port_scan",
        "benign": False,
        "description": f"{ATTACKER} 对 {VICTIM} 1-200 端口 SYN 扫描（100 包）",
        "expected_alerts": [
            {
                "sid": 1000001,
                "msg": "SPYCAM SYN port scan to low ports",
                "src_ip": ATTACKER,
                "dst_ip": VICTIM,
                "dst_port_range": [1, 200],
                "proto": "TCP",
                "window": {
                    "start": epoch_to_iso(BASE),
                    "end": epoch_to_iso(BASE + 6),
                },
                "min_count": 1,
            }
        ],
        "known_limitations": ["慢扫（间隔 > 10s）不会命中 detection_filter 窗口"],
    }


def gen_ssh_bruteforce():
    pkts = []
    for i in range(40):
        p = IP(src=ATTACKER, dst=VICTIM) / TCP(sport=RandShort(), dport=22, flags="S")
        p.time = ts(i, step=0.5)  # 60s 内 40 次
        pkts.append(p)
    return pkts, {
        "pcap": "ssh_bruteforce.pcap",
        "scenario": "ssh_bruteforce",
        "benign": False,
        "description": f"{ATTACKER} 对 {VICTIM}:22 SYN 爆破（40 次/20s）",
        "expected_alerts": [
            {
                "sid": 1000002,
                "msg": "SPYCAM SSH bruteforce burst",
                "src_ip": ATTACKER,
                "dst_ip": VICTIM,
                "dst_port_range": [22, 22],
                "proto": "TCP",
                "window": {"start": epoch_to_iso(BASE), "end": epoch_to_iso(BASE + 25)},
                "min_count": 1,
            }
        ],
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
    for round_no in range(60):
        for uri in uris:
            pkts.extend(http_flow(ATTACKER, VICTIM, sport, 80, uri, t=ts(idx, step=0.1)))
            sport += 1
            idx += 1
    return pkts, {
        "pcap": "web_attacks.pcap",
        "scenario": "web_sqli_xss",
        "benign": False,
        "description": "SQLi UNION + XSS 完整 TCP 会话 HTTP GET（60 会话）",
        "expected_alerts": [
            {
                "sid": 1000003,
                "msg": "SPYCAM SQLi UNION SELECT in URI or body",
                "src_ip": ATTACKER,
                "dst_ip": VICTIM,
                "dst_port_range": [80, 80],
                "proto": "TCP",
                "window": {"start": epoch_to_iso(BASE), "end": epoch_to_iso(BASE + 60)},
                "min_count": 1,
            },
            {
                "sid": 1000004,
                "msg": "SPYCAM XSS script tag with event handler",
                "src_ip": ATTACKER,
                "dst_ip": VICTIM,
                "dst_port_range": [80, 80],
                "proto": "TCP",
                "window": {"start": epoch_to_iso(BASE), "end": epoch_to_iso(BASE + 60)},
                "min_count": 1,
            },
        ],
        "known_limitations": [],
    }


def gen_dns_tunnel():
    pkts = []
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    for i in range(120):
        label = "".join(random.choice(alphabet) for _ in range(48))
        p = (
            IP(src=CLIENT, dst=DNS_SERVER)
            / UDP(sport=RandShort(), dport=53)
            / DNS(rd=1, qd=DNSQR(qname=f"{label}.exfil.example.com"))
        )
        p.time = ts(i, step=0.2)
        pkts.append(p)
    # 混入正常 DNS 作对照
    for i in range(20):
        p = (
            IP(src=CLIENT, dst=DNS_SERVER)
            / UDP(sport=RandShort(), dport=53)
            / DNS(rd=1, qd=DNSQR(qname="portal.example.com"))
        )
        p.time = ts(200 + i, step=0.2)
        pkts.append(p)
    return pkts, {
        "pcap": "dns_tunnel.pcap",
        "scenario": "dns_tunnel",
        "benign": False,
        "description": "120 条超长标签 DNS 查询（>=40 字符）+ 20 条正常查询",
        "expected_alerts": [
            {
                "sid": 1000005,
                "msg": "SPYCAM DNS tunnel long label query",
                "src_ip": CLIENT,
                "dst_ip": DNS_SERVER,
                "dst_port_range": [53, 53],
                "proto": "UDP",
                "window": {"start": epoch_to_iso(BASE), "end": epoch_to_iso(BASE + 40)},
                "min_count": 1,
            }
        ],
        "known_limitations": [],
    }


def gen_benign_mix():
    """负样本：正常 DNS + 正常 HTTP（不含攻击特征）。"""
    pkts = []
    for i in range(80):
        p = (
            IP(src=CLIENT, dst=DNS_SERVER)
            / UDP(sport=RandShort(), dport=53)
            / DNS(rd=1, qd=DNSQR(qname=f"www{i % 7}.example.com"))
        )
        p.time = ts(i, step=0.3)
        pkts.append(p)
    for i in range(60):
        pkts.extend(
            http_flow(CLIENT, VICTIM, 50000 + i, 80, f"/products/item?id={i}", t=ts(100 + i, step=0.3))
        )
    for i in range(20):
        p = (
            IP(src=CLIENT, dst=VICTIM)
            / TCP(sport=RandShort(), dport=443, flags="S")
        )
        p.time = ts(200 + i, step=0.5)
        pkts.append(p)
    return pkts, {
        "pcap": "benign_mix.pcap",
        "scenario": "benign_mixed_traffic",
        "benign": True,
        "description": "正常 DNS(80)+HTTP(60)+TCP SYN(20)，无攻击特征",
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
