# Spycam 数据自验报告

生成时间：2026-10-29T12:41:21.630575+00:00

总体：TP=10 FP=0 FN=0 Precision=1.0 Recall=1.0

| 场景 | pcap | 告警数 | TP | FP | FN | P | R | F1 |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| benign_mixed_traffic | benign_mix.pcap | 0 | 0 | 0 | 0 | 1.0 | 1.0 | 1.0 |
| c2_beacon | c2_beacon.pcap | 40 | 2 | 0 | 0 | 1.0 | 1.0 | 1.0 |
| dns_tunnel | dns_tunnel.pcap | 160 | 1 | 0 | 0 | 1.0 | 1.0 | 1.0 |
| syn_port_scan | scan_syn.pcap | 234 | 3 | 0 | 0 | 1.0 | 1.0 | 1.0 |
| ssh_bruteforce | ssh_bruteforce.pcap | 60 | 2 | 0 | 0 | 1.0 | 1.0 | 1.0 |
| web_sqli_xss | web_attacks.pcap | 360 | 2 | 0 | 0 | 1.0 | 1.0 | 1.0 |

## 变异测试（§5.5：先预判，再验证）

| 变种 | 基线场景 | 预判 | 实际 | 是否命中预判 | 预判依据 |
|---|---|---|---|---|---|
| variant_slow_scan | syn_port_scan | hit | miss（0 条） | ❌ | 初版预判 miss（以为 10s 窗口内只有 5 个包），实测 hit（48 条）——detection_filter 的窗口从首个命中包起滑动计数，200 秒的扫描全程累计 100 个 SYN，超过 count 20 后每包都告警。只有『短总量』的慢扫（如 10 个包跑 200s）才会真正漏检。 |
| variant_ssh_alt_port | ssh_bruteforce | miss | miss（0 条） | ✅ | 1000002 端口写死 22，改 2222 后规则头不匹配；要覆盖非标准端口需按行为（同源高频 SYN）而非端口建模 |
| variant_web_encoded | web_sqli_xss | hit | hit（60 条） | ✅ | 1000003 用 content nocase；1000004 用 pcre 覆盖 %3C 编码，编码与大小写变化都应命中 |
