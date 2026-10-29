---
description: "Use when writing Suricata rules, configuring suricata.yaml, building the engine-agent, or generating attack-scenario pcaps with Scapy. Covers sid conventions, metadata for incident staging, and reproducible data generation."
applyTo: ["rules/**", "suricata/**", "data/**"]
---
# Suricata 规则与数据生成规范

- 自定义规则 `sid` 从 `1000001` 起连续分配；每条规则单行；仓库内规则 ≥5 条（M2）
- 每条规则 `metadata` 必须包含 `stage`（recon/bruteforce/exploit/c2/exfil）、`mitre_tactic`、`mitre_technique`——事件串联（S3）与 ATT&CK 映射（C3）依赖它，不许省略
- 规则文件生成：先写临时文件再原子重命名到 `rules-active`；路径由服务端拼接，绝不接受调用方传入路径；改动必须先过 `suricata -T`
- eve.json 消费按行读取 JSON；`event_type` 分发处理，未识别类型只计数不报错
- `suricata.yaml` 启用 `stats` 事件（间隔 10s），供引擎可观测（S6）读取丢包与规则加载耗时
- `data/` 场景生成脚本：固定随机种子 + 固定时间戳，单 pcap 1k–50k 包，保证 ground truth 时间窗可复现（评测口径见需求梳理 §5）
- 每个场景 pcap 必须先写 `ground_truth.json` 再跑检测（先写预期，后测）
