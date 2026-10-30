# Spycam — 流量威胁检测系统

基于 Suricata IDS 的流量威胁检测系统：pcap 回放 / 网卡实时抓包 → Suricata 检测 → eve.json 采集归一化 → PostgreSQL + Redis → Go API → React 界面。

## 架构

```text
浏览器 ── web(nginx, 唯一对外 127.0.0.1:8080)
            └─ /api 反代 ── api(Go: REST+SSE+鉴权) ── PostgreSQL(事实源)
                                  │                      Redis(队列/流/会话/PubSub)
            worker(Go: 队列消费/eve采集/聚合/事件串联)
                  └─ engine-agent(内部HTTP+token) ── Suricata(unix-socket) ── pcaps/rules-active(只读卷)
                                    └─ live tailer ── eve-out/live/eve.json ── suricata-live(af-packet, live profile)validator(tools profile: Scapy 造数 + 走公开API评测)
```

- [需求梳理](docs/需求梳理.md) — 需求唯一来源（MoSCoW、验收口径、评分规则）
- [系统架构设计](docs/系统架构设计.md) — 服务划分、数据模型、API、安全设计
- [自验报告](docs/自验报告.md) — 一页纸：场景明细、误报归因、引擎行为发现、未解决问题
- [Agent 协作记录](agent-log/) — prompts / decisions / bugs(10+) / review 审查清单（评分项 D5）

## 设计取舍

| 决策点 | 备选 | 取舍与理由 |
|---|---|---|
| 引擎回放方式 | 每任务起 `suricata -r` 进程 vs **常驻 unix-socket** | 选常驻：规则热重载不重启引擎；每任务独立输出目录天然隔离；不挂 docker.sock |
| 规则管理粒度 | 只做启停（需求 M4 下限） vs **UI 内创建自定义规则** | 选后者：新攻击手法无需改代码/重启引擎，这才是可运营产品（对标 Scirius）|
| 报告形态 | 报告页进产品菜单 vs **纯文件产物** | 选文件：需求 §5.3 要求的是 report.json/md 文件；界面只放运营功能，报告是工程产物 |
| 聚合策略 | 直接改写告警 vs **原始全保留 + 独立分组表** | 选后者：评测走原始视图不受聚合影响；分组仅是 UI/处置视图，可随时重算 |
| 时间口径 | 墙钟过滤 vs ** pcap 内时间可选过滤** | 离线回放的告警时间是 pcap 内时间，墙钟过滤会让图表永远为空——统计默认全量 |
| 造数据方式 | 下载公开 pcap vs **Scapy 生成多源拓扑** | 选生成：固定种子可复现、ground truth 先写后测、能覆盖分布式与负样本场景 |
| 数据库分工 | 全塞 Redis vs **PG 事实源 + Redis 可重建层** | 选后者：Redis 丢了只影响实时性不影响告警数据；队列/聚合窗/会话都可从 PG 恢复 |

完整决策记录（含 AI 建议 vs 实际判断）见 [agent-log/decisions.md](agent-log/decisions.md)。

## 快速启动

```powershell
# 0. 启动 Docker Desktop，确认 docker info 正常
# 1. 准备环境变量（修改默认密码与 token）
Copy-Item .env.example .env
# 2. 一键启动（首次构建约 5-10 分钟）
docker compose up -d
# 3. 访问 http://127.0.0.1:8080 （默认账号见 .env 的 SEED_ADMIN_*）
```

数据自验（一条命令，产出 `validation/out/report.json|md`）：

```powershell
docker compose --profile tools run --rm validator
```

实时抓包（C1，可选 `live` profile）：

```powershell
# 在 .env 中设置 LIVE_IFACE（默认 eth0）、可选 LIVE_HOME_NET（如 [10.0.0.0/8]）
docker compose --profile live up -d
```

- 独立 Suricata 实例以 af-packet 模式监听 `LIVE_IFACE`，worker 每秒尾随 `eve-out/live/eve.json` 入库，前端经 SSE 收到 `live` 事件即刷新；实测包→入库 0.2–0.5s
- 规则启停对实时引擎同样生效（容器内 watcher 检测 rules-active 变化后发 USR2 热重载）
- 部署到真实服务器：在 Linux 主机上运行，`LIVE_IFACE` 设为业务网卡；监测其他主机时把交换机 SPAN/镜像口接到该网卡，或远程 `tcpdump -w -` 经 ssh 转发后用回放链路分析
- Docker Desktop（Windows/macOS）的 host 网络是虚拟机网卡，只能看到 VM 自身流量（实测可捕获容器外联 HTTP 并触发 C2 心跳规则），看不到宿主局域网；本机演示可设 `LIVE_NETWORK_MODE=bridge`

## 功能覆盖（对照需求 MoSCoW）

| 需求 | 实现 | 验证方式 |
|---|---|---|
| M1 pcap 回放 | 上传（魔数校验+UUID 存储）→ 任务队列 → agent 调 Suricata `pcap-file` | 页面「数据与回放」 |
| M2 IDS+自定义规则 | 6 条规则（含 stage/ATT&CK metadata），`suricata -T` 通过 | `docker compose exec suricata suricata -T ...` |
| M3 采集归一化 | alert/flow/dns/http/tls/stats 落库，去重键幂等 | 数据库直查 |
| M4 Web 界面 | 告警列表（服务端过滤：时间/威胁等级/协议/处置状态/sid/IP/任务；服务端排序白名单；服务端分页）/详情/总览/规则管理（启停/新建经 rules-active 热重载，改规则→重放告警数随之变化已实测） + 聚合/事件/引擎/审计页（运营功能；自验报告为纯文件，不进界面） | 浏览器 |
| M5 数据自验 | 6 场景（含 C2 心跳）共 5205 包 + ground truth 先写后测 + 一条命令评测；FP 按告警逐条严格判定并输出告警级精确率。旧版“P=1.0 零误报”因口径过宽已撤回，严格口径数字以重跑后的 report.md 为准（见自验报告“口径修订”） | `--profile tools run validator` |
| M6 可复现 | 镜像 tag 锁定、迁移种子自动执行、干净机器 compose up | 面试官复跑 |
| M7 自身安全 | 参数数组 exec、sqlc 参数绑定、UUID 路径、CSP、非 root 容器、无 sock 挂载；非 GET 请求校验 `X-Requested-With` 头（CSRF）；同一用户名 15 分钟内失败 5 次锁定；自定义规则头/metadata 字段格式白名单 | agent-log/review.md |
| S1 聚合 | sid+五元组+N 秒窗口分桶，hit_count 累计 | 「聚合处置」页 |
| S2 处置流转 | new→confirmed/false_positive/ignored，写 triage_actions + audit_log | 「聚合处置」页操作 |
| S3 事件串联 | 同源 IP 时间窗归事件，阶段链 recon→…→exfil | 「攻击事件」页 |
| S4 取证导出 | `GET /alerts/{id}/pcap`（UUID 拼路径） | API |
| S5 登录角色 | viewer/analyst/admin（argon2id + Redis 会话）；登录/规则变更/处置/上传/回放全部写审计日志，admin 可在「审计日志」页查看；规则每次成功生效写 rule_revisions 版本快照 | 登录、「审计日志」页 |
| S6 引擎可观测 | stats 事件按 Suricata 7 实际字段入库：已加载/失败规则数、累计告警、运行时长、内核丢包（离线 pcap 模式无此指标，显示“不适用”）；规则校验+重载耗时由 engine-agent 记录 | 「引擎状态」页 |
| C1 实时抓包+推送 | `live` profile：af-packet 抓包 → worker 尾随 eve.json 秒级入库 → SSE `live` 事件；回放任务另有 SSE：worker 在任务开始/完成/失败时 PUBLISH → api 订阅 → 前端 EventSource 失效重拉相关列表并弹通知；断线自动重连，轮询保留兜底 | 顶栏连接状态 + 回放完成/实时告警通知 |
| §5.5 变异测试 | 3 变种先预判后验证，2/3 预判命中（慢扫预判失误，归因见自验报告） | 自验报告 |

## 当前已知缺陷（如实声明）

- 取证导出仅支持经典 pcap 切片（双向五元组/主机对 + 告警前 5 分钟至后 1 分钟）；pcapng 回退整文件并以 `X-Filter-Applied: false` 声明，时间窗为固定值
- S3 事件串联的 gap 与 S1 窗口为固定/环境变量值，未做界面配置
- `govulncheck` 未执行（宿主 32 位 Go 编译受限）；npm audit 已清零
- 本地演示为 HTTP，Cookie `Secure` 留生产配置
- C2 规则生成器、C4 LLM 研判、C5 并发回放未实现（C3 部分达成：ATT&CK 列）
- 回放任务的推送以任务为粒度（离线模式告警在任务完成时批量入库）；实时抓包为每秒一批的 `live` 事件
- 实时抓包源没有落盘 pcap：取证切片与“重放”对其返回 409；`live/eve.json` 未做轮转，长期运行需外部 logrotate；引擎状态页的 stats 未区分实时/回放实例
- 规则构建器生成 `classtype:custom`，不在 classification.config 中，引擎加载时仅告警不报错
- 登录锁定按用户名计数，存在被他人故意触发锁定管理员账号的风险（15 分钟自动解除），未做 IP 维度限速
- 新增 sqlc 查询代码为手工编写的问题同上；本轮 `GET /rules/{sid}` 复用已有 `GetRule`，未新增查询
- 本轮新增查询的 sqlc 生成代码因宿主机 sqlc 不可用为手工按 sqlc 1.27 格式编写，需在 Docker 内 `sqlc generate` 比对（见 agent-log/decisions.md）

## 目录

```text
backend/     Go 后端（api/worker/engine-agent，单元测试覆盖 eve/aggregate/rules）
frontend/    React 前端（Vite+AntD+recharts，9 个页面，仅运营功能）
suricata/    引擎镜像（suricata.yaml + engine-agent + entrypoint）
rules/       自定义 Suricata 规则（seed 副本在 backend/seed-rules/）
validation/  场景生成 + ground truth + 评测器（out/ 为报告产物）
data/        冒烟 pcap 与生成脚本
agent-log/   Agent 协作记录（评分项 D5）
docs/        需求与架构文档
scripts/     辅助脚本（S1/S2 冒烟等）
```
