# Spycam — 流量威胁检测系统

基于 Suricata IDS 的流量威胁检测系统（48 小时动手考题）：pcap 回放 → Suricata 检测 → eve.json 采集归一化 → PostgreSQL + Redis → Go API → React 界面。

## 架构

```text
浏览器 ── web(nginx, 唯一对外 127.0.0.1:8080)
            └─ /api 反代 ── api(Go: REST+SSE+鉴权) ── PostgreSQL(事实源)
                                  │                      Redis(队列/流/会话/PubSub)
            worker(Go: 队列消费/eve采集/聚合/事件串联)
                  └─ engine-agent(内部HTTP+token) ── Suricata(unix-socket) ── pcaps/rules-active(只读卷)
validator(tools profile: Scapy 造数 + 走公开API评测)
```

- [需求梳理](docs/需求梳理.md) — 需求唯一来源（MoSCoW、验收口径、评分规则）
- [系统架构设计](docs/系统架构设计.md) — 服务划分、数据模型、API、安全设计
- [Agent 协作记录](agent-log/) — prompts / decisions / bugs(10+) / review 审查清单（评分项 D5）

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

## 功能覆盖（对照需求 MoSCoW）

| 需求 | 实现 | 验证方式 |
|---|---|---|
| M1 pcap 回放 | 上传（魔数校验+UUID 存储）→ 任务队列 → agent 调 Suricata `pcap-file` | 页面「数据与回放」 |
| M2 IDS+自定义规则 | 6 条规则（含 stage/ATT&CK metadata），`suricata -T` 通过 | `docker compose exec suricata suricata -T ...` |
| M3 采集归一化 | alert/flow/dns/http/tls/stats 落库，去重键幂等 | 数据库直查 |
| M4 Web 界面 | 告警列表/详情/总览/规则管理 + 聚合/事件/引擎页（运营功能；自验报告为纯文件，不进界面） | 浏览器 |
| M5 数据自验 | 5 场景 + ground truth 先写后测 + 一条命令评测，**P=1.0 R=1.0 零误报**；报告为纯文件产物（report.json/md），不进产品界面 | `--profile tools run validator` |
| M6 可复现 | 镜像 tag 锁定、迁移种子自动执行、干净机器 compose up | 面试官复跑 |
| M7 自身安全 | 参数数组 exec、sqlc 参数绑定、UUID 路径、CSP、非 root 容器、无 sock 挂载 | agent-log/review.md |
| S1 聚合 | sid+五元组+N 秒窗口分桶，hit_count 累计 | 「聚合处置」页 |
| S2 处置流转 | new→confirmed/false_positive/ignored + 审计表 | 「聚合处置」页操作 |
| S3 事件串联 | 同源 IP 时间窗归事件，阶段链 recon→…→exfil | 「攻击事件」页 |
| S4 取证导出 | `GET /alerts/{id}/pcap`（UUID 拼路径） | API |
| S5 登录角色 | viewer/analyst/admin（argon2id + Redis 会话） | 登录 |
| S6 引擎可观测 | stats 事件入库：规则加载耗时/内核丢包 | 「引擎状态」页 |
| C1 实时推送 | SSE（worker PUBLISH → api → EventSource） | 告警页自动刷新 |
| §5.5 变异测试 | 3 变种先预判后验证，3/3 命中 | 自验报告页 |

## 当前已知缺陷（如实声明）

- 取证导出回传整段 pcap，按时间/五元组切片未实现（响应头已声明过滤条件）
- S3 事件串联的 gap 与 S1 窗口为固定/环境变量值，未做界面配置
- `govulncheck` 未执行（宿主 32 位 Go 编译受限）；npm audit 已清零
- 本地演示为 HTTP，Cookie `Secure` 留生产配置
- C2 规则生成器、C4 LLM 研判、C5 并发回放未实现（C1/C3 部分达成：SSE+ATT&CK 列）
- jasonish/suricata 基础镜像声明 VOLUME：更新内置规则后需 `--renew-anon-volumes`（见 agent-log/bugs.md Bug-5）

## 目录

```text
backend/     Go 后端（api/worker/engine-agent，单元测试覆盖 eve/aggregate/rules）
frontend/    React 前端（Vite+AntD+recharts，8 个页面，仅运营功能）
suricata/    引擎镜像（suricata.yaml + engine-agent + entrypoint）
rules/       自定义 Suricata 规则（seed 副本在 backend/seed-rules/）
validation/  场景生成 + ground truth + 评测器（out/ 为报告产物）
data/        冒烟 pcap 与生成脚本
agent-log/   Agent 协作记录（评分项 D5）
docs/        需求与架构文档
scripts/     辅助脚本（S1/S2 冒烟等）
```
