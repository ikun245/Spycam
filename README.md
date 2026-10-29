# Spycam — 流量威胁检测系统

基于 Suricata IDS 的流量威胁检测系统（48 小时动手考题）：pcap 回放 → Suricata 检测 → eve.json 采集归一化 → PostgreSQL + Redis → Go API → React 界面。

## 架构与文档

- [需求梳理](docs/需求梳理.md) — 需求唯一来源（MoSCoW、验收口径、评分规则）
- [系统架构设计](docs/系统架构设计.md) — 服务划分、数据模型、API、安全设计
- [Agent 协作记录](agent-log/) — prompts / decisions / bugs / review（评分项 D5）

## 快速启动

```powershell
# 0. 启动 Docker Desktop（Windows），确认 docker info 正常
# 1. 准备环境变量
Copy-Item .env.example .env   # 修改其中的密码与 token
# 2. 一键启动
docker compose up -d
# 3. 访问
#    http://127.0.0.1:8080  （唯一对外端口）
```

数据自验（骨架期未实现）：`docker compose --profile tools run --rm validator`

## 当前状态（骨架期）

| 模块 | 状态 |
|---|---|
| docker-compose（7 服务） | ✅ 已编写，待 Docker 环境验证 |
| Suricata 容器 + 规则（6 条） | ✅ 已编写，`suricata -T` 待容器内验证 |
| Go 后端（api / worker / engine-agent） | ✅ 骨架编译通过；数据面 handler 为 501 占位 |
| React 前端（登录 / 总览 / 告警 / 规则） | ✅ 骨架构建通过；列表页为占位 |
| eve 采集归一化、聚合、评测 | ⬜ 未实现（P0 后续） |

## 目录

```text
backend/     Go 后端（cmd/api, cmd/worker, cmd/engine-agent）
frontend/    React 前端（Vite + AntD）
suricata/    引擎镜像（suricata.yaml + engine-agent）
rules/       自定义 Suricata 规则
validation/  自验（ground truth + 评测，未实现）
data/        场景 pcap 与生成脚本（未实现）
agent-log/   Agent 协作记录（评分项）
docs/        需求与架构文档
```

## 已知缺陷

- 数据采集（eve.json → 库）、pcap 上传回放、聚合、事件串联均未实现，相关 API 返回 501
- engine-agent 的回放/校验为占位实现，unix-socket 控制协议待真机验证（架构设计 §13）
