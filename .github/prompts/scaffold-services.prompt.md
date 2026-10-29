---
description: "安装基础服务并搭建项目骨架：启动 Docker、创建目录结构、编写 docker-compose.yml 并拉起 postgres/redis/suricata，再生成 Go 后端与 React 前端最小骨架，直到健康检查通过。"
argument-hint: "[可选：范围调整，例如 '只起基础服务' 或 '跳过前端']"
agent: "agent"
---
# 安装基础服务 + 搭建基础骨架

按 [docs/系统架构设计.md](../../../docs/系统架构设计.md) §2、§6、§9 执行。每步有验收标准，失败先排查再继续；用户参数若为“只起基础服务”则在第 5 步后停止。

## 1. 预检

- `docker info` 探活；失败则告知用户手动启动 Docker Desktop 后重试，不要代启
- 确认 `git init` 已完成（交付物 D1 要求完整 commit 历史）

## 2. 目录与仓库基础

按架构设计 §9.2 创建：`rules/`、`backend/`、`frontend/`、`suricata/`、`data/`、`validation/`、`agent-log/`（含 4 个空 md 骨架）、`scripts/`、`.github/`。
验收：`.gitignore`（含 `.env`）、`.env.example`、`.gitattributes`（`*.sh`/`Dockerfile`/`*.yml` 强制 LF）就位；`git status` 干净。

## 3. docker-compose.yml

按架构设计 §9.1 编写：`postgres`(16.x)、`redis`(7.x)、`suricata`(7.x，可先占位)、`api`、`worker`、`web`、`validator`(tools profile)。tag 锁定；仅 `web` 发布 `127.0.0.1:8080`；pg/redis 带 healthcheck；命名卷五件套；不挂 docker.sock。
验收：`docker compose config` 无报错。

## 4. 拉起基础服务并验证

先 `docker compose up -d postgres redis`。
验收：`docker compose ps` 两服务 healthy；`docker compose exec postgres pg_isready` 通过；`docker compose exec redis redis-cli ping` 返回 PONG。

## 5. Suricata 引擎容器

编写 `suricata/Dockerfile`（基础镜像 + `engine-agent`）与 `suricata/suricata.yaml`（unix-socket 模式、eve 输出到 `eve-out`、stats 间隔 10s），放入 `rules/` 种子规则 ≥5 条（含 metadata：stage/mitre_tactic/mitre_technique）。
验收：容器内 `suricata -T` 通过（架构设计 §13 第一项待验证内容在此确认并记录结论到 agent-log/decisions.md）。

## 6. Go 后端骨架

按架构设计 §6.2 创建 module 与目录：`cmd/api`、`cmd/worker`、`cmd/engine-agent`、`internal/{config,httpapi,store,engine,realtime,observability}`、`migrations/`、`queries/`。依赖：chi、pgx、sqlc、go-redis、goose。
本期实现：配置加载、`/healthz`/`/readyz`（readyz 检查 PG+Redis）、迁移自动执行、初始账号与默认规则种子化、登录接口。其余 handler 返回 501 占位。
验收：`go build ./...`、`go vet ./...` 通过；`/readyz` 返回 200。

## 7. React 前端骨架

Vite + TS + AntD + TanStack Query + React Router；页面占位：登录、总览、告警列表、规则管理。API 客户端封装含 401 处理。ESLint 禁用 `dangerouslySetInnerHTML`。构建产物由 `web`(nginx) 服务并反代 `/api`。
验收：`npm run build` 通过；浏览器打开 `http://127.0.0.1:8080` 能看到登录页（用 open_browser_page 工具验证并截图确认）。

## 8. 端到端冒烟与收尾

`docker compose up -d` 全量启动；healthz/readyz、登录、页面可达逐项确认。
收尾：把本轮关键 prompt、决策（如镜像 tag 选择、待验证结论）写入 `agent-log/`；分阶段 git commit（保持语义化、频度符合 D1 要求）；更新 README 的启动步骤。

## 安全约束（全程生效）

见根目录 AGENTS.md「安全红线」：exec 参数数组、SQL 参数绑定、`.env` 不入库、无 `latest` 镜像、仅 web 暴露端口。
