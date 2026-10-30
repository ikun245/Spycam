---
description: "Use when editing docker-compose files, Dockerfiles, or defining services for Suricata, PostgreSQL, Redis, nginx, api, worker, or validator. Covers image pinning, healthchecks, port exposure, volumes, and Windows-specific pitfalls."
applyTo: ["**/docker-compose*.yml", "**/docker-compose*.yaml", "**/Dockerfile*", "**/.dockerignore"]
---
# 容器与 Compose 规范

- 镜像 tag 锁定具体版本（如 `postgres:16.x`、`redis:7.x`、Suricata `7.x`），禁止 `latest`；重要镜像在 README 记录 digest
- 端口：仅 `web` 发布端口，默认绑定 `127.0.0.1:28765`（容器内也监听 28765）；禁止使用 80/8080 等常用端口（用户要求）。`postgres`/`redis`/`api`/`worker`/`suricata` 一律不发布端口。临时调试用 compose `profiles`（如 `debug`）按需开放，不进默认配置
- `postgres` 与 `redis` 必须配置 healthcheck；`api`/`worker` 通过 `depends_on.condition: service_healthy` 等待
- 命名卷：`pgdata`、`redisdata`、`pcaps`、`eve-out`、`rules-active`。`eve-out` **禁止用 bind mount**（Windows Docker Desktop 文件变更通知不可靠）
- `pcaps` 与 `rules-active` 对 `suricata` 只读挂载（`:ro`），对 `api` 可写
- 禁止挂载 `docker.sock`；Suricata 离线回放无需 `NET_ADMIN`/`NET_RAW`，在线抓包（加分项）放独立 `live` profile 再加
- 容器命令使用 exec 形式（JSON 数组），不用 shell 形式
- 造数据与评测走 `tools` profile 的 `validator` 一次性容器，不要求宿主机装 Python/Scapy
- 迁移与种子数据由 `api` 启动时自动执行，不允许需要手工步骤的启动流程（M6 要求干净机器 ≤15 分钟）
