---
description: "Use when writing or editing Go code in backend/: api, worker, engine-agent services, eve.json ingestion, PostgreSQL/Redis access, migrations, or REST handlers. Covers sqlc, chi, slog conventions and security rules."
applyTo: ["backend/**/*.go", "backend/go.mod", "backend/queries/**", "backend/migrations/**"]
---
# Go 后端规范

- 技术栈固定：chi（路由）、pgx + sqlc（PostgreSQL）、go-redis、goose 或 golang-migrate（迁移）、`log/slog` JSON 日志
- SQL 只写在 `queries/` 由 sqlc 生成；禁止 `fmt.Sprintf` 拼 SQL；排序/过滤字段在服务端用白名单 map 映射
- 配置全部来自环境变量，启动时校验缺失项并 fail fast；日志带 `request_id`/`task_id`/`sid` 字段
- worker 批量入库用 `CopyFrom` 或批量 upsert；幂等靠 `UNIQUE(task_id, dedup_key)` + `ON CONFLICT DO NOTHING`，成功后 `XACK`
- eve.json 按行解析：单行失败记日志并计数后跳过，不中断任务
- 调用 Suricata 一律走 `internal/engine` 的 engine-agent 客户端（内部 HTTP + 共享 token）；`exec.Command` 只用参数数组，禁止 `sh -c`
- 错误用 `%w` 包装携带上下文；handler 返回统一结构的错误 JSON，不泄露内部路径
- 密码 argon2id；会话存 Redis；Cookie `HttpOnly` + `SameSite=Strict`，非 GET 请求校验自定义头防 CSRF
- 每个 eve `event_type` 映射器、聚合逻辑、规则文件生成都要有表驱动测试
