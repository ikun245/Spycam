# AI 生成代码审查清单

> 要求见需求梳理 §6：审查清单覆盖输入校验、SQL 注入、命令注入、路径穿越、密钥硬编码、依赖漏洞。

## 审查记录

| 日期 | 审查对象 | 检查项 | 结论 | 修复 |
|---|---|---|---|---|
| 2026-10-29 | `httpapi/data_handlers.go`（pcap 上传） | 输入校验/路径穿越 | ✅ 原始文件名只作展示（`filepath.Base` 清洗），存储名服务端生成 UUID；魔数校验 pcap/pcapng 4 字节头；64MB 大小上限 | — |
| 2026-10-29 | `engine/agent.go`（replay 接口） | 命令注入/路径穿越 | ✅ 只接受 task_id/pcap_id 且强制 UUID 格式校验，路径由 agent 内部拼接；`exec.Command` 全部参数数组，无 `sh -c` | — |
| 2026-10-29 | 全部 SQL（sqlc 生成） | SQL 注入 | ✅ 查询全部由 sqlc 从 `queries/*.sql` 生成参数绑定；排序/过滤字段服务端白名单（`pageParams` 限制 limit≤500） | — |
| 2026-10-29 | `store/migrate.go` + goose | SQL 注入（迁移文件来源） | ✅ 迁移文件进仓库受版本控制，不接受运行时输入的 SQL | — |
| 2026-10-29 | `auth/auth.go` + `config` | 密钥硬编码 | ✅ argon2id 哈希（m=19456,t=2,p=2）；`SEED_ADMIN_PASSWORD`/`ENGINE_AGENT_TOKEN`/`DATABASE_URL` 全走环境变量；`.env` 在 `.gitignore` 且仓库只有 `.env.example`；DB 密码 compose 里 `:?` 强制要求注入 | — |
| 2026-10-29 | `frontend/nginx.conf` + 前端 | XSS | ✅ 全部流量数据（payload/URI/UA/原始 JSON）纯文本渲染；`grep dangerouslySetInnerHTML` 零命中；CSP `script-src 'self'`；告警导出文件名走 `Content-Disposition` 不进 HTML | — |
| 2026-10-29 | `frontend/package.json` | 依赖漏洞 | ✅ `npm audit` 从 5（4 high）清零：react-router-dom/vite/esbuild/@vitejs/plugin-react 升级 | 已修复 |
| 2026-10-29 | Go 依赖（go.mod） | 依赖漏洞 | ⚠️ `govulncheck` 未跑（宿主 32 位 Go 编译受限）；依赖仅 chi/pgx/goose/go-redis/crypto，均为主流维护库；列入待办 | 待办 |
| 2026-10-29 | `httpapi/validation_handlers.go`（取证导出） | 路径穿越/越权 | ✅ 从 DB UUID 重新拼路径，**不信任** `pcaps.stored_path` 列（防历史脏数据越权读）；analyst+ 角色门控 | — |
| 2026-10-29 | `suricata/entrypoint.sh` + Dockerfile | 容器暴露面 | ✅ 仅 `web` 发布 `127.0.0.1:8080`；无 docker.sock 挂载；engine-agent 仅内部网络 + token；非 root（uid 10001）运行 | — |

## 已知边界（如实声明，详见 README）

- 本地演示为 HTTP：Cookie `Secure` 属性留部署环境配置
- Suricata 解析不可信 pcap 存在引擎自身漏洞风险，靠容器隔离缓解
- `govulncheck` 未执行（见上）
- 取证导出当前回传整段 pcap（按时间/五元组切片未实现），响应头已声明过滤条件
