# AI 生成代码审查清单

> 要求见需求梳理 §6：审查清单覆盖输入校验、SQL 注入、命令注入、路径穿越、密钥硬编码、依赖漏洞。

## 审查记录

| 日期 | 审查对象 | 检查项 | 结论 | 修复 |
|---|---|---|---|---|
| 2026-10-29 | `httpapi/data_handlers.go`（pcap 上传） | 输入校验/路径穿越 | ✅ 原始文件名只作展示（`filepath.Base` 清洗），存储名服务端生成 UUID；魔数校验 pcap/pcapng 4 字节头；64MB 大小上限 | — |
| 2026-10-29 | `engine/agent.go`（replay 接口） | 命令注入/路径穿越 | ✅ 只接受 task_id/pcap_id 且强制 UUID 格式校验，路径由 agent 内部拼接；`exec.Command` 全部参数数组，无 `sh -c` | — |
| 2026-10-29 | 全部 SQL（sqlc 生成） | SQL 注入 | ✅ 查询全部由 sqlc 从 `queries/*.sql` 生成参数绑定；排序/过滤字段服务端白名单（`pageParams` 限制 limit≤500） | — |
| 2026-10-29 | `store/migrate.go` + goose | SQL 注入（迁移文件来源） | ✅ 迁移文件进仓库受版本控制，不接受运行时输入的 SQL | — |
| 2026-10-29 | `auth/auth.go` + `config` | 密钥硬编码 | ✅ argon2id 哈希（m=19456,t=1,p=2；勘误：此处原写 t=2，实际计算一直是 t=1，PHC 串标签已于 10-30 改为与计算一致）；`SEED_ADMIN_PASSWORD`/`ENGINE_AGENT_TOKEN`/`DATABASE_URL` 全走环境变量；`.env` 在 `.gitignore` 且仓库只有 `.env.example`；DB 密码 compose 里 `:?` 强制要求注入 | 10-30 修正标签 |
| 2026-10-29 | `frontend/nginx.conf` + 前端 | XSS | ✅ 全部流量数据（payload/URI/UA/原始 JSON）纯文本渲染；`grep dangerouslySetInnerHTML` 零命中；CSP `script-src 'self'`；告警导出文件名走 `Content-Disposition` 不进 HTML | — |
| 2026-10-29 | `frontend/package.json` | 依赖漏洞 | ✅ `npm audit` 从 5（4 high）清零：react-router-dom/vite/esbuild/@vitejs/plugin-react 升级 | 已修复 |
| 2026-10-29 | Go 依赖（go.mod） | 依赖漏洞 | ⚠️ 初审未运行 `govulncheck`；后续在容器内执行发现 15 个可达漏洞，已升级标准库与依赖并复扫为 0 | Bug-25 |
| 2026-10-29 | `httpapi/forensics_handlers.go`（取证导出；勘误：原误写为 validation_handlers.go） | 路径穿越/越权 | ✅ 从 DB UUID 重新拼路径，**不信任** `pcaps.stored_path` 列（防历史脏数据越权读）；analyst+ 角色门控 | — |
| 2026-10-29 | `suricata/entrypoint.sh` + Dockerfile | 容器暴露面 | ✅ 仅 `web` 发布 `127.0.0.1:8080`；无 docker.sock 挂载；engine-agent 仅内部网络 + token；非 root（uid 10001）运行 | — |
| 2026-10-30 | 复审：上方 10-29「全部 SQL」一行 | 审查结论真实性 | ❌ 当时写“排序/过滤字段服务端白名单”，实际告警列表**没有任何服务端排序/过滤**，只有 limit/offset——审查结论照抄了架构设计的意图而非核对代码 | `parseAlertQuery`：sort 键走 `alertSortKeys` 白名单映射为 SQL CASE 分支，过滤值逐项类型校验（UUID/IP/枚举/RFC3339），全部 sqlc 参数绑定；表驱动单测覆盖非法输入 |
| 2026-10-30 | `httpapi/server.go` + `auth/auth.go` | CSRF / 爆破 | ❌ 前端发 `X-Requested-With`，但后端从未校验；登录无失败计数 | `requireCSRFHeader` 中间件拦截 /api/ 下全部非 GET/HEAD/OPTIONS（含登录，防登录 CSRF）；Redis 按用户名+clientIP 计数，15 分钟内 5 次失败锁定，并加用户名总计 50 次上限；单测覆盖 |
| 2026-10-30 | `httpapi/rule_create_handler.go` | 规则内容注入 | ❌ `src_ip/ports/mitre_*` 未校验直接拼进规则体；`msg` 的 ASCII 回退保留了 `"` `;` `\`，可提前闭合 msg 注入 `pcre` 等关键字 | 地址/端口/metadata 正则白名单 + msg 剥离三种元字符；创建失败回滚时补做规则文件重生成（原先只改 DB，坏规则留在文件里使之后每次重载都失败） |
| 2026-10-30 | `httpapi/server.go` `clientIP` | 日志伪造 | ⚠️ AI 初稿取 X-Forwarded-For 最左值写审计；nginx 用 `$proxy_add_x_forwarded_for` 是**追加**，最左值可被客户端伪造 | 改取最右值（nginx 写入的真实对端），单测覆盖伪造场景 |
| 2026-10-30 | `pages/AuditLog.tsx` | XSS | ✅ 审计详情含用户输入（规则原文、处置备注），`JSON.stringify` 后以文本节点渲染，无 `dangerouslySetInnerHTML` | — |
| 2026-10-30 | `pcapslice/pcapslice.go`（取证切片解析器） | 不可信输入解析 / DoS | ⚠️ 解析用户上传的 pcap：单包长度字段可被伪造成 4GB 触发超大分配 | 单包上限 256KiB，超限直接报错返回 422；末尾不完整记录（抓包中断）丢弃该条并以 `X-Source-Truncated` 声明；只认经典 pcap 魔数与 8 种链路类型，其余回退整文件；`scope` 仅 `flow`/`hosts` 白名单；导出写审计 `pcap.export`。表驱动测试 + 仓库真实 Scapy pcap 回归 |
| 2026-10-30 | `engine/agent.go` `handleValidate` | 命令注入 / 临时文件 | ✅ 候选规则只写入 `os.MkdirTemp` 私有目录（0600）并以参数数组传 `-S`，无 shell；请求体 256KiB 上限；错误详情剥离临时路径 | — |

## 已知边界（如实声明，详见 README）

- `COOKIE_SECURE` 默认关闭以兼容本地 HTTP；HTTPS 反代部署必须开启
- Suricata 解析不可信 pcap 存在引擎自身漏洞风险，靠容器隔离缓解
- Suricata 仍会解析不可信 pcap；隔离容器不能替代引擎补丁与输入来源控制，需持续更新固定版本镜像
- 取证切片只支持经典 pcap；pcapng 回退整文件并以 `X-Filter-Applied: false` 声明
