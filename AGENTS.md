# AGENTS.md — Spycam 项目代理指南

流量威胁检测系统（应届招聘动手考题，48 小时个人赛）：Suricata IDS → eve.json 采集 → PostgreSQL + Redis → Go 后端 API → React 前端，Docker Compose 部署。

## 必读文档（动工前先读）

- [docs/需求梳理.md](docs/需求梳理.md) — 需求、MoSCoW、验收口径、评分规则；需求唯一来源
- [docs/系统架构设计.md](docs/系统架构设计.md) — 服务划分、数据模型、API 设计、安全设计；实施方案
- 两文档冲突时以需求梳理为准；发现冲突要提出，不要静默选边

## 当前状态

- 仅完成文档，代码骨架尚未创建；目标目录结构见架构设计 §9.2，不要发明新的顶层目录
- 镜像未构建、服务未起过；架构设计 §13 的待验证事项需要在最小闭环时用真实环境确认

## 环境（Windows，注意）

- Docker CLI 29.6.2 + Compose v5.3.1 已安装，但 **Docker Desktop 守护进程经常未运行**：任何 compose 命令前先 `docker info` 探活，失败则提示用户手动启动 Docker Desktop，不要尝试提权代启
- PowerShell 5.1：含中文的 `.ps1` 必须保存为 UTF-8 带 BOM，否则中文乱码甚至报假的括号不匹配语法错误；原生命令参数里的内层双引号会被剥掉，复杂参数改写入临时文件传递
- 仓库通过 `.gitattributes` 对 `*.sh`、`Dockerfile`、`*.yml` 强制 LF，避免 Windows 换行符破坏容器内脚本

## 命令（骨架建立后生效）

- `docker compose up -d` — 启动全部服务；仅 `web` 暴露 `127.0.0.1:8080`
- `docker compose --profile tools run --rm validator` — 数据自验（即 `make validate` 的等价物）；Windows 无 make 时用 `scripts/` 下的 PowerShell 包装
- 后端测试：`go test ./...`（backend 目录内）

## 安全红线（对应 M7，违反即返工）

- `exec.Command` 只用参数数组；禁止 `sh -c` 与任何字符串拼接命令
- SQL 一律参数绑定（sqlc/pgx）；排序与过滤字段走服务端白名单，不透传前端
- 前端禁止 `dangerouslySetInnerHTML`；payload、域名、UA 等流量数据只作文本渲染
- 密钥只经环境变量注入；`.env` 不进 git，只提交 `.env.example`
- 不挂载 `docker.sock`；除 `web` 外任何服务不发布端口
- 镜像 tag 锁定具体版本，禁止 `latest`；新增依赖先确认用途与许可证

## Agent 协作记录（评分项 D5，务必维护）

每次关键决策、AI 引入的 bug、有效的 prompt，要同步沉淀到 `agent-log/`（`prompts.md`、`decisions.md`、`bugs.md`、`review.md`），格式要求见需求梳理 §6。这是评分项，不是可选文档；`bugs.md` 为空或写“没有 bug”会被判为红旗。
