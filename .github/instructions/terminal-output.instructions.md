---
description: "Use when running any terminal command that may exceed ~30 seconds: docker pull/build/compose, go install/build/test, npm install, downloads, validation scripts. Covers real-time log streaming, Tee-Object, and forbidding fully-buffered silent output."
---
# 终端命令输出规范（用户硬性要求）

用户明确要求：**长时间命令必须实时可见日志**——要么直接滚动输出，要么写入 log 文件实时追加。不允许静默跑完后才一次性给结果。

## 硬性规则

- **禁止**对长命令使用 `2>&1 | Select-Object -Last N | Out-String` 之类全缓冲管道：它在结束前一行都不输出（已多次导致用户以为卡死而取消）
- 原生命令（docker/go/npm/git 等）**不加 PS 管道直接跑**，原生输出本就实时滚动到终端；需要留档时用 `... 2>&1 | Tee-Object <log>` 同时滚动+落盘
- 预计超过 ~2 分钟的任务用 run_in_terminal 的 async 模式启动，随后用 get_terminal_output **周期性读取并把关键进度转述给用户**，不要等到完成才说话
- 启动长任务前先用一句话说明：预计耗时、输出长什么样、多久汇报进度
- 下载/安装前先选最快路径（本机已有镜像、国内代理 GOPROXY=goproxy.cn、Docker Hub 直拉），并说明为什么这条路快
- PS 5.1 下不要用 `2>&1` 混合 stderr 到成功流做判断（会包装成 ErrorRecord 噪声）；要判断成败用 `$LASTEXITCODE` 或 try/catch

## 反例（本项目实际踩过）

- ❌ `docker compose build 2>&1 | Select-Object -Last 20 | Out-String` → 构建数分钟终端零输出，用户取消
- ❌ `go install sqlc@v1.27.0`（32 位 Go 编译巨型依赖树）→ 数分钟无输出，用户取消
- ✅ `docker pull sqlc/sqlc:1.27.0`（裸命令，进度条实时滚动）
- ✅ `go build ./... 2>&1 | Tee-Object ..\.tmp\build.log`（实时可见 + 落盘）
