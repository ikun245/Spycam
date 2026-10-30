# AI 引入的 Bug 记录

> 要求见需求梳理 §6：≥3 个 AI 引入的错误（幻觉 API、错字段、错 SQL、安全漏洞、编造的配置项），写清怎么发现、怎么验证、怎么修。
> ⚠️ 本文件为空或写「没有 bug」会被判为红旗。

## Bug-1：goose v3 新版 Provider API 用法错误（幻觉旧 API）

- **日期**：2026-10-29 ｜ **引入位置**：`backend/internal/store/migrate.go`
- **现象**：`go build` 报 `assignment mismatch: 1 variable but provider.Up returns 2 values`
- **原因**：AI 按 goose 旧版 `goose.Up(db, dir)` 的印象写了 `provider.Up(ctx)` 单返回值；goose v3.22 改为 Provider 模式，`Up(ctx)` 返回 `([]result.Result, error)` 两个值
- **发现方式**：`go build ./...` 编译期直接暴露
- **验证方式**：修复后 `go build ./...` 通过、`go vet ./...` 无告警
- **修复**：`if _, err := provider.Up(ctx); err != nil`（忽略结果切片，只查错误）
- **教训**：用不熟的库时先 `go doc` 确认签名，不要凭记忆写

## Bug-2：未使用 import `database/sql`

- **日期**：2026-10-29 ｜ **引入位置**：`backend/internal/store/migrate.go`
- **现象**：`"database/sql" imported and not used`
- **原因**：AI 写代码时按"标准姿势"带上了 `database/sql`，实际用 pgx `stdlib` 桥接后根本不需要
- **发现/验证**：同上，编译期暴露；删除后构建通过
- **修复**：删除该 import

## Bug-3：`fmt.Fprintf` 返回值误用

- **日期**：2026-10-29 ｜ **引入位置**：`backend/internal/auth/auth.go`
- **现象**：`assignment mismatch: 1 variable but fmt.Fprintf returns 2 values`
- **原因**：写了 `_ = fmt.Fprintf(...)`，但 `Fprintf` 返回 `(int, error)` 两个值，单 `_` 只能接一个
- **发现/验证**：编译期暴露；改为 `_, _ = fmt.Fprintf(...)` 后通过
- **教训**：Go 里丢弃多返回值要每个位置一个 `_`；同文件里 `json.NewEncoder(w).Encode(v)` 单返回值写法是对的，别混

## Bug-4：对标准库 mux 路由值做了无效类型断言

- **日期**：2026-10-29 ｜ **引入位置**：`backend/internal/httpapi/server.go`
- **现象**：`s.auth.Middleware("").(http.HandlerFunc).Wrap(...)` —— 中间件返回的是 `http.Handler`（接口），没有 `Wrap` 方法，也没有 `http.HandlerFunc` 可断言的实体
- **原因**：AI 把 chi 的 `Use()` 中间件挂载习惯带进了标准库 `ServeMux`；两者路由模型不同
- **发现方式**：`get_errors`（gopls 静态诊断）在编译前就报错
- **修复**：改为 `r.Handle("POST /api/v1/auth/logout", s.auth.Middleware("")(http.HandlerFunc(s.handleLogout)))`，中间件包裹 handler 后再注册
- **教训**：标准库 `ServeMux`（Go 1.22+ 方法模式）没有中间件概念，鉴权中间件必须显式包裹每个 handler

## Bug-5：Suricata 基础镜像 VOLUME 声明导致规则更新被匿名卷遮蔽

- **日期**：2026-10-29 ｜ **引入位置**：`suricata/Dockerfile`（构建/编排层）
- **现象**：修复 sid 1000004 规则（`http.uri` → `http.uri.raw`）并重建镜像后，容器内 `suricata -T` 仍报旧规则错误；`docker image inspect` 与 `docker inspect` 显示容器用的就是新镜像 ID，但容器内文件 md5 与镜像内不一致
- **原因**：`jasonish/suricata` 基础镜像 Dockerfile 里声明了 `VOLUME /etc/suricata`（及 /var/log/suricata 等）。容器重建时 Docker 复用同名匿名卷（旧卷内容=首次创建时的旧规则），把镜像内新文件**遮蔽**了。不是镜像没更新，也不是容器没重建
- **发现方式**：对比三处内容——宿主机源文件（新）→ 镜像内文件（新，`docker run --rm ... grep`）→ 容器内文件（旧，md5 不同）→ 检查 `.Mounts` 发现匿名卷
- **验证方式**：`docker compose up -d --force-recreate --renew-anon-volumes suricata` 后 `suricata -T` 输出 "Configuration provided was successfully loaded"
- **修复**：重建时加 `--renew-anon-volumes`；长期方案是 compose 里把 `/etc/suricata/rules` 显式挂成命名卷或只读 bind，不依赖镜像层文件
- **教训**：基于声明了 VOLUME 的镜像做改包时，改完必须 `--renew-anon-volumes`，否则"改了没生效"的表象会误导排查方向（先怀疑 build 缓存、再怀疑 compose 没重建，都是错的方向）

## Bug-6：engine-agent 状态探针泄漏 Suricata unix-socket 连接

- **日期**：2026-10-29 ｜ **引入位置**：`backend/internal/engine/agent.go`
- **现象**：`suricatasc -c uptime /var/run/suricata.socket` 一直等待；socket 文件存在、Suricata 进程正常，`readyz` 也返回 200。
- **原因**：旧 `handleStatus` 每次收到 `/readyz` 都 `net.Dial("unix", ...)`，只判断连接成功，却不关闭 `net.Conn`、也不发送控制协议消息。Suricata 控制端为这个空闲客户端等待数据，后续控制命令无法正常完成。
- **发现方式**：重启 Suricata 清空旧连接后，尚未请求 `readyz` 时 `suricatasc uptime` 立即成功；调用旧探针后会复现等待。排除 `suricatasc` 参数顺序、socket 文件缺失和 Suricata 进程退出。
- **修复**：探针使用 `net.DialTimeout` 并立即 `Close`；随后 5 次连续请求 `/api/v1/readyz` 均为 200，`suricatasc uptime` 仍返回 `OK`。
- **影响范围**：造成 unix-socket 验证假性卡死，但不是 P0 端到端链路唯一阻塞。
- **教训**：健康探针不能只“连接一下”而不关闭；readyz 返回成功也不代表 pcap 上传/回放和 eve 采集已经实现。

## Bug-7：Suricata unix-socket 控制协议三连错（版本号/换行/输出目录）

- **日期**：2026-10-29 ｜ **引入位置**：`backend/internal/engine/suricata.go`（自研协议客户端）
- **现象**：agent 调 `pcap-file` 依次报 `handshake read: EOF` → `command read: EOF` → `"output-dir does not exist"`，三个错误逐个暴露
- **原因**：AI 凭印象写协议——①握手版本写成 `0.3`，官方 suricatasc 源码（容器内 `/usr/lib/suricata/python/suricata/sc/suricatasc.py` L181-187）实为 **`0.2`**；②版本消息**不带**换行、命令消息**必须带** `\n`（`json.dumps(cmdmsg)+"\n"`），我一开始统一加了换行/统一没加；③`pcap-file` 的 output-dir 必须**已存在**，Suricata 不会自建
- **发现方式**：每轮错误体都不同（handshake read → command read → output-dir），逐个对照官方客户端源码确认
- **验证方式**：修复后 `pcap-file` 返回 `{"message":1,"return":"OK"}`，eve.json 正常产出
- **教训**：不熟悉的二进制协议**先读官方客户端源码**再实现；EOF 类错误基本等于“消息格式不符被服务端断开”

## Bug-8：eve.json 时间戳解析（两次踩坑）

- **日期**：2026-10-29 ｜ **引入位置**：`backend/internal/eve/eve.go`
- **现象**：101 行 eve 全部 skipped，错误 `parsing time "...+0000" as "...Z07:00"` 修完一次又出现
- **原因**：①Suricata 时间戳是 `2006-01-02T15:04:05.999999+0000`（数字时区），Go `time.Time` 默认按 RFC3339 解析必失败；②第一次修复只处理了预解析路径，`Event` 结构体里 `Timestamp time.Time` 带 `json:"timestamp"` 标签，第二次 `Unmarshal` 又撞同一个坑
- **修复**：预解析单独取 timestamp 字符串用 `2006-01-02T15:04:05.999999-0700` 布局解析；`Event.Timestamp` 改 `json:"-"` 由 Parse 赋值
- **验证**：`ingest done events=181 alerts=80 skipped=0`
- **教训**：结构体里任何 `time.Time` JSON 字段都是隐形 RFC3339 约束；非标时间格式必须 `json:"-"` + 手工解析

## Bug-9：pcaps 卷权限导致上传 503（storage unavailable）

- **日期**：2026-10-29 ｜ **引入位置**：`backend/Dockerfile.api`
- **现象**：上传 pcap 报 `storage unavailable`
- **原因**：api 以 uid 10001 (app) 运行，命名卷首挂属主 root，app 无写权限
- **修复**：镜像内 `RUN mkdir -p /data/pcaps && chown -R app:app /data`——命名卷首挂时继承镜像内目录属主
- **教训**：非 root 容器 + 命名卷，必须在镜像里预建挂载点并 chown，否则首挂后没有补救机会

## Bug-10：规则方向写错导致扫描不告警（零误报假象）

- **日期**：2026-10-29 ｜ **引入位置**：`rules/spycam.rules` sid 1000001/1000002
- **现象**：回放成功、flow 100 条入库，但 alerts=0——链路完全正常却没有告警
- **原因**：规则源写了 `$EXTERNAL_NET`，测试流量源 `10.0.0.66` 也在 HOME_NET(10/8) 内，源地址不匹配；真实的内网横向扫描本就该检出
- **修复**：扫描/爆破类规则源改 `any`（rev 2），重新 `suricata -T` + 回放后 80 条告警入库
- **教训**：**“没有告警”要先查规则方向再怀疑代码**；自造数据时攻击源放 EXTERNAL_NET 才符合这两条规则的原语义，或规则本身就要覆盖内网源

## Bug-11：自验 FP 口径按 sid 豁免，P=1.0 是假象

- **日期**：2026-10-30（自查发现，代码引入于 10-29） ｜ **引入位置**：`validation/run_validation.py`
- **现象**：所有场景 FP=0、P=1.0，看起来完美
- **原因**：AI 写的 FP 判定是“sid 不在本场景期望集合里才算 FP”——只要 sid 对上，五元组和时间窗完全不匹配的告警也被豁免。叠加 ground truth 抽样不全（Web 场景 3 源×3 资产×2 类攻击只写了 2 条期望，DNS 隧道 2 台终端只写了 1 台），大量真实但“不在 GT 里”的告警全被吞掉
- **修复**：FP 改为“未被任何期望匹配的告警”逐条计数；补全 Web 6 条、DNS 2 条期望；新增告警级精确率 `alert_precision` 与每场景 `matched_alert_count`
- **教训**：**评测器自身也要被评测**——完美分数先怀疑口径。判定条件里任何“豁免”分支都必须能对应到需求原文

## Bug-12：时间戳解析失败被静默跳过（被 Bug-11 掩盖）

- **日期**：2026-10-30 ｜ **引入位置**：`validation/run_validation.py`
- **现象**：离线复核时发现部分告警从未参与匹配
- **原因**：API 用 Go RFC3339Nano 输出时间，**整秒时刻不带小数位**（`...:05Z`），而解析写死 `%S.%f%z`，失败后 `except: continue` 静默跳过；由于 sid 豁免，这些告警既不算 TP 也不算 FP，问题完全不可见
- **修复**：正则解析 RFC3339Nano（0–9 位小数、Z 或 ±hh:mm）与 Suricata `+0000` 两种格式，解析失败直接抛错
- **教训**：评测脚本里的 `except: continue` 等于把错误数据从分母里删掉；**宁可崩，不要静默**

## Bug-13：S6 stats 字段映射全错，引擎页指标恒为 0/空

- **日期**：2026-10-30（自查发现） ｜ **引入位置**：`backend/internal/eve/eve.go` `Stats`
- **现象**：引擎状态页“规则加载耗时/内核丢包”永远是 0，“已加载规则”恒为空
- **原因**：AI 凭印象编了 stats 结构：`detect.alerts`（实际 `detect.alert`）、`kernel_packets.kernel_drops`（实际 `capture.kernel_drops`）、`rule_reload`（Suricata 根本没有这个字段）；json 反序列化对不存在的字段静默给零值，测试也没覆盖 stats
- **修复**：按 Suricata 7 实际结构重写（`detect.engines[].rules_loaded/rules_failed`、`detect.alert` 累计值单独存 `alerts_total`、`capture` 段用指针区分“pcap 模式未上报”与“0 丢包”）；迁移 0002 加列；重载耗时改由 engine-agent 在 `suricata -T`+重载后实测记录；补表驱动单测
- **教训**：**第三方数据格式不能凭记忆写结构体**，要拿真实样本写测试；“不上报”和“值为 0”在可观测里是两件事

## Bug-14：SSE 实时推送只有两端，中间没接线

- **日期**：2026-10-30（自查发现） ｜ **引入位置**：`backend/internal/realtime/realtime.go`
- **现象**：README 写“SSE 实时推送”，但页面靠轮询刷新
- **原因**：AI 生成了 `Publisher` 与 `/api/v1/stream` 订阅端，但 worker 从未实例化 Publisher、前端从未创建 EventSource——各自编译通过、单看都“实现了”
- **修复**：worker 在任务 running/done/failed 时发布事件（含新增告警数/事件数）；前端 `useRealtime` 订阅后让相关查询失效重拉并弹通知，顶栏显示连接状态；服务端加 25s 心跳与 `retry:`
- **教训**：**“每块都有”不等于“链路通了”**——验收要从用户可见现象倒推，grep 调用点而不是 grep 定义

## Bug-15：创建规则失败回滚只回滚了数据库

- **日期**：2026-10-30（审查发现） ｜ **引入位置**：`backend/internal/httpapi/rule_create_handler.go`
- **现象**：（推演）一条通过本地校验但 `suricata -T` 失败的规则，回滚后之后的每次规则启停都会重载失败
- **原因**：回滚只把 DB 中的新规则置为禁用，没有重新生成 rules-active 文件，坏规则仍留在引擎读取的文件里
- **修复**：回滚时重新生成规则文件；同时补了规则头/metadata 字段白名单与 msg 元字符剥离（见 review.md）
- **教训**：“改 DB + 改文件 + 重载”是三步事务，回滚必须对称覆盖每一步

## Bug-16：C2 场景终端 1 心跳时间戳全部相同（已修复，待引擎重跑）

- **日期**：2026-10-30（审查发现） ｜ **引入位置**：`validation/gen_scenarios.py` `gen_c2_beacon`
- **现象**：终端 1 的 30 次“每 2 秒心跳”在 pcap 里全部落在同一时刻
- **原因**：`t=ts(idx, step=2.0) if k == 0 else ...` 中 `idx` 在内层循环里不递增（只在外层 `idx += 30`），终端 1 每次都是 `ts(0)`
- **修复**：两台终端统一用 `t0 + i * 2.0`，删除无用的 `idx`；用临时 venv（scapy 2.6.1）只重新生成 `c2_beacon.pcap`，避免其他场景的 `RandShort` 源端口无故变化。断言结果：两台终端各 30 个不同时间戳、跨度 58s，第 10 次心跳在 18s（满足 sid 1000006 的 `count 10, seconds 60`，仍在 GT 时间窗 t0..t0+70 内）；ground truth JSON 无变化
- **状态**：评测器回放的是已提交的 pcap，新 pcap 尚未在 Suricata 上重跑（Docker 未运行）
- **教训**：造数据代码同样需要断言（例如检查生成包的时间分布），否则测试数据本身的 bug 会被当成“引擎行为”

## Bug-17：pcap sha256 只哈希了 4 字节魔数，且结果被丢弃

- **日期**：2026-10-30（自查发现） ｜ **引入位置**：`backend/internal/httpapi/data_handlers.go` `handleUploadPcap`
- **现象**：`pcaps.sha256` 列恒为 NULL；代码里 `sha256.Sum256(magic)` 后 `_ = sum`
- **原因**：AI 在骨架期写了“P0 先占位、P2 补全量哈希”的注释，用 `_ = sum` 压掉未使用变量的编译错误，之后没有任何检查项追踪这个占位
- **修复**：落盘时用 `io.MultiWriter(out, hasher)` 一次读流同时计算全文件哈希并写入 DB、在上传响应里返回；写盘或入库失败时删除已落盘文件。同时实现 `GET /api/v1/pcaps`（分页参数白名单校验，对外视图不暴露容器内 `stored_path`），补表驱动测试
- **教训**：`_ = x` 是“让编译器闭嘴”的信号，审查时应 grep `_ = ` 与“占位/后续补”注释，逐个确认是否真有跟踪
- **复发险情（同日）**：写 `pcapslice.parse` 时 AI 再次给未用参数写了 `_ = bo`，落盘前自查发现，改为删除该参数。说明这是生成习惯而非偶发，审查清单需固定保留这一条

## Bug-18：取证导出注释写“提取片段”，实际回传整段 pcap，且前端没有入口

- **日期**：2026-10-30（自查发现） ｜ **引入位置**：`backend/internal/httpapi/forensics_handlers.go`、`frontend/src/pages/AlertDetail.tsx`
- **现象**：函数注释写“按告警时间戳 + 五元组从原 pcap 提取片段”，实际 `http.ServeFile` 整个文件；前端 grep 不到任何调用 `/alerts/{id}/pcap` 的地方，S4 对用户不可见
- **原因**：与 Bug-14 同型——后端接口“有了”、注释描述的是目标而非现状，前端入口没人接
- **修复**：新增纯标准库 `internal/pcapslice`（经典 pcap，双向五元组/主机对 + 告警前 5 分钟至后 1 分钟），切片结果先写内存再响应以便返回正确错误码；告警详情页加“取证：本会话 / 主机对”两个下载按钮
- **验证**：表驱动测试覆盖 raw IP/Ethernet、正反向、端口/IP/时间窗不符、pcapng、超长与截断记录；用仓库内真实 `c2_beacon.pcap` 回归（360 包中切出 1 次心跳的 6 包会话）。端到端下载尚未在 Docker 中实测
- **教训**：注释要描述代码**现在**做什么；目标写进 README 的已知缺陷，不写进函数注释


## Bug-19：`# syntax=docker/dockerfile:1` 让每次构建都去 Docker Hub 拉前端镜像

- **日期**：2026-10-30（用户构建失败发现） ｜ **引入位置**：全部 5 个 Dockerfile 首行
- **现象**：`failed to resolve source metadata for docker.io/docker/dockerfile:1 ... mirror.aliyuncs.com ... EOF`，所有镜像构建在第一步失败；另 web 构建 `npm ci` 报 `Exit handler never called!`
- **原因**：AI 习惯性加了 `# syntax=` 指令，BuildKit 因此每次都要额外解析/拉取 `docker/dockerfile` 前端镜像，走的是本机 daemon 配置的镜像加速器，加速器不可用即全部失败——而该指令对本项目毫无必要（内置前端已支持 `RUN --mount`）。npm 问题则是容器内到 registry 只有约 250KB/s，默认超时下 npm 崩溃，`|| npm install` 回退又再失败一次
- **修复**：删除全部 `# syntax=` 行；web 构建去掉 `|| npm install` 回退，只用 `npm ci`，调大 fetch 超时/重试、限制并发，并用 BuildKit 缓存挂载保留已下载 tarball；新增 `frontend/.dockerignore` 防止 Windows 的 node_modules 进构建上下文。按用户要求不引入任何第三方镜像源。重建全部 5 个镜像通过，`docker compose up -d` 后 web 返回 200
- **教训**：每多一个构建期外部依赖都是一个失败点；“样板里常见”的指令要先问是否必要

## Bug-20：引擎从未加载 rules-active，M4 规则启停对检测完全无效

- **日期**：2026-10-30（对照题面复核 M4 时发现） ｜ **引入位置**：`suricata/suricata.yaml` `default-rule-path`
- **现象**：UI 新建的 sid 2000001 在引擎 `ruleset-stats` 中不存在；禁用 XSS 规则后重放 pcap，XSS 告警数不变
- **原因**：api 把启用规则写到 `rules-active/spycam.rules` 并触发重载，但 yaml 的 `default-rule-path` 仍指向镜像内置的 `/etc/suricata/rules`。重载“成功”，重载的却是内置文件。之前所有自验只用默认规则集，所以一直没暴露；规则页显示启停成功、审计和版本快照也都正常，假象很完整
- **修复**：规则路径改为 `/opt/spycam/rules-active`；新增 `rules-path.sh`，启动时最多等待 60s 让 api 生成活动规则文件，超时回退内置规则，并通过 `--set default-rule-path=` 显式传入
- **验证**：重放 web_attack pcap，XSS 告警 120 → 禁用后 0 → 重新启用后 120，同时 SQLi 始终为 240；新建规则可在引擎规则统计中看到
- **教训**：“接口返回成功”不等于“生效”。规则管理的验收必须是行为级的：改规则 → 重放 → 告警数变化

## Bug-21：Bug-5 复发——临时绕过掩盖了未落地的长期修复

- **日期**：2026-10-30 ｜ **引入位置**：`suricata/Dockerfile`（配置放在基础镜像声明的 VOLUME 路径 `/etc/suricata` 下）
- **现象**：修复 Bug-20 后改了 suricata.yaml 并重建镜像，`docker compose up -d` 后容器内 yaml 仍是旧版
- **原因**：Bug-5 当时只用 `--renew-anon-volumes` 绕过，记录里写的“长期方案”没有实施。任何普通 `up -d` 都会复用旧匿名卷，配置与内置规则改动全部静默失效；评审者照 README 复跑时同样会中招
- **修复**：自有配置与内置规则全部移出 VOLUME 路径——`/opt/spycam/suricata.yaml`、`/opt/spycam/rules`、`/opt/spycam/rules-active`（只读挂载）；engine-agent 的 `-c` 参数改用常量 `suricataConfig`。之后普通 `up -d` 即可生效，README 中的 `--renew-anon-volumes` 说明一并删除
- **教训**：bug 记录里写的“长期方案”要么当场做，要么进 README 已知缺陷；只写在 bugs.md 里等于没做

## Bug-22：引擎启动后找不到活动规则——rules-active 只在“改规则”时生成

- **日期**：2026-10-30（修 Bug-20 后复查干净安装路径发现） ｜ **引入位置**：`backend/cmd/api/main.go`
- **现象**：干净安装（新卷）首次 `up`，Suricata 等待 60s 后回退到内置规则；此后不改规则就一直在用内置路径，UI 新建的规则不生效
- **原因**：Bug-20 修复让引擎读取 `rules-active`，但该文件只在规则启停/新建的 handler 里生成，启动时没人写
- **修复**：api 启动时用 `ListEnabledRules` 生成 rules-active，再在后台重试调用 agent 重载（10 次，每次间隔 6s）
- **验证**：重建后 api 日志依次出现 `rules-active generated enabled=7` 和 `engine reloaded with active rules`

## Bug-23：实时引擎的 stats 覆盖回放 stats，引擎状态页数字混用

- **日期**：2026-10-30（自查发现） ｜ **引入位置**：`backend/migrations/0001` `engine_stats` 主键 `ts`、`LatestEngineStat`
- **现象**：开启 live 后，引擎状态页的已加载规则数、告警累计在两个实例之间跳动
- **原因**：两个 Suricata 实例写同一张表，查询取 ts 最大的一条。回放 stats 的 ts 是 pcap 时间（通常是过去），实时是墙钟，所以永远显示实时实例；两边 ts 恰好相同时还会 ON CONFLICT 互相覆盖
- **修复**：迁移 0004 加 `source` 列，主键改为 `(source, ts)`；API 分别返回 `latest_stats` 与 `live_stats`，前端分两组卡片展示
- **验证**：库内 replay 104 行与 live 7 行分开；`/engine/status` 两组 ts 各自正确

## Bug-24：规则构建器生成 `classtype:custom`，不在 classification.config 中

- **日期**：2026-10-30（README 已知缺陷收口） ｜ **引入位置**：`backend/internal/httpapi/rule_create_handler.go`
- **现象**：每次重载引擎都输出 classtype 未知警告；规则也没有 priority，所有自定义规则在 Suricata 视角同级
- **修复**：按攻击阶段映射到标准 classtype（recon→attempted-recon 等 5 项），并写入 `priority:<severity>`；迁移 0003 修正库中已有的自定义规则
- **验证**：sid 2000001 的 raw 中已无 `classtype:custom`，classtype 列为 `web-application-attack`

## Bug-25：Go 工具链与依赖存在 15 个可达漏洞——安全扫描被“工具不好装”拖成了已知缺陷

- **日期**：2026-10-30 ｜ **引入位置**：`backend/go.mod`、三个 Dockerfile 的 `golang:1.25-alpine`
- **现象**：此前 README 写“govulncheck 未执行（宿主 32 位 Go 受限）”。改在 `golang` 容器里挂宿主模块缓存运行后，报告代码可达的漏洞 15 个：标准库 net/http、crypto/tls、crypto/x509、net/textproto 共 11 个（1.25.14 无修复，需 1.26.9+）；pgx v5.7.1、go-redis v9.7.0 各 1 个；x/text v0.19.0 2 个
- **原因**：AI 初始化项目时选的依赖版本是训练数据里的“熟悉版本”，未在当时做漏洞扫描；之后又把扫描当成“环境问题”挂在已知缺陷里，没有换一条路去跑
- **修复**：构建镜像固定 `golang:1.26.10-alpine`（完整版本号，不再用浮动的 `1.25-alpine`）；pgx→v5.9.2、go-redis→v9.7.3、x/text→v0.41.0
- **验证**：同一容器内 `go vet` 与 `go test ./...` 全过；govulncheck 输出 `No vulnerabilities found`；重建镜像后完整自验回归
- **附带踩坑**：第一次在容器里跑时，因为没挂模块缓存，在容器内从 proxy.golang.org 拉模块，结果 TLS 握手超时。挂载宿主 `GOMODCACHE` 后只需联网下载漏洞库。全程未使用任何镜像源
- **教训**：工具装不上就换运行环境（容器），不要让“没扫”变成“声明没扫”。此外 PowerShell 两次误操作也记在这里：`R` 是 Invoke-History 的内置别名，用它当函数名会执行历史命令；`-replace` 替换串里的 `$1` 会被当成捕获组，把 SQL 参数 `$1` 吞掉。字符串替换一律改用 `.Replace()`

## Bug-26：回放引擎跨任务保留阈值状态——同一 pcap 重放结果不稳定，还导致变异测试预判被误改

- **日期**：2026-10-30（补 §5.4 指标后回归时发现） ｜ **引入位置**：`backend/internal/engine/agent.go` `handleReplay`（常驻 unix-socket 实例 + `pcap-file` 命令）
- **现象**：`variant_slow_scan` 在几次回归中依次得到 48、73、26、0 条告警。把引擎重启后单独回放该 pcap 三次，结果是 0、0、36
- **原因**：常驻 Suricata 的 host 表与 `detection_filter` 阈值状态在相邻 pcap 任务间不清空。慢扫变种和 `syn_port_scan` 用的是同一个源 IP，pcap 时间戳又都从同一基线开始，前一个任务的计数被带进后一个任务。unix-socket 没有重置状态的命令
- **AI 的锅**：这个现象两次出现过，两次都被错误归因。第一次 AI 看到 hit（48 条）后，把原本正确的预判 miss“修正”为 hit，还编了一个“窗口从首个命中包起滑动累计”的引擎语义解释。第二次在自验报告里写了“计数状态跨任务持久”，但处理方式是“给场景分不同源 IP 规避”，没有修引擎。真实用户重放同一 pcap 也会得到不同结果，这是 M1/M6 层面的缺陷
- **修复**：agent 为每个回放任务串行启动独立的 `suricata -r` 进程：参数数组，关闭 unix-command，规则目录选择与 rules-path.sh 一致，超时 5 分钟。入队计数在响应前同步完成，避免 worker 误判空闲。失败原因经 `replay-status.errors[task_id]` 回传，worker 据此把任务标记为失败，不再静默完成。常驻实例保留，用于热重载与状态。慢扫变种的预判恢复为 miss
- **验证**：容器内同一 pcap 一次性运行两次，均为 0 条告警，单次约 0.5s；新增单测覆盖“入队即非空闲”和“进程失败带回原因”；validator 连续两轮结果一致（见 report.md）
- **教训**：同一输入多次运行结果不同，说明存在隐藏状态，不能挑一个“合理”的结果去改预判。拿到与预判不符的结果时，第一步应该是在干净环境复现，而不是给结果编一套解释
## Bug-27：实时抓包默认不启动、网卡写死 eth0——Linux 部署后系统看起来“一直离线”

- **日期**：2026-10-30（用户在 VPS 部署后反馈） ｜ **引入位置**：`docker-compose.yml` `suricata-live`（`profiles: ["live"]`、`LIVE_IFACE:-eth0`）
- **现象**：用户从 GitHub 下载 zip 后执行 `docker compose up -d`，容器列表里没有 `spycam-suricata-live`，引擎状态页没有任何实时数据，找不到接入实时流量的入口
- **原因**：实时抓包放在可选 profile 里，必须显式 `--profile live` 才启动；界面只在实时实例上报过 stats 后才渲染卡片。即使启动，`LIVE_IFACE` 默认 `eth0`，云主机常见网卡名为 `ens3`/`enp0s3`，Suricata 会因网卡不存在退出
- **AI 的锅**：C1 是需求中的实时检测能力，AI 却按“可选附加功能”设计成 profile，只在 README 里写了一句启动命令。第一次修复又在前端页面里写了一大段部署说明，把文档问题搬进产品界面，被用户否决
- **修复**：去掉 profile，`suricata-live` 改为常驻服务；entrypoint 在 `LIVE_IFACE` 为空或网卡不存在时回退到默认路由网卡，并把实际网卡写入 `eve-out/live/iface` 供 worker 命名数据源；前端只显示状态与统计；新增只读诊断脚本 `scripts/server-check.sh`
- **验证**：本机普通 `docker compose up -d` 即启动实时容器；`LIVE_IFACE` 为空、为不存在的 `ens999` 时均回退到 `eth0` 并正常抓包；新增单测覆盖网卡名解析（文件优先、非法内容忽略、无配置为 auto）
- **教训**：需求里的核心能力不能做成默认关闭的开关；部署环境的差异（网卡名）要在程序里兜底，而不是靠用户读文档改配置