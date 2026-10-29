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

