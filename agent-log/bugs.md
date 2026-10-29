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

