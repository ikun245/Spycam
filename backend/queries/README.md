# sqlc 查询目录

- 所有 SQL 查询写在本目录的 `*.sql` 文件中，由 sqlc 生成类型安全的 Go 代码到 `internal/store/`
- 禁止在 Go 代码里用字符串拼接 SQL；动态排序/过滤字段在服务端白名单映射
- 生成命令（骨架期暂未引入 sqlc.yaml，落地数据层时补充）：`sqlc generate`
