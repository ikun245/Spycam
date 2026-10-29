# 关键决策记录

> 要求见需求梳理 §6：≥5 个关键决策——选项是什么、AI 建议什么、你怎么判断、结果如何。

## D-1 前端构建的 esbuild 临时目录问题（环境决策）

- **日期**：2026-10-29
- **现象**：`npm run build` 在 transform 完成后的 transpile 阶段稳定报 `Access is denied`（esbuild 清理系统 TEMP 下的临时文件失败），两次复现，非偶发
- **AI 建议**：无（AI 未预见；属于本机环境与杀软实时扫描的相互作用）
- **判断**：TypeScript 编译（tsc -b）已通过、3072 模块 transform 完成，问题只在 esbuild 与系统 TEMP 交互；把 `TMP/TEMP` 重定向到项目内目录即可绕过，无需改动代码或依赖版本
- **结果**：设置 `$env:TEMP=$env:TMP=<项目>\.tmp` 后构建成功（1.03MB 主 chunk，gzip 325KB）；`.tmp` 已加入 .gitignore
- **教训**：Windows 上构建工具链的临时文件行为受杀软影响，先重定向 TEMP 再考虑换工具版本

## D-2 骨架期占位策略

- **日期**：2026-10-29
- **备选方案**：a) 只搭目录不写代码；b) 写全功能但未验证；c) 可编译的最小骨架 + 501 占位
- **AI 建议**：倾向于直接把回放链路写完
- **实际选择**：c。理由：unix-socket 控制协议是架构设计 §13 的待验证项，未上真机前写全大概率返工；501 占位让 API 契约先行，前后端可并行
- **结果验证**：`go build ./...`、`go vet`、`npm run build` 全部通过；真实验证待 Docker 可用

## D-3 P0 卡点分层：控制通道假故障 vs 数据面未实现

- **日期**：2026-10-29
- **现象**：`suricatasc` 长时间无响应，容易误判为 Suricata unix-socket 不兼容。
- **备选原因**：a) socket 路径/参数错；b) Suricata 不接受控制命令；c) `/readyz` 的状态探针留下空闲连接；d) 回放 API 和 worker 尚未实现。
- **验证过程**：确认参数格式为 `suricatasc -c uptime /var/run/suricata.socket`；重启清空旧连接后命令返回 `OK`；修复探针后连续 5 次 `/readyz` 均 200，`uptime` 仍成功；`pcap-file` 命令清楚返回 filename 不存在，确认控制命令工作。另一方面，真实 `POST /api/v1/replay-tasks` 返回 501，worker 代码只连 PG/Redis 后等待信号。
- **判断与结论**：c 是造成控制通道排查卡住的真实 bug，已修复；d 才是当前“无法验收 P0 闭环”的根因。P0 不能因为服务健康或引擎可控就宣称完成。
- **后续**：实现上传与回放任务 API、worker 队列消费、eve 解析入库，再用真实 pcap 验收。

（后续决策按此格式追加）
