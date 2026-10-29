---
description: "Use when writing or editing React/TypeScript code in frontend/: pages, components, API clients, SSE streaming, or charts. Covers Ant Design usage, XSS-safety rules for traffic data, and data-fetching conventions."
applyTo: ["frontend/**"]
---
# React 前端规范

- 技术栈固定：Vite + TypeScript + Ant Design + TanStack Query + React Router；图表用 ECharts；UI 模板来源在 README 注明
- **XSS 红线**：payload、域名、URL、User-Agent、原始 JSON 等来自流量的数据一律作纯文本渲染；禁止 `dangerouslySetInnerHTML`（ESLint 直接禁用该 API）
- 列表页（告警等）一律服务端分页/过滤/排序；请求参数值走 URLSearchParams 或请求体，不在代码里拼查询字符串
- API 调用统一封装：自动携带凭据、401 跳登录、非 GET 请求带自定义头（CSRF）；组件内不直接 fetch
- 实时刷新用原生 `EventSource`（SSE），实现断线自动重连；不引入 WebSocket
- 时间展示注明时区：eve.json 的 `timestamp` 是 pcap 内时间，不是当前时间，界面上要能区分
- 处置操作（确认/误报/忽略）提交后用 TanStack Query 失效对应缓存，不手动改本地状态
