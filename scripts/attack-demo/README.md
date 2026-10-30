# 攻击演示脚本（展示规则检测效果）

这组脚本用于**演示** `rules/spycam.rules` 的 6 条检测规则在实时抓包
（`spycam-suricata-live` 容器）下的告警效果。每个脚本持续约 30 秒、
达到规则阈值即触发告警。

> ⚠️ 仅用于你**自己拥有或已获授权**的主机。脚本只产生匹配规则特征的
> 良性请求（TCP 连接 / HTTP 请求 / DNS 查询），不含任何真实破坏性操作。
> 纯 Python 标准库，无需第三方依赖；外部 4 个脚本**无需 root**。

## 前置条件

1. 目标服务器已按 README 启动，并运行了实时抓包容器：
   ```bash
   docker compose up -d --build
   docker compose ps   # 应能看到 spycam-suricata-live
   ```
2. 实时抓包网卡（`LIVE_IFACE`）就是承载你攻击流量的网卡（公网机一般是 `eth0`）。
3. **Web 攻击走明文 HTTP（默认 80 端口）**：HTTPS 是加密的，引擎看不到 URI，
   因此 SQLi/XSS 演示必须用 `http://`，不能用 `https://`。

## 脚本与对应规则

| 脚本 | 规则 sid | 说明 | 在哪运行 |
|------|----------|------|----------|
| `port_scan.py` | 1000001 | SYN 端口扫描（1-200 低端口） | 攻击机 → 服务器 |
| `ssh_bruteforce.py` | 1000002 | 高频连接 22 端口 | 攻击机 → 服务器 |
| `web_sqli.py` | 1000003 | URI 带 `UNION SELECT` | 攻击机 → 服务器 |
| `web_xss.py` | 1000004 | URI 带 `<script onerror` | 攻击机 → 服务器 |
| `dns_tunnel.py` | 1000005 | 超长子域名 DNS 查询 | **服务器本机** |
| `c2_beacon.py` | 1000006 | 向外部高频 POST `/api/collect` | **服务器本机** |

### 为什么 1000005 / 1000006 要在服务器本机运行？

这两条规则的方向是 `$HOME_NET -> ...`，即流量**源**必须是被监控主机本身
（模拟“已失陷主机对外回连 / 外带数据”）。所以要在服务器上运行，
而不是从攻击机打过去。其余 4 条是 `-> $HOME_NET`，从攻击机打向服务器即可。

## 用法

从攻击机（把 `<服务器IP>` 换成目标公网 IP）：

```bash
# 单独运行
python3 port_scan.py       <服务器IP> -d 30
python3 ssh_bruteforce.py  <服务器IP> -d 30
python3 web_sqli.py        <服务器IP> --http-port 80 -d 30
python3 web_xss.py         <服务器IP> --http-port 80 -d 30

# 一键并行跑上面 4 个
python3 run_all.py <服务器IP> --http-port 80 -d 30
```

在服务器本机（演示失陷主机外联）：

```bash
python3 dns_tunnel.py --resolver 8.8.8.8 -d 30
python3 c2_beacon.py  --dest example.com --port 80 -d 30
```

运行后到 Spycam 前端「告警列表」查看对应规则的新告警（实时数据源名形如
`live:<网卡>`）。

## 常见问题

- **没有告警**：确认 `spycam-suricata-live` 在跑、攻击流量确实经过
  `LIVE_IFACE` 网卡；Web 攻击确认走的是 80 端口 HTTP。
- **公网机告警为 0**：实时容器会自动把本机网卡 IP 加入 HOME_NET
  （见 `suricata/entrypoint-live.sh`），不要在 `.env` 手动写死
  `LIVE_HOME_NET`。
- **C2 心跳不触发**：`--dest` 必须是**外部**主机且端口在规则的明文
  HTTP_PORTS（80/81/3000/8000/8008/8080/8081）内。
