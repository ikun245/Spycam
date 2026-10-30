#!/bin/sh
# Spycam 服务器环境诊断（只读，不修改任何配置）。
# 用法：在项目根目录执行  sh scripts/server-check.sh
# 结果同时写入 spycam-check.log，把该文件内容发给维护者即可。
# 注意：只输出 .env 中与网络/抓包相关的键，不输出任何密码或 token。

cd "$(dirname "$0")/.." || exit 1
LOG=spycam-check.log

section() { printf '\n===== %s =====\n' "$1"; }

{
  section "时间与系统"
  date
  uname -a
  [ -f /etc/os-release ] && grep -E '^(PRETTY_NAME|VERSION_ID)=' /etc/os-release

  section "Docker 版本"
  docker version --format 'server {{.Server.Version}} / client {{.Client.Version}}' 2>&1
  docker compose version 2>&1

  section "网卡列表"
  ip -br link 2>&1
  section "网卡地址"
  ip -br addr 2>&1
  section "路由"
  ip route 2>&1
  DEF_IF=$(ip route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
  echo "default route interface: ${DEF_IF:-<none>}"

  if [ -n "${DEF_IF}" ] && command -v ethtool >/dev/null 2>&1; then
    section "网卡 offload（${DEF_IF}）"
    ethtool -k "${DEF_IF}" 2>&1 | grep -E 'generic-receive-offload|large-receive-offload'
    ethtool -i "${DEF_IF}" 2>&1 | grep -E '^driver'
  fi

  section ".env 中网络/抓包相关配置（不含密钥）"
  if [ -f .env ]; then
    grep -E '^(LIVE_[A-Z_]*|WEB_BIND|WEB_PORT|COOKIE_SECURE|COMPOSE_PROFILES)=' .env || echo "(未设置相关键，使用默认值)"
  else
    echo ".env 不存在"
  fi

  section "compose 服务与容器"
  docker compose config --services 2>&1
  docker compose ps -a 2>&1

  section "端口监听（80 / 443 / WEB_PORT）"
  WEB_PORT=$(grep -E '^WEB_PORT=' .env 2>/dev/null | cut -d= -f2)
  ss -lntp 2>/dev/null | grep -E ":(80|443|${WEB_PORT:-28765})\b" || echo "(无匹配)"

  section "实时抓包容器日志（最近 30 行）"
  docker logs --tail 30 spycam-suricata-live 2>&1

  section "实时抓包输出目录"
  docker exec spycam-suricata-live sh -c 'ls -la /var/log/suricata/live; echo; echo iface=$(cat /var/log/suricata/live/iface 2>/dev/null)' 2>&1

  section "worker 实时采集日志"
  docker logs spycam-worker 2>&1 | grep -i live | tail -n 10

  section "最近的实时告警（eve.json 中 alert 计数）"
  docker exec spycam-suricata-live sh -c 'grep -c "\"event_type\":\"alert\"" /var/log/suricata/live/eve.json 2>/dev/null || echo 0' 2>&1
} 2>&1 | tee "${LOG}"

printf '\n诊断结果已保存到 %s/%s\n' "$(pwd)" "${LOG}"
