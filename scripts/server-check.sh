#!/bin/sh
# Spycam 服务器环境诊断（只读，不修改任何配置）。
# 用法：sh server-check.sh [项目目录]
#   项目目录可省略：依次尝试参数、脚本上级目录、当前目录、运行中 spycam 容器记录的 compose 目录。
# 结果同时写入 /tmp/spycam-check.log，把该文件内容发给维护者即可。
# 注意：只输出 .env 中与网络/抓包相关的键，不输出任何密码或 token。

LOG=/tmp/spycam-check.log

has_compose() { [ -f "$1/docker-compose.yml" ] || [ -f "$1/compose.yaml" ]; }

PROJECT_DIR=""
for d in "${1:-}" "$(cd "$(dirname "$0")/.." 2>/dev/null && pwd)" "$(pwd)"; do
  if [ -n "$d" ] && has_compose "$d"; then PROJECT_DIR="$d"; break; fi
done
if [ -z "${PROJECT_DIR}" ]; then
  for c in spycam-web spycam-api spycam-worker; do
    d=$(docker inspect "$c" --format '{{ index .Config.Labels "com.docker.compose.project.working_dir" }}' 2>/dev/null)
    if [ -n "$d" ] && has_compose "$d"; then PROJECT_DIR="$d"; break; fi
  done
fi

section() { printf '\n===== %s =====\n' "$1"; }

{
  section "项目目录"
  if [ -n "${PROJECT_DIR}" ]; then
    echo "${PROJECT_DIR}"
    cd "${PROJECT_DIR}" || exit 1
    if grep -q 'profiles: \["live"\]' docker-compose.yml 2>/dev/null; then
      echo "代码版本：旧版（suricata-live 仍需 --profile live），请更新代码后 docker compose up -d --build"
    else
      echo "代码版本：新版（suricata-live 默认启动）"
    fi
  else
    echo "未找到 docker-compose.yml，请执行：sh server-check.sh /项目目录"
  fi
  for c in spycam-worker spycam-suricata-live; do
    printf '%s 容器创建时间：' "$c"
    docker inspect "$c" --format '{{.Created}}' 2>/dev/null || echo "容器不存在"
  done

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
  docker exec spycam-suricata-live sh -c 'grep -c "\"event_type\":\"alert\"" /var/log/suricata/live/eve.json 2>/dev/null; true' 2>&1
} 2>&1 | tee "${LOG}"

printf '\n诊断结果已保存到 %s\n' "${LOG}"
