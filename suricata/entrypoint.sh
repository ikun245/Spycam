#!/bin/sh
# 启动 engine-agent（内部控制接口）+ Suricata unix-socket 模式
set -eu

LOG_DIR=/var/log/suricata
mkdir -p "${LOG_DIR}"

/usr/local/bin/engine-agent \
  -listen ":9090" \
  -token "${ENGINE_AGENT_TOKEN}" &
AGENT_PID=$!

cleanup() {
  kill "${AGENT_PID}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

exec suricata --unix-socket \
  -c /etc/suricata/suricata.yaml \
  -l "${LOG_DIR}"
