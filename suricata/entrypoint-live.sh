#!/bin/sh
# 在线抓包（C1，compose live profile）：Suricata 直接监听网卡，eve 写入 live/ 子目录，
# 由 worker 持续 tail 增量入库。规则与离线回放共用 rules-active，文件变化时 USR2 热重载。
set -eu

LIVE_IFACE="${LIVE_IFACE:-}"
LIVE_HOME_NET="${LIVE_HOME_NET:-}"
LOG_DIR=/var/log/suricata/live

# 未配置或配置的网卡不存在（云主机常见 ens3/enp0s3 而非 eth0）时，回退到默认路由所在网卡
default_route_iface() {
  while read -r name dest _; do
    if [ "${dest}" = "00000000" ]; then printf '%s' "${name}"; return 0; fi
  done < /proc/net/route
  return 1
}
if [ -z "${LIVE_IFACE}" ] || [ ! -e "/sys/class/net/${LIVE_IFACE}" ]; then
  detected=$(default_route_iface || true)
  if [ -z "${detected}" ]; then
    echo "LIVE_IFACE '${LIVE_IFACE}' not found and no default route interface detected" >&2; exit 2
  fi
  echo "LIVE_IFACE '${LIVE_IFACE}' not set or not found, using default route interface ${detected}" >&2
  LIVE_IFACE="${detected}"
fi

# 网卡名与 HOME_NET 只接受白名单字符（参数均以独立 argv 传递，不经 shell 拼接）
case "${LIVE_IFACE}" in
  ""|*[!A-Za-z0-9._-]*) echo "invalid LIVE_IFACE" >&2; exit 2 ;;
esac
if [ -n "$(printf '%s' "${LIVE_HOME_NET}" | tr -d '0-9A-Fa-f.:/,[]! ')" ]; then
  echo "invalid LIVE_HOME_NET" >&2; exit 2
fi

mkdir -p "${LOG_DIR}"
# 告知 worker 实际监听的网卡（用于数据源命名与界面展示）
printf '%s\n' "${LIVE_IFACE}" > "${LOG_DIR}/iface"
echo "live capture on interface ${LIVE_IFACE}" >&2

. /usr/local/lib/spycam/rules-path.sh
choose_rule_path

# exec 后 suricata 继承本 shell 的 PID，后台 watcher 据此发 USR2 触发规则热重载，
# 并在 eve.json 超过阈值时轮转：改名为 eve.json.1 后 SIGHUP 让 Suricata 重新打开日志文件。
# worker 按 inode 识别轮转，先读完 .1 的剩余部分再切到新文件；.1 只保留一份。
LIVE_EVE_MAX_MB="${LIVE_EVE_MAX_MB:-100}"
case "${LIVE_EVE_MAX_MB}" in
  ""|*[!0-9]*) echo "invalid LIVE_EVE_MAX_MB" >&2; exit 2 ;;
esac
EVE_MAX_BYTES=$((LIVE_EVE_MAX_MB * 1024 * 1024))
SURI_PID=$$
(
  last=""
  while sleep 5; do
    cur=$(cksum "${RULE_PATH}/spycam.rules" 2>/dev/null || true)
    if [ -n "${last}" ] && [ "${cur}" != "${last}" ]; then
      echo "rules changed, reloading live engine" >&2
      kill -USR2 "${SURI_PID}" 2>/dev/null || true
    fi
    last="${cur}"
    size=0
    if [ -f "${LOG_DIR}/eve.json" ]; then
      size=$(wc -c < "${LOG_DIR}/eve.json" 2>/dev/null || echo 0)
    fi
    if [ "${EVE_MAX_BYTES}" -gt 0 ] && [ "${size}" -gt "${EVE_MAX_BYTES}" ]; then
      echo "eve.json ${size} bytes > ${LIVE_EVE_MAX_MB}MB, rotating" >&2
      mv -f "${LOG_DIR}/eve.json" "${LOG_DIR}/eve.json.1"
      kill -HUP "${SURI_PID}" 2>/dev/null || true
    fi
  done
) &

set -- suricata \
  -c /opt/spycam/suricata.yaml \
  --set "default-rule-path=${RULE_PATH}" \
  --set "unix-command.enabled=no" \
  --af-packet="${LIVE_IFACE}" \
  -k none \
  -l "${LOG_DIR}"
if [ -n "${LIVE_HOME_NET}" ]; then
  set -- "$@" --set "vars.address-groups.HOME_NET=${LIVE_HOME_NET}"
fi
exec "$@"