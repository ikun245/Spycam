#!/bin/sh
# 规则路径选择：优先 api 生成的 rules-active（管理端改动的唯一真相），
# 首次启动时 api 可能尚未写出，等待片刻后回退到镜像内置规则，避免引擎起不来。
RULES_ACTIVE=/opt/spycam/rules-active/spycam.rules
RULES_WAIT_SECONDS="${RULES_WAIT_SECONDS:-60}"

choose_rule_path() {
  waited=0
  while [ ! -s "${RULES_ACTIVE}" ] && [ "${waited}" -lt "${RULES_WAIT_SECONDS}" ]; do
    sleep 2
    waited=$((waited + 2))
  done
  if [ -s "${RULES_ACTIVE}" ]; then
    RULE_PATH=/opt/spycam/rules-active
  else
    echo "rules-active not ready after ${RULES_WAIT_SECONDS}s, fallback to built-in rules" >&2
    RULE_PATH=/opt/spycam/rules
  fi
}