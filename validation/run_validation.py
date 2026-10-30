"""M5 自动评测：上传全部场景 pcap → 回放 → 按任务取原始告警 → 对照 ground truth →
输出 report.json / report.md。

判定口径（需求梳理 §5.3）：
- TP：存在至少一条告警 sid 匹配、五元组匹配（目的端口在范围内）、时间落在期望窗内
- FN：某条期望完全无命中
- FP：负样本 pcap 的任意告警；或攻击 pcap 中不匹配任何期望的告警（不按 sid 豁免）
"""
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

BASE = os.environ.get("API_BASE_URL", "http://api:8081")
USER = os.environ.get("VALIDATOR_USER", "admin")
PASSWORD = os.environ.get("VALIDATOR_PASSWORD", "")
OUT = Path(os.environ.get("VALIDATION_OUT", "/work/out"))


def iso_to_dt(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def _fmt(v):
    return "-" if v is None else v


def parse_eve_ts(s):
    """兼容 Go RFC3339Nano（整秒无小数、Z 后缀、最多 9 位小数）与 Suricata +0000 格式。
    解析失败必须抛出而不是静默跳过，否则严格口径下会被误计为 FP。"""
    s = s.replace("Z", "+00:00")
    m = re.match(r"^(.*T\d{2}:\d{2}:\d{2})(?:\.(\d+))?([+-]\d{2}:?\d{2})$", s)
    if not m:
        raise ValueError(f"unparseable ts: {s}")
    base, frac, tz = m.groups()
    frac = (frac or "0")[:6].ljust(6, "0")
    if ":" not in tz:
        tz = tz[:3] + ":" + tz[3:]
    return datetime.fromisoformat(f"{base}.{frac}{tz}")


def login(session):
    r = session.post(
        f"{BASE}/api/v1/auth/login",
        json={"username": USER, "password": PASSWORD},
        timeout=10,
    )
    r.raise_for_status()


def wait_task(session, task_id, timeout=120):
    deadline = time.time() + timeout
    while time.time() < deadline:
        t = session.get(f"{BASE}/api/v1/replay-tasks/{task_id}", timeout=10).json()
        if t["status"] in ("done", "failed"):
            return t
        time.sleep(2)
    return {"status": "timeout"}


def fetch_alerts(session, task_id):
    items = []
    limit, offset = 200, 0
    while True:
        r = session.get(
            f"{BASE}/api/v1/alerts",
            params={"task_id": task_id, "limit": limit, "offset": offset},
            timeout=10,
        ).json()
        items.extend(r["items"])
        if len(items) >= r["total"] or not r["items"]:
            break
        offset += limit
    return items


def evaluate_expectation(exp, alerts):
    """返回命中的告警 id 列表。"""
    window = exp.get("window", {})
    ws = iso_to_dt(window["start"]) if window.get("start") else None
    we = iso_to_dt(window["end"]) if window.get("end") else None
    lo, hi = exp.get("dst_port_range", [0, 65535])
    matched = []
    for a in alerts:
        if a["sid"] != exp["sid"]:
            continue
        if a["src_ip"] != exp["src_ip"] or a["dest_ip"] != exp["dst_ip"]:
            continue
        dp = a.get("dest_port")
        if dp is None or not (lo <= dp <= hi):
            continue
        if ws or we:
            ts = parse_eve_ts(a["ts"])
            if ws and ts < ws:
                continue
            if we and ts > we:
                continue
        matched.append(a["id"])
    return matched


def evaluate_variant(session, gt):
    """§5.5 变异测试：只跑回放，比较"预判 vs 实际"，不参与 TP/FP/FN 统计。"""
    pcap_path = OUT / gt["pcap"]
    with pcap_path.open("rb") as fh:
        r = session.post(
            f"{BASE}/api/v1/pcaps",
            files={"file": (gt["pcap"], fh, "application/octet-stream")},
            data={"name": gt["pcap"], "sample_type": gt["scenario"]},
            timeout=60,
        )
    r.raise_for_status()
    pcap_id = r.json()["id"]
    t = session.post(
        f"{BASE}/api/v1/replay-tasks", json={"pcap_id": pcap_id}, timeout=10
    ).json()
    final = wait_task(session, t["id"])
    alerts = fetch_alerts(session, t["id"]) if final["status"] == "done" else []

    detected = len(alerts) > 0
    prediction = gt.get("prediction", "hit")
    expected = prediction == "hit"
    return {
        "scenario": gt["scenario"],
        "variant_of": gt["variant_of"],
        "pcap": gt["pcap"],
        "prediction": prediction,
        "prediction_reason": gt.get("prediction_reason", ""),
        "actual_alert_count": len(alerts),
        "actual": "hit" if detected else "miss",
        "prediction_correct": detected == expected,
        "sids": sorted({a["sid"] for a in alerts}),
    }


def evaluate_one(session, gt):
    pcap_path = OUT / gt["pcap"]
    with pcap_path.open("rb") as fh:
        r = session.post(
            f"{BASE}/api/v1/pcaps",
            files={"file": (gt["pcap"], fh, "application/octet-stream")},
            data={"name": gt["pcap"], "sample_type": gt["scenario"]},
            timeout=60,
        )
    r.raise_for_status()
    pcap_id = r.json()["id"]
    t = session.post(
        f"{BASE}/api/v1/replay-tasks", json={"pcap_id": pcap_id}, timeout=10
    ).json()
    final = wait_task(session, t["id"])
    alerts = fetch_alerts(session, t["id"]) if final["status"] == "done" else []

    matched_ids = set()
    per_exp = []
    alert_ts = {a["id"]: parse_eve_ts(a["ts"]) for a in alerts}
    detect_delays = []
    for exp in gt["expected_alerts"]:
        ids = evaluate_expectation(exp, alerts)
        per_exp.append(
            {
                "sid": exp["sid"],
                "matched": len(ids),
                "min_count": exp.get("min_count", 1),
            }
        )
        matched_ids.update(ids)
        # 检测时延（pcap 内时间）：期望窗起点 = 该攻击首包时间 → 首条命中告警
        if ids and exp.get("window", {}).get("start"):
            first = min(alert_ts[i] for i in ids)
            detect_delays.append((first - iso_to_dt(exp["window"]["start"])).total_seconds())

    # 严格 §5.3：未被任何期望（sid+五元组+时间窗）匹配的告警一律计 FP，
    # 不因 sid 出现在期望集合里而豁免
    fps = [a for a in alerts if a["id"] not in matched_ids]

    if gt["benign"]:
        tp, fn = 0, 0
        fp = len(alerts)
        fps = alerts
    else:
        tp = sum(1 for e in per_exp if e["matched"] >= e["min_count"])
        fn = len(per_exp) - tp
        fp = len(fps)

    precision = tp / (tp + fp) if (tp + fp) else (1.0 if tp + fn == 0 else 0.0)
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    # 处理时延（墙钟）：提交回放任务 → 首条/全部告警入库；离线回放的“包时间”是历史时间，
    # 不能直接与入库墙钟相减，因此拆成检测时延 + 处理时延两段报告
    pipe_first = pipe_last = None
    if final.get("created_at") and final.get("first_ingested_at"):
        created = parse_eve_ts(final["created_at"])
        pipe_first = (parse_eve_ts(final["first_ingested_at"]) - created).total_seconds()
        pipe_last = (parse_eve_ts(final["last_ingested_at"]) - created).total_seconds()
    groups = final.get("group_count") or 0
    # 参考口径：按 sid+源/目的主机对（忽略端口）计组数，用于说明五元组聚合键对扫描/爆破类告警为何几乎不压缩
    hostpair_groups = len({(a["sid"], a["src_ip"], a.get("dest_ip")) for a in alerts})

    return {
        "scenario": gt["scenario"],
        "pcap": gt["pcap"],
        "benign": gt["benign"],
        "task_id": t["id"],
        "task_status": final["status"],
        "alert_count": len(alerts),
        "matched_alert_count": 0 if gt["benign"] else len(matched_ids),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "detect_delay_s": {
            "mean": round(sum(detect_delays) / len(detect_delays), 3) if detect_delays else None,
            "max": round(max(detect_delays), 3) if detect_delays else None,
        },
        "pipeline_latency_s": {
            "first_alert": round(pipe_first, 3) if pipe_first is not None else None,
            "all_alerts": round(pipe_last, 3) if pipe_last is not None else None,
        },
        "group_count": groups,
        "dedup_rate": round(1 - groups / len(alerts), 4) if alerts and groups else None,
        "hostpair_group_count": hostpair_groups,
        "expectations": per_exp,
        "fp_samples": [
            {
                "sid": a["sid"],
                "src_ip": a["src_ip"],
                "dest_ip": a.get("dest_ip"),
                "dest_port": a.get("dest_port"),
                "ts": a.get("ts"),
            }
            for a in fps[:10]
        ],
    }


def main():
    session = requests.Session()
    # 后端对非 GET 请求做 CSRF 自定义头校验（架构设计 §6.6），脚本客户端同样需要携带
    session.headers["X-Requested-With"] = "spycam"
    login(session)

    gt_files = sorted((OUT / "ground_truth").glob("*.json"))
    scenarios = []
    variants = []
    for gt_file in gt_files:
        gt = json.loads(gt_file.read_text(encoding="utf-8"))
        if gt.get("variant_of"):
            v = evaluate_variant(session, gt)
            variants.append(v)
            mark = "OK" if v["prediction_correct"] else "WRONG"
            print(f"[validator] {v['scenario']} (variant of {v['variant_of']}): "
                  f"predicted={v['prediction']} actual={v['actual']} -> {mark}")
            continue
        s = evaluate_one(session, gt)
        scenarios.append(s)
        print(f"[validator] {s['scenario']}: alerts={s['alert_count']} "
              f"TP={s['tp']} FP={s['fp']} FN={s['fn']}")

    tp_total = sum(s["tp"] for s in scenarios)
    fp_total = sum(s["fp"] for s in scenarios)
    fn_total = sum(s["fn"] for s in scenarios)
    g_precision = tp_total / (tp_total + fp_total) if (tp_total + fp_total) else 0.0
    g_recall = tp_total / (tp_total + fn_total) if (tp_total + fn_total) else 1.0
    alerts_total = sum(s["alert_count"] for s in scenarios)
    matched_total = sum(s["matched_alert_count"] for s in scenarios)
    alert_precision = matched_total / alerts_total if alerts_total else 1.0
    pred_ok = sum(1 for v in variants if v["prediction_correct"])

    def _vals(key, sub):
        return [s[key][sub] for s in scenarios if s[key][sub] is not None]

    det_mean, det_max = _vals("detect_delay_s", "mean"), _vals("detect_delay_s", "max")
    pipe_all = _vals("pipeline_latency_s", "all_alerts")
    groups_total = sum(s["group_count"] for s in scenarios)
    latency = {
        "detect_delay_mean_s": round(sum(det_mean) / len(det_mean), 3) if det_mean else None,
        "detect_delay_max_s": max(det_max) if det_max else None,
        "pipeline_latency_mean_s": round(sum(pipe_all) / len(pipe_all), 3) if pipe_all else None,
        "pipeline_latency_max_s": max(pipe_all) if pipe_all else None,
    }
    dedup_rate = round(1 - groups_total / alerts_total, 4) if alerts_total and groups_total else None
    hostpair_total = sum(s["hostpair_group_count"] for s in scenarios)
    hostpair_rate = round(1 - hostpair_total / alerts_total, 4) if alerts_total and hostpair_total else None

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "criteria": (
            "需求梳理 §5.3（严格口径）：TP=期望条目被 sid+五元组+时间窗全匹配的告警命中；"
            "FN=期望条目无命中；FP=负样本任意告警，或攻击样本中未匹配任何期望条目的告警（不按 sid 豁免）。"
            "alert_precision=被期望匹配的告警数/总告警数，作为告警级补充指标"
        ),
        "overall": {
            "tp": tp_total,
            "fp": fp_total,
            "fn": fn_total,
            "precision": round(g_precision, 4),
            "recall": round(g_recall, 4),
            "alert_count": alerts_total,
            "matched_alert_count": matched_total,
            "alert_precision": round(alert_precision, 4),
            "group_count": groups_total,
            "dedup_rate": dedup_rate,
            "hostpair_group_count": hostpair_total,
            "hostpair_dedup_rate": hostpair_rate,
            **latency,
            "variant_predictions_correct": f"{pred_ok}/{len(variants)}",
        },
        "scenarios": scenarios,
        "variants": variants,
    }
    (OUT / "report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    lines = [
        "# Spycam 数据自验报告",
        "",
        f"生成时间：{report['generated_at']}",
        "",
        f"判定口径：{report['criteria']}",
        "",
        f"总体：TP={tp_total} FP={fp_total} FN={fn_total} "
        f"Precision={report['overall']['precision']} Recall={report['overall']['recall']}；"
        f"告警级 Precision={report['overall']['alert_precision']}（{matched_total}/{alerts_total}）",
        "",
        f"告警时延：检测时延（pcap 内时间，攻击首包 → 首条命中告警）均值 {latency['detect_delay_mean_s']}s / "
        f"最大 {latency['detect_delay_max_s']}s；处理时延（墙钟，提交回放 → 全部告警入库）均值 "
        f"{latency['pipeline_latency_mean_s']}s / 最大 {latency['pipeline_latency_max_s']}s。"
        "离线回放的包时间戳是历史时间，故拆成两段；实时抓包（live profile）包 → 入库实测见自验报告",
        "",
        f"去重率：原始告警 {alerts_total} 条 → 聚合 {groups_total} 组，去重率 {dedup_rate}（1 - 组数/告警数）。"
        f"聚合键按需求 S1 为“同签名+同五元组”，扫描换目的端口、爆破/心跳/隧道每次新建连接换源端口，五元组几乎不重复，"
        f"因此该口径下压缩有限；参考口径“同签名+同主机对”为 {hostpair_total} 组（去重率 {hostpair_rate}），"
        "这一层归并由 S3 事件串联承担",
        "",
        "| 场景 | pcap | 告警数 | 匹配告警 | TP | FP | FN | P | R | F1 | 检测时延 均值/最大(s) | 处理时延(s) | 聚合组 | 去重率 |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for s in scenarios:
        d, p = s["detect_delay_s"], s["pipeline_latency_s"]
        lines.append(
            f"| {s['scenario']} | {s['pcap']} | {s['alert_count']} | {s['matched_alert_count']} | {s['tp']} | "
            f"{s['fp']} | {s['fn']} | {s['precision']} | {s['recall']} | {s['f1']} | "
            f"{_fmt(d['mean'])}/{_fmt(d['max'])} | {_fmt(p['all_alerts'])} | {s['group_count']} | {_fmt(s['dedup_rate'])} |"
        )
    if variants:
        lines += [
            "",
            f"## 变异测试（§5.5：先预判，再验证；预判正确 {pred_ok}/{len(variants)}）",
            "",
            "| 变种 | 基线场景 | 预判 | 实际 | 是否命中预判 | 预判依据 |",
            "|---|---|---|---|---|---|",
        ]
        for v in variants:
            ok = "✅" if v["prediction_correct"] else "❌"
            lines.append(
                f"| {v['scenario']} | {v['variant_of']} | {v['prediction']} | "
                f"{v['actual']}（{v['actual_alert_count']} 条） | {ok} | {v['prediction_reason']} |"
            )
    if fp_total or fn_total:
        lines += ["", "## 已知 FN / FP 说明", ""]
        for s in scenarios:
            if s["fn"]:
                lines.append(f"- {s['scenario']}: FN={s['fn']}（期望未命中，见 ground truth known_limitations）")
            if s["fp"]:
                lines.append(f"- {s['scenario']}: FP={s['fp']}，样例 {s['fp_samples']}")
    (OUT / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    sys.exit(main())
