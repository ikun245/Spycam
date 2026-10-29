"""M5 自动评测：上传全部场景 pcap → 回放 → 按任务取原始告警 → 对照 ground truth →
输出 report.json / report.md。

判定口径（需求梳理 §5.3）：
- TP：存在至少一条告警 sid 匹配、五元组匹配（目的端口在范围内）、时间落在期望窗内
- FN：某条期望完全无命中
- FP：负样本 pcap 的任意告警；或攻击 pcap 中不匹配任何期望的告警
"""
import json
import os
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


def parse_eve_ts(s):
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%f%z")


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
            try:
                ts = parse_eve_ts(a["ts"])
            except Exception:
                continue
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

    exp_sids = {exp["sid"] for exp in gt["expected_alerts"]}
    fps = [a for a in alerts if a["id"] not in matched_ids and a["sid"] not in exp_sids]

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

    return {
        "scenario": gt["scenario"],
        "pcap": gt["pcap"],
        "benign": gt["benign"],
        "task_id": t["id"],
        "task_status": final["status"],
        "alert_count": len(alerts),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "expectations": per_exp,
        "fp_samples": [
            {"sid": a["sid"], "src_ip": a["src_ip"], "dest_port": a.get("dest_port")}
            for a in fps[:10]
        ],
    }


def main():
    session = requests.Session()
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

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "criteria": "需求梳理 §5.3：TP=sid+五元组+时间窗全匹配；FP=负样本任意告警或未匹配期望的告警",
        "overall": {
            "tp": tp_total,
            "fp": fp_total,
            "fn": fn_total,
            "precision": round(g_precision, 4),
            "recall": round(g_recall, 4),
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
        f"总体：TP={tp_total} FP={fp_total} FN={fn_total} "
        f"Precision={report['overall']['precision']} Recall={report['overall']['recall']}",
        "",
        "| 场景 | pcap | 告警数 | TP | FP | FN | P | R | F1 |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for s in scenarios:
        lines.append(
            f"| {s['scenario']} | {s['pcap']} | {s['alert_count']} | {s['tp']} | "
            f"{s['fp']} | {s['fn']} | {s['precision']} | {s['recall']} | {s['f1']} |"
        )
    if variants:
        lines += [
            "",
            "## 变异测试（§5.5：先预判，再验证）",
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
