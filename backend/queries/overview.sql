-- name: CountAllAlerts :one
SELECT count(*) FROM alerts;

-- name: TrendByHour :many
SELECT date_trunc('hour', ts)::timestamptz AS bucket, count(*) AS cnt
FROM alerts
WHERE (sqlc.narg('since')::timestamptz IS NULL OR ts >= sqlc.narg('since'))
GROUP BY bucket ORDER BY bucket;

-- name: TopSrcIPs :many
SELECT src_ip, count(*) AS cnt
FROM alerts
WHERE (sqlc.narg('since')::timestamptz IS NULL OR ts >= sqlc.narg('since'))
GROUP BY src_ip ORDER BY cnt DESC LIMIT $1;

-- name: TopSignatures :many
SELECT sid, signature, count(*) AS cnt
FROM alerts
WHERE (sqlc.narg('since')::timestamptz IS NULL OR ts >= sqlc.narg('since'))
GROUP BY sid, signature ORDER BY cnt DESC LIMIT $1;

-- name: TopDestPorts :many
SELECT dest_port, count(*) AS cnt
FROM alerts
WHERE ts >= sqlc.narg('since') AND dest_port IS NOT NULL
GROUP BY dest_port ORDER BY cnt DESC LIMIT $1;

-- name: SeverityDistribution :many
SELECT severity, count(*) AS cnt
FROM alerts
WHERE severity IS NOT NULL
GROUP BY severity ORDER BY severity;

-- name: StageDistribution :many
SELECT COALESCE(r.stage, '未分类') AS stage, count(*) AS cnt
FROM alerts a
LEFT JOIN rules r ON r.sid = a.sid
GROUP BY COALESCE(r.stage, '未分类')
ORDER BY cnt DESC;

-- name: CountPendingGroups :one
SELECT count(*) FROM alert_groups WHERE status = 'new';

-- name: CountRules :one
SELECT count(*) FROM rules;

-- name: CountEnabledRules :one
SELECT count(*) FROM rules WHERE enabled = TRUE;

-- name: NextCustomSid :one
SELECT COALESCE(max(sid), 2000000) + 1 AS next_sid FROM rules WHERE sid >= 2000000;

-- name: CreateRule :one
INSERT INTO rules (sid, raw, msg, enabled, classtype, severity, stage, mitre_tactic, mitre_technique, source)
VALUES ($1, $2, $3, TRUE, $4, $5, $6, $7, $8, 'custom')
RETURNING sid, raw, msg, enabled, classtype, severity, stage, mitre_tactic, mitre_technique, source;
