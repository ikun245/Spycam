-- name: CountAllAlerts :one
SELECT count(*) FROM alerts;

-- name: TrendByHour :many
SELECT date_trunc('hour', ts) AS bucket, count(*) AS cnt
FROM alerts
WHERE ts >= $1
GROUP BY bucket ORDER BY bucket;

-- name: TopSrcIPs :many
SELECT src_ip, count(*) AS cnt
FROM alerts
WHERE ts >= $1
GROUP BY src_ip ORDER BY cnt DESC LIMIT $2;

-- name: TopSignatures :many
SELECT sid, signature, count(*) AS cnt
FROM alerts
WHERE ts >= $1
GROUP BY sid, signature ORDER BY cnt DESC LIMIT $2;

-- name: TopDestPorts :many
SELECT dest_port, count(*) AS cnt
FROM alerts
WHERE ts >= $1 AND dest_port IS NOT NULL
GROUP BY dest_port ORDER BY cnt DESC LIMIT $2;

-- name: CountPendingGroups :one
SELECT count(*) FROM alert_groups WHERE status = 'new';

-- name: CountRules :one
SELECT count(*) FROM rules;

-- name: CountEnabledRules :one
SELECT count(*) FROM rules WHERE enabled = TRUE;
