-- name: CreateAlert :exec
INSERT INTO alerts (task_id, ts, flow_id, community_id, src_ip, src_port, dest_ip, dest_port,
                    proto, app_proto, sid, signature, severity, category, payload_printable, raw, dedup_key)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
ON CONFLICT (task_id, dedup_key) DO NOTHING;

-- name: ListAlerts :many
SELECT id, task_id, ts, src_ip, src_port, dest_ip, dest_port, proto, app_proto,
       sid, signature, severity, category
FROM alerts
WHERE (sqlc.narg('task_id')::uuid IS NULL OR task_id = sqlc.narg('task_id'))
  AND (sqlc.narg('sid')::bigint IS NULL OR sid = sqlc.narg('sid'))
  AND (sqlc.narg('src_ip')::text IS NULL OR src_ip = sqlc.narg('src_ip'))
ORDER BY ts DESC
LIMIT $1 OFFSET $2;

-- name: CountAlerts :one
SELECT count(*)
FROM alerts
WHERE (sqlc.narg('task_id')::uuid IS NULL OR task_id = sqlc.narg('task_id'))
  AND (sqlc.narg('sid')::bigint IS NULL OR sid = sqlc.narg('sid'))
  AND (sqlc.narg('src_ip')::text IS NULL OR src_ip = sqlc.narg('src_ip'));

-- name: GetAlert :one
SELECT id, task_id, ts, ingested_at, flow_id, community_id, src_ip, src_port, dest_ip, dest_port,
       proto, app_proto, sid, signature, severity, category, payload_printable, raw
FROM alerts WHERE id = $1;

-- name: GetFlow :one
SELECT * FROM flows WHERE task_id = $1 AND flow_id = $2;

-- name: ListUnGroupedAlerts :many
SELECT id, sid, src_ip, src_port, dest_ip, dest_port, proto, ts
FROM alerts
WHERE task_id = $1 AND group_id IS NULL;
