-- name: CreateAlert :exec
INSERT INTO alerts (task_id, ts, flow_id, community_id, src_ip, src_port, dest_ip, dest_port,
                    proto, app_proto, sid, signature, severity, category, payload_printable, raw, dedup_key)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
ON CONFLICT (task_id, dedup_key) DO NOTHING;

-- name: ListAlerts :many
SELECT a.id, a.task_id, a.ts, a.src_ip, a.src_port, a.dest_ip, a.dest_port, a.proto, a.app_proto,
       a.sid, a.signature, a.severity, a.category,
       COALESCE(g.status, 'new')::text AS triage_status
FROM alerts a
LEFT JOIN alert_groups g ON g.id = a.group_id
WHERE (sqlc.narg('task_id')::uuid IS NULL OR a.task_id = sqlc.narg('task_id'))
  AND (sqlc.narg('sid')::bigint IS NULL OR a.sid = sqlc.narg('sid'))
  AND (sqlc.narg('src_ip')::text IS NULL OR a.src_ip = sqlc.narg('src_ip'))
  AND (sqlc.narg('dest_ip')::text IS NULL OR a.dest_ip = sqlc.narg('dest_ip'))
  AND (sqlc.narg('severity')::int IS NULL OR a.severity = sqlc.narg('severity'))
  AND (sqlc.narg('proto')::text IS NULL OR a.proto = sqlc.narg('proto'))
  AND (sqlc.narg('triage_status')::text IS NULL OR COALESCE(g.status, 'new') = sqlc.narg('triage_status'))
  AND (sqlc.narg('ts_from')::timestamptz IS NULL OR a.ts >= sqlc.narg('ts_from'))
  AND (sqlc.narg('ts_to')::timestamptz IS NULL OR a.ts <= sqlc.narg('ts_to'))
ORDER BY
  CASE WHEN sqlc.arg('sort_key')::text = 'ts' AND NOT sqlc.arg('sort_desc')::bool THEN a.ts END ASC,
  CASE WHEN sqlc.arg('sort_key')::text = 'ts' AND sqlc.arg('sort_desc')::bool THEN a.ts END DESC,
  CASE WHEN sqlc.arg('sort_key')::text = 'severity' AND NOT sqlc.arg('sort_desc')::bool THEN a.severity END ASC,
  CASE WHEN sqlc.arg('sort_key')::text = 'severity' AND sqlc.arg('sort_desc')::bool THEN a.severity END DESC,
  CASE WHEN sqlc.arg('sort_key')::text = 'sid' AND NOT sqlc.arg('sort_desc')::bool THEN a.sid END ASC,
  CASE WHEN sqlc.arg('sort_key')::text = 'sid' AND sqlc.arg('sort_desc')::bool THEN a.sid END DESC,
  CASE WHEN sqlc.arg('sort_key')::text = 'src_ip' AND NOT sqlc.arg('sort_desc')::bool THEN a.src_ip END ASC,
  CASE WHEN sqlc.arg('sort_key')::text = 'src_ip' AND sqlc.arg('sort_desc')::bool THEN a.src_ip END DESC,
  CASE WHEN sqlc.arg('sort_key')::text = 'dest_ip' AND NOT sqlc.arg('sort_desc')::bool THEN a.dest_ip END ASC,
  CASE WHEN sqlc.arg('sort_key')::text = 'dest_ip' AND sqlc.arg('sort_desc')::bool THEN a.dest_ip END DESC,
  a.id DESC
LIMIT sqlc.arg('page_limit') OFFSET sqlc.arg('page_offset');

-- name: CountAlerts :one
SELECT count(*)
FROM alerts a
LEFT JOIN alert_groups g ON g.id = a.group_id
WHERE (sqlc.narg('task_id')::uuid IS NULL OR a.task_id = sqlc.narg('task_id'))
  AND (sqlc.narg('sid')::bigint IS NULL OR a.sid = sqlc.narg('sid'))
  AND (sqlc.narg('src_ip')::text IS NULL OR a.src_ip = sqlc.narg('src_ip'))
  AND (sqlc.narg('dest_ip')::text IS NULL OR a.dest_ip = sqlc.narg('dest_ip'))
  AND (sqlc.narg('severity')::int IS NULL OR a.severity = sqlc.narg('severity'))
  AND (sqlc.narg('proto')::text IS NULL OR a.proto = sqlc.narg('proto'))
  AND (sqlc.narg('triage_status')::text IS NULL OR COALESCE(g.status, 'new') = sqlc.narg('triage_status'))
  AND (sqlc.narg('ts_from')::timestamptz IS NULL OR a.ts >= sqlc.narg('ts_from'))
  AND (sqlc.narg('ts_to')::timestamptz IS NULL OR a.ts <= sqlc.narg('ts_to'));

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
