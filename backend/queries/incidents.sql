-- name: UpsertIncident :one
INSERT INTO incidents (src_ip, start_ts, end_ts, severity)
VALUES ($1, $2, $3, $4)
RETURNING id;

-- name: ListGroupsForChain :many
SELECT g.id, g.sid, g.src_ip, g.src_port, g.dest_ip, g.dest_port, g.proto,
       g.first_seen, g.last_seen, g.hit_count, g.status,
       (SELECT min(a.severity) FROM alerts a WHERE a.group_id = g.id) AS severity,
       r.stage
FROM alert_groups g
LEFT JOIN rules r ON r.sid = g.sid
WHERE EXISTS (SELECT 1 FROM alerts a WHERE a.group_id = g.id AND a.task_id = $1)
ORDER BY g.src_ip, g.first_seen;

-- name: AttachGroupToIncident :exec
INSERT INTO incident_alerts (incident_id, group_id, stage_order)
VALUES ($1, $2, $3)
ON CONFLICT (incident_id, group_id) DO NOTHING;

-- name: UpdateIncidentSpan :exec
UPDATE incidents
SET end_ts = GREATEST(end_ts, $2),
    stage_summary = sqlc.narg('stage_summary'),
    severity = sqlc.narg('severity')
WHERE id = $1;

-- name: ListIncidents :many
SELECT * FROM incidents ORDER BY start_ts DESC LIMIT $1 OFFSET $2;

-- name: CountIncidents :one
SELECT count(*) FROM incidents;

-- name: GetIncident :one
SELECT * FROM incidents WHERE id = $1;

-- name: ListIncidentGroups :many
SELECT g.id, g.sid, g.src_ip, g.src_port, g.dest_ip, g.dest_port, g.proto,
       g.first_seen, g.last_seen, g.hit_count, g.status,
       r.stage, r.msg AS signature, r.mitre_tactic, r.mitre_technique,
       ia.stage_order
FROM incident_alerts ia
JOIN alert_groups g ON g.id = ia.group_id
LEFT JOIN rules r ON r.sid = g.sid
WHERE ia.incident_id = $1
ORDER BY ia.stage_order, g.first_seen;

-- name: LatestEngineStat :one
SELECT * FROM engine_stats ORDER BY ts DESC LIMIT 1;
