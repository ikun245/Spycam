-- name: UpsertAlertGroup :one
INSERT INTO alert_groups (group_hash, sid, src_ip, src_port, dest_ip, dest_port, proto,
                          first_seen, last_seen, hit_count)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8, 1)
ON CONFLICT (group_hash) DO UPDATE SET
  last_seen = GREATEST(alert_groups.last_seen, EXCLUDED.last_seen),
  hit_count = alert_groups.hit_count + 1
RETURNING id, group_hash, sid, src_ip, src_port, dest_ip, dest_port, proto,
          first_seen, last_seen, hit_count, status, assignee, updated_at;

-- name: GetGroupByHash :one
SELECT * FROM alert_groups WHERE group_hash = $1;

-- name: AttachAlertToGroup :exec
UPDATE alerts SET group_id = $2 WHERE id = $1;

-- name: ListGroups :many
SELECT g.*, r.stage, r.mitre_tactic, r.mitre_technique, r.msg AS signature
FROM alert_groups g
LEFT JOIN rules r ON r.sid = g.sid
WHERE (sqlc.narg('status')::text IS NULL OR g.status = sqlc.narg('status'))
ORDER BY g.last_seen DESC
LIMIT $1 OFFSET $2;

-- name: CountGroups :one
SELECT count(*) FROM alert_groups
WHERE (sqlc.narg('status')::text IS NULL OR status = sqlc.narg('status'));

-- name: GetGroup :one
SELECT g.*, r.stage, r.mitre_tactic, r.mitre_technique, r.msg AS signature
FROM alert_groups g
LEFT JOIN rules r ON r.sid = g.sid
WHERE g.id = $1;

-- name: SetGroupStatus :exec
UPDATE alert_groups SET status = $2, assignee = $3, updated_at = now() WHERE id = $1;

-- name: InsertTriageAction :exec
INSERT INTO triage_actions (group_id, from_status, to_status, actor_id, note)
VALUES ($1, $2, $3, $4, $5);
