-- name: ListRules :many
SELECT sid, msg, enabled, classtype, severity, stage, mitre_tactic, mitre_technique, source
FROM rules ORDER BY sid;

-- name: GetRule :one
SELECT sid, raw, msg, enabled, classtype, severity, stage, mitre_tactic, mitre_technique, source
FROM rules WHERE sid = $1;

-- name: SetRuleEnabled :exec
UPDATE rules SET enabled = $2, updated_at = now() WHERE sid = $1;

-- name: ListEnabledRules :many
SELECT sid, raw, msg, enabled, classtype, severity, stage, mitre_tactic, mitre_technique, source
FROM rules WHERE enabled = TRUE ORDER BY sid;
