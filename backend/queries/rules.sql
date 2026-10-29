-- name: ListRules :many
SELECT sid, msg, enabled, classtype, severity, stage, mitre_tactic, mitre_technique, source
FROM rules ORDER BY sid;
