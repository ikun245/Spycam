-- name: InsertAudit :exec
-- 会话里只有用户名，actor_id 用子查询解析；用户不存在（如登录失败）时为 NULL
INSERT INTO audit_log (actor_id, action, target, detail)
VALUES ((SELECT id FROM users WHERE username = sqlc.arg('username')), sqlc.arg('action'), sqlc.arg('target'), sqlc.arg('detail'));

-- name: CreateRuleRevision :one
-- 规则集每次成功生效后递增版本号，快照记录本次变更与全部规则的启停状态
INSERT INTO rule_revisions (version, snapshot, actor_id)
SELECT COALESCE(MAX(rv.version), 0) + 1,
       jsonb_build_object(
           'change', sqlc.arg('change')::jsonb,
           'rules', (SELECT COALESCE(jsonb_agg(jsonb_build_object('sid', ru.sid, 'enabled', ru.enabled) ORDER BY ru.sid), '[]'::jsonb) FROM rules ru)
       ),
       (SELECT id FROM users WHERE username = sqlc.arg('username'))
FROM rule_revisions rv
RETURNING version;

-- name: ListAuditLog :many
SELECT a.id, COALESCE(u.username, '')::text AS username, a.action, a.target, a.detail, a.created_at
FROM audit_log a
LEFT JOIN users u ON u.id = a.actor_id
ORDER BY a.id DESC
LIMIT $1;
