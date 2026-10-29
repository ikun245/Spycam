-- name: CreateTask :exec
INSERT INTO replay_tasks (id, pcap_id) VALUES ($1, $2);

-- name: GetTask :one
SELECT id, pcap_id, status, started_at, finished_at, error, rules_version, created_at
FROM replay_tasks WHERE id = $1;

-- name: ListTasks :many
SELECT t.id, t.pcap_id, t.status, t.started_at, t.finished_at, t.error, t.rules_version, t.created_at,
       p.original_name
FROM replay_tasks t JOIN pcaps p ON p.id = t.pcap_id
ORDER BY t.created_at DESC LIMIT $1 OFFSET $2;

-- name: UpdateTaskStatus :exec
UPDATE replay_tasks SET status = $2, started_at = now() WHERE id = $1;

-- name: FinishTask :exec
UPDATE replay_tasks SET status = $2, finished_at = now(), error = $3 WHERE id = $1;

-- name: ListQueuedTasks :many
SELECT id FROM replay_tasks WHERE status = 'queued';
