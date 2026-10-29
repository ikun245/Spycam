-- name: CreatePcap :exec
INSERT INTO pcaps (id, original_name, stored_path, size_bytes, sha256, sample_type)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: GetPcap :one
SELECT id, original_name, stored_path, size_bytes, packet_count, sha256, sample_type, created_at
FROM pcaps WHERE id = $1;

-- name: ListPcaps :many
SELECT id, original_name, stored_path, size_bytes, packet_count, sha256, sample_type, created_at
FROM pcaps ORDER BY created_at DESC LIMIT $1 OFFSET $2;
