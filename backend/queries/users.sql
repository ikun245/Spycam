-- name: GetUserByUsername :one
SELECT id, username, role FROM users WHERE username = $1;
