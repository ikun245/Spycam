-- name: UpsertFlow :exec
INSERT INTO flows (flow_id, task_id, src_ip, src_port, dest_ip, dest_port, proto, app_proto,
                   pkts_toserver, bytes_toserver, pkts_toclient, bytes_toclient, state, start_ts, end_ts)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
ON CONFLICT (task_id, flow_id) DO UPDATE SET
  app_proto = EXCLUDED.app_proto,
  pkts_toserver = EXCLUDED.pkts_toserver,
  bytes_toserver = EXCLUDED.bytes_toserver,
  pkts_toclient = EXCLUDED.pkts_toclient,
  bytes_toclient = EXCLUDED.bytes_toclient,
  state = EXCLUDED.state,
  end_ts = EXCLUDED.end_ts;

-- name: CreateDnsEvent :exec
INSERT INTO dns_events (task_id, flow_id, ts, src_ip, dest_ip, dns_type, qname, rrtype, rcode, raw)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);

-- name: CreateHttpEvent :exec
INSERT INTO http_events (task_id, flow_id, ts, src_ip, dest_ip, dest_port,
                         http_method, http_uri, http_status, http_user_agent, hostname, raw)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12);

-- name: CreateTlsEvent :exec
INSERT INTO tls_events (task_id, flow_id, ts, src_ip, dest_ip, dest_port, sni, version, raw)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);

-- name: CreateEngineStat :exec
INSERT INTO engine_stats (ts, uptime_sec, rules_loaded, kernel_drops, alerts_total, rules_failed)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (ts) DO NOTHING;
