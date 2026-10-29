-- +goose Up
-- 初始 schema（架构设计 §5.1）

CREATE TABLE users (
    id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'viewer',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE rules (
    sid             BIGINT PRIMARY KEY,
    raw             TEXT NOT NULL,
    msg             TEXT NOT NULL DEFAULT '',
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    classtype       TEXT,
    severity        INT,
    stage           TEXT,
    mitre_tactic    TEXT,
    mitre_technique TEXT,
    source          TEXT NOT NULL DEFAULT 'custom',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE rule_revisions (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    version    BIGINT NOT NULL,
    snapshot   JSONB NOT NULL,
    actor_id   BIGINT REFERENCES users (id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (version)
);

CREATE TABLE pcaps (
    id            UUID PRIMARY KEY,
    original_name TEXT NOT NULL,
    stored_path   TEXT NOT NULL UNIQUE,
    size_bytes    BIGINT NOT NULL DEFAULT 0,
    packet_count  BIGINT,
    sha256        TEXT,
    sample_type   TEXT NOT NULL DEFAULT 'unknown',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE replay_tasks (
    id            UUID PRIMARY KEY,
    pcap_id       UUID NOT NULL REFERENCES pcaps (id),
    status        TEXT NOT NULL DEFAULT 'queued',
    started_at    TIMESTAMPTZ,
    finished_at   TIMESTAMPTZ,
    error         TEXT,
    rules_version BIGINT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE alerts (
    id                BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    task_id           UUID NOT NULL REFERENCES replay_tasks (id),
    ts                TIMESTAMPTZ NOT NULL,
    ingested_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    flow_id           BIGINT,
    community_id      TEXT,
    src_ip            TEXT NOT NULL,
    src_port          INT,
    dest_ip           TEXT NOT NULL,
    dest_port         INT,
    proto             TEXT,
    app_proto         TEXT,
    sid               BIGINT NOT NULL,
    signature         TEXT,
    severity          INT,
    category          TEXT,
    payload_printable TEXT,
    raw               JSONB NOT NULL,
    group_id          BIGINT,
    dedup_key         TEXT NOT NULL,
    UNIQUE (task_id, dedup_key)
);

CREATE TABLE alert_groups (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    group_hash TEXT NOT NULL UNIQUE,
    sid        BIGINT NOT NULL,
    src_ip     TEXT NOT NULL,
    src_port   INT,
    dest_ip    TEXT NOT NULL,
    dest_port  INT,
    proto      TEXT,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen  TIMESTAMPTZ NOT NULL,
    hit_count  BIGINT NOT NULL DEFAULT 1,
    status     TEXT NOT NULL DEFAULT 'new',
    assignee   BIGINT REFERENCES users (id),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE flows (
    flow_id          BIGINT NOT NULL,
    task_id          UUID NOT NULL REFERENCES replay_tasks (id),
    src_ip           TEXT NOT NULL,
    src_port         INT,
    dest_ip          TEXT NOT NULL,
    dest_port        INT,
    proto            TEXT,
    app_proto        TEXT,
    pkts_toserver    BIGINT,
    bytes_toserver   BIGINT,
    pkts_toclient    BIGINT,
    bytes_toclient   BIGINT,
    state            TEXT,
    start_ts         TIMESTAMPTZ,
    end_ts           TIMESTAMPTZ,
    PRIMARY KEY (task_id, flow_id)
);

CREATE TABLE dns_events (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    task_id    UUID NOT NULL REFERENCES replay_tasks (id),
    flow_id    BIGINT,
    ts         TIMESTAMPTZ NOT NULL,
    src_ip     TEXT,
    dest_ip    TEXT,
    dns_type   TEXT,
    qname      TEXT,
    rrtype     TEXT,
    rcode      TEXT,
    raw        JSONB NOT NULL
);

CREATE TABLE http_events (
    id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    task_id       UUID NOT NULL REFERENCES replay_tasks (id),
    flow_id       BIGINT,
    ts            TIMESTAMPTZ NOT NULL,
    src_ip        TEXT,
    dest_ip       TEXT,
    dest_port     INT,
    http_method   TEXT,
    http_uri      TEXT,
    http_status   INT,
    http_user_agent TEXT,
    hostname      TEXT,
    raw           JSONB NOT NULL
);

CREATE TABLE tls_events (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    task_id      UUID NOT NULL REFERENCES replay_tasks (id),
    flow_id      BIGINT,
    ts           TIMESTAMPTZ NOT NULL,
    src_ip       TEXT,
    dest_ip      TEXT,
    dest_port    INT,
    sni          TEXT,
    version      TEXT,
    ja3          JSONB,
    raw          JSONB NOT NULL
);

CREATE TABLE incidents (
    id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    src_ip        TEXT NOT NULL,
    start_ts      TIMESTAMPTZ NOT NULL,
    end_ts        TIMESTAMPTZ NOT NULL,
    stage_summary TEXT,
    severity      INT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE incident_alerts (
    incident_id BIGINT NOT NULL REFERENCES incidents (id) ON DELETE CASCADE,
    group_id    BIGINT NOT NULL REFERENCES alert_groups (id),
    stage_order INT NOT NULL DEFAULT 0,
    PRIMARY KEY (incident_id, group_id)
);

CREATE TABLE triage_actions (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    group_id    BIGINT NOT NULL REFERENCES alert_groups (id),
    from_status TEXT NOT NULL,
    to_status   TEXT NOT NULL,
    actor_id    BIGINT REFERENCES users (id),
    note        TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE audit_log (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor_id   BIGINT REFERENCES users (id),
    action     TEXT NOT NULL,
    target     TEXT,
    detail     JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE engine_stats (
    ts            TIMESTAMPTZ PRIMARY KEY,
    uptime_sec    BIGINT,
    rules_loaded  BIGINT,
    rule_load_ms  BIGINT,
    kernel_drops  BIGINT,
    alerts_per_min BIGINT
);

CREATE INDEX idx_alerts_ts ON alerts (ts DESC);
CREATE INDEX idx_alerts_src_ip_ts ON alerts (src_ip, ts);
CREATE INDEX idx_alerts_sid_ts ON alerts (sid, ts);
CREATE INDEX idx_alerts_task ON alerts (task_id);
CREATE INDEX idx_groups_status ON alert_groups (status, last_seen DESC);
CREATE INDEX idx_flows_task_flow ON flows (task_id, flow_id);
CREATE INDEX idx_dns_task_ts ON dns_events (task_id, ts);
CREATE INDEX idx_http_task_ts ON http_events (task_id, ts);
CREATE INDEX idx_tls_task_ts ON tls_events (task_id, ts);
CREATE INDEX idx_tasks_status ON replay_tasks (status);

-- P0 阶段迁移仅前进不回滚（48h 项目约定）；schema 同时作为 sqlc 的 schema 输入
