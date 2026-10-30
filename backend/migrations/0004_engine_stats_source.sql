-- +goose Up
-- 实时抓包实例与离线回放实例各自输出 stats，按来源区分，避免引擎页混读两个实例的计数器；
-- 主键从 ts 改为 (source, ts)，否则两实例同一秒的统计会因 ON CONFLICT (ts) 互相丢弃
ALTER TABLE engine_stats ADD COLUMN source TEXT NOT NULL DEFAULT 'replay';
ALTER TABLE engine_stats DROP CONSTRAINT engine_stats_pkey;
ALTER TABLE engine_stats ADD PRIMARY KEY (source, ts);

-- +goose Down
ALTER TABLE engine_stats DROP CONSTRAINT engine_stats_pkey;
DELETE FROM engine_stats WHERE source <> 'replay';
ALTER TABLE engine_stats ADD PRIMARY KEY (ts);
ALTER TABLE engine_stats DROP COLUMN source;
