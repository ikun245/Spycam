-- +goose Up
-- S6 引擎可观测：stats 事件里的 detect.alert 是自启动以来的累计值，不是每分钟速率，
-- 单独存为 alerts_total；rules_failed 来自 detect.engines[].rules_failed
ALTER TABLE engine_stats ADD COLUMN alerts_total BIGINT;
ALTER TABLE engine_stats ADD COLUMN rules_failed BIGINT;

-- +goose Down
ALTER TABLE engine_stats DROP COLUMN rules_failed;
ALTER TABLE engine_stats DROP COLUMN alerts_total;
