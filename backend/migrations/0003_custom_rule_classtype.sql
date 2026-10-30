-- +goose Up
-- 早期规则构建器生成 classtype:custom，未在 classification.config 注册，引擎加载时报警告。
-- 按阶段改为已注册的 classtype；api 启动时会据此重新生成 rules-active 并重载引擎。
UPDATE rules
SET classtype = m.ct,
    raw = replace(raw, 'classtype:custom;', 'classtype:' || m.ct || ';')
FROM (VALUES ('recon', 'attempted-recon'),
             ('bruteforce', 'attempted-admin'),
             ('exploit', 'web-application-attack'),
             ('c2', 'command-and-control'),
             ('exfil', 'policy-violation')) AS m(stage, ct)
WHERE rules.classtype = 'custom' AND rules.stage = m.stage;

-- +goose Down
SELECT 1;
