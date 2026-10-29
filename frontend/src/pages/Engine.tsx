import { Card, Col, Row, Statistic } from 'antd';
import { useQuery } from '@tanstack/react-query';
import { api } from '../api/client';

interface EngineStatus {
  agent: { running: boolean; rule_load_ms?: number; rules_loaded?: number; kernel_drops?: number };
  latest_stats?: {
    ts: string;
    uptime_sec: number | null;
    rules_loaded: number | null;
    rule_load_ms: number | null;
    kernel_drops: number | null;
    alerts_total: number | null;
    rules_failed: number | null;
  };
}

function fmtUptime(sec: number | null | undefined): string {
  if (sec == null) return '-';
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  return h > 0 ? `${h} 小时 ${m} 分` : `${m} 分 ${sec % 60} 秒`;
}

export default function EngineStatus() {
  const { data } = useQuery({
    queryKey: ['engine'],
    queryFn: () => api.get<EngineStatus>('/api/v1/engine/status'),
    refetchInterval: 5000,
  });

  const st = data?.latest_stats;
  const ruleLoadMs = data?.agent?.rule_load_ms ?? st?.rule_load_ms;
  const drops = st?.kernel_drops ?? data?.agent?.kernel_drops;
  return (
    <Row gutter={[16, 16]}>
      <Col span={6}>
        <Card>
          <Statistic
            title="引擎进程"
            value={data?.agent?.running ? '运行中' : '不可达'}
            valueStyle={{ color: data?.agent?.running ? '#3f8600' : '#cf1322' }}
          />
        </Card>
      </Col>
      <Col span={6}>
        <Card>
          <Statistic title="已加载规则" value={st?.rules_loaded ?? data?.agent?.rules_loaded ?? '-'} />
        </Card>
      </Col>
      <Col span={6}>
        <Card>
          <Statistic
            title="加载失败规则"
            value={st?.rules_failed ?? '-'}
            valueStyle={{ color: (st?.rules_failed ?? 0) > 0 ? '#cf1322' : undefined }}
          />
        </Card>
      </Col>
      <Col span={6}>
        <Card>
          <Statistic title="最近一次规则校验+重载耗时 (ms)" value={ruleLoadMs ?? '尚未重载'} />
        </Card>
      </Col>
      <Col span={6}>
        <Card>
          <Statistic
            title="内核丢包"
            value={drops ?? '不适用（离线 pcap 模式）'}
            valueStyle={{ color: (drops ?? 0) > 0 ? '#cf1322' : undefined, fontSize: drops == null ? 16 : undefined }}
          />
        </Card>
      </Col>
      <Col span={6}>
        <Card>
          <Statistic title="引擎累计告警" value={st?.alerts_total ?? '-'} />
        </Card>
      </Col>
      <Col span={6}>
        <Card>
          <Statistic title="引擎运行时长" value={fmtUptime(st?.uptime_sec)} />
        </Card>
      </Col>
      <Col span={6}>
        <Card>
          <Statistic title="最近统计时间" value={st?.ts ? new Date(st.ts).toLocaleString() : '-'} valueStyle={{ fontSize: 16 }} />
        </Card>
      </Col>
      <Col span={24}>
        <Card title="说明">
          规则数、失败数、累计告警、运行时长来自 Suricata 每 10 秒输出的 stats 事件（worker 落库 engine_stats）；
          规则校验+重载耗时由 engine-agent 在每次 suricata -T 校验并热重载后记录；
          内核丢包仅在实时抓包模式下由 Suricata 上报，离线 pcap 回放模式无此指标，显示为“不适用”。刷新间隔 5 秒。
        </Card>
      </Col>
    </Row>
  );
}
