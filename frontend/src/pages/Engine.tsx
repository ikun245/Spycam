import { Card, Col, Row, Statistic } from 'antd';
import { useQuery } from '@tanstack/react-query';
import { api } from '../api/client';

interface EngineStatus {
  agent: { running: boolean; rules_loaded?: number; kernel_drops?: number };
  latest_stats?: {
    ts: string;
    uptime_sec: number | null;
    rules_loaded: number | null;
    rule_load_ms: number | null;
    kernel_drops: number | null;
    alerts_per_min: number | null;
  };
}

export default function EngineStatus() {
  const { data } = useQuery({
    queryKey: ['engine'],
    queryFn: () => api.get<EngineStatus>('/api/v1/engine/status'),
    refetchInterval: 5000,
  });

  const st = data?.latest_stats;
  return (
    <Row gutter={16}>
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
          <Statistic title="规则加载耗时 (ms)" value={st?.rule_load_ms ?? '-'} />
        </Card>
      </Col>
      <Col span={6}>
        <Card>
          <Statistic
            title="内核丢包"
            value={st?.kernel_drops ?? data?.agent?.kernel_drops ?? '-'}
            valueStyle={{ color: (st?.kernel_drops ?? 0) > 0 ? '#cf1322' : undefined }}
          />
        </Card>
      </Col>
      <Col span={24} style={{ marginTop: 16 }}>
        <Card title="说明">
          数据来源：Suricata 每 10 秒输出的 stats 事件（worker 落库 engine_stats），
          agent 存活状态来自 unix-socket 探针。刷新间隔 5 秒。
        </Card>
      </Col>
    </Row>
  );
}
