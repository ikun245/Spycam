import { Card, Col, Row, Statistic } from 'antd';
import { useQuery } from '@tanstack/react-query';
import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip as ETooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { api } from '../api/client';

interface OverviewResp {
  total_alerts: number;
  pending_groups: number;
  rules_total: number;
  rules_enabled: number;
  trend_by_hour: { bucket: string; cnt: number }[];
  top_src_ips: { src_ip: string; cnt: number }[];
  top_signatures: { sid: number; signature: string; cnt: number }[];
  top_dest_ports: { dest_port: number; cnt: number }[];
}

export default function Overview() {
  const { data } = useQuery({
    queryKey: ['overview'],
    queryFn: () => api.get<OverviewResp>('/api/v1/overview?hours=72'),
    refetchInterval: 8000,
  });

  return (
    <>
      <Row gutter={16}>
        <Col span={6}>
          <Card>
            <Statistic title="告警总数" value={data?.total_alerts ?? '-'} />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic title="待处置" value={data?.pending_groups ?? '-'} />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic
              title="规则启用"
              value={data ? `${data.rules_enabled}/${data.rules_total}` : '-'}
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic title="引擎状态" value="运行中" valueStyle={{ color: '#3f8600' }} />
          </Card>
        </Col>
      </Row>

      <Card title="告警趋势（按小时，近 72h）" style={{ marginTop: 16 }}>
        <ResponsiveContainer width="100%" height={260}>
          <BarChart data={data?.trend_by_hour ?? []}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis
              dataKey="bucket"
              tickFormatter={(v: string) => new Date(v).toLocaleTimeString('zh-CN', { hour: '2-digit' })}
            />
            <YAxis allowDecimals={false} />
            <ETooltip labelFormatter={(v) => new Date(String(v)).toLocaleString('zh-CN')} />
            <Bar dataKey="cnt" name="告警数" fill="#1677ff" />
          </BarChart>
        </ResponsiveContainer>
      </Card>

      <Row gutter={16} style={{ marginTop: 16 }}>
        <Col span={8}>
          <Card title="Top 源 IP" size="small">
            {(data?.top_src_ips ?? []).map((r) => (
              <div key={r.src_ip} style={{ display: 'flex', justifyContent: 'space-between' }}>
                <code>{r.src_ip}</code>
                <span>{r.cnt}</span>
              </div>
            ))}
          </Card>
        </Col>
        <Col span={8}>
          <Card title="Top 签名" size="small">
            {(data?.top_signatures ?? []).map((r) => (
              <div key={r.sid} style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}>
                <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {r.signature || `sid ${r.sid}`}
                </span>
                <span>{r.cnt}</span>
              </div>
            ))}
          </Card>
        </Col>
        <Col span={8}>
          <Card title="Top 目的端口" size="small">
            {(data?.top_dest_ports ?? []).map((r) => (
              <div key={r.dest_port} style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span>{r.dest_port}</span>
                <span>{r.cnt}</span>
              </div>
            ))}
          </Card>
        </Col>
      </Row>
    </>
  );
}
