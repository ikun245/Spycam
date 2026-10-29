import { Card, Col, Row, Statistic, Tag } from 'antd';
import { useQuery } from '@tanstack/react-query';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Pie,
  PieChart,
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
  severity_distribution: { severity: number; cnt: number }[];
  stage_distribution: { stage: string; cnt: number }[];
}

const stageNames: Record<string, string> = {
  recon: '侦察探测',
  bruteforce: '暴力破解',
  exploit: '漏洞利用',
  c2: '命令控制',
  exfil: '数据外泄',
  未分类: '未分类',
};

const sevNames: Record<number, { text: string; color: string }> = {
  1: { text: '高危', color: '#cf1322' },
  2: { text: '中危', color: '#d46b08' },
  3: { text: '低危', color: '#2f54eb' },
};

export default function Overview() {
  const { data } = useQuery({
    queryKey: ['overview'],
    // 不传 since：离线回放的告警时间戳是 pcap 内原始时间，按墙钟过滤会永远为空
    queryFn: () => api.get<OverviewResp>('/api/v1/overview'),
    refetchInterval: 8000,
  });

  const sevData = (data?.severity_distribution ?? []).map((d) => ({
    name: sevNames[d.severity]?.text ?? `等级${d.severity}`,
    value: d.cnt,
    color: sevNames[d.severity]?.color ?? '#8c8c8c',
  }));

  const stageData = (data?.stage_distribution ?? []).map((d) => ({
    name: stageNames[d.stage] ?? d.stage,
    cnt: d.cnt,
  }));

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
            <Statistic title="待处置事件" value={data?.pending_groups ?? '-'} />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic
              title="检测规则"
              value={data ? `${data.rules_enabled} / ${data.rules_total}` : '-'}
              suffix="条启用"
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic title="引擎状态" value="运行中" valueStyle={{ color: '#3f8600' }} />
          </Card>
        </Col>
      </Row>

      <Row gutter={16} style={{ marginTop: 16 }}>
        <Col span={14}>
          <Card title="告警时间分布（按小时）" size="small">
            <ResponsiveContainer width="100%" height={240}>
              <BarChart data={data?.trend_by_hour ?? []}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis
                  dataKey="bucket"
                  tickFormatter={(v: string) =>
                    new Date(v).toLocaleString('zh-CN', {
                      month: '2-digit',
                      day: '2-digit',
                      hour: '2-digit',
                    })
                  }
                />
                <YAxis allowDecimals={false} />
                <ETooltip
                  labelFormatter={(v) => new Date(String(v)).toLocaleString('zh-CN')}
                  formatter={(v) => [`${v} 条`, '告警数']}
                />
                <Bar dataKey="cnt" name="告警数" fill="#1677ff" />
              </BarChart>
            </ResponsiveContainer>
          </Card>
        </Col>
        <Col span={10}>
          <Card title="威胁等级分布" size="small">
            {sevData.length ? (
              <ResponsiveContainer width="100%" height={240}>
                <PieChart>
                  <Pie
                    data={sevData}
                    dataKey="value"
                    nameKey="name"
                    outerRadius={80}
                    label={(e: { name?: string; value?: number }) => `${e.name ?? ''} ${e.value ?? ''}`}
                  >
                    {sevData.map((entry) => (
                      <Cell key={entry.name} fill={entry.color} />
                    ))}
                  </Pie>
                  <Legend />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <Statistic title="暂无告警" value={0} />
            )}
          </Card>
        </Col>
      </Row>

      <Row gutter={16} style={{ marginTop: 16 }}>
        <Col span={8}>
          <Card title="攻击来源 TOP10" size="small">
            {(data?.top_src_ips ?? []).map((r) => (
              <div key={r.src_ip} style={{ display: 'flex', justifyContent: 'space-between', padding: '2px 0' }}>
                <code>{r.src_ip}</code>
                <Tag>{r.cnt} 次</Tag>
              </div>
            ))}
          </Card>
        </Col>
        <Col span={8}>
          <Card title="受攻击目标端口 TOP10" size="small">
            {(data?.top_dest_ports ?? []).map((r) => (
              <div key={r.dest_port} style={{ display: 'flex', justifyContent: 'space-between', padding: '2px 0' }}>
                <span>{r.dest_port} 端口</span>
                <Tag>{r.cnt} 次</Tag>
              </div>
            ))}
          </Card>
        </Col>
        <Col span={8}>
          <Card title="攻击类型分布" size="small">
            {stageData.length ? (
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={stageData} layout="vertical">
                  <XAxis type="number" allowDecimals={false} />
                  <YAxis type="category" dataKey="name" width={80} />
                  <ETooltip formatter={(v) => [`${v} 条`, '告警']} />
                  <Bar dataKey="cnt" name="告警数" fill="#722ed1" />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <Statistic title="暂无数据" value={0} />
            )}
          </Card>
        </Col>
      </Row>

      <Card title="命中规则 TOP10" size="small" style={{ marginTop: 16 }}>
        {(data?.top_signatures ?? []).map((r) => (
          <div key={r.sid} style={{ display: 'flex', justifyContent: 'space-between', padding: '2px 0' }}>
            <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {r.signature || `规则 ${r.sid}`}
            </span>
            <Tag>{r.cnt} 次</Tag>
          </div>
        ))}
      </Card>
    </>
  );
}
