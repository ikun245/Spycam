import { Card, Empty, Table, Tag, Typography } from 'antd';
import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { api } from '../api/client';
import { sevMeta, sevText, stageColor, stageText } from '../labels';

interface Incident {
  id: number;
  src_ip: string;
  start_ts: string;
  end_ts: string;
  stage_summary: string | null;
  severity: number | null;
}

interface IncidentGroup {
  id: number;
  sid: number;
  dest_ip: string;
  dest_port: number | null;
  first_seen: string;
  hit_count: number;
  status: string;
  stage: string | null;
  signature: string | null;
  mitre_technique: string | null;
  stage_order: number;
}

export default function Incidents() {
  const [selected, setSelected] = useState<number | null>(null);

  const { data, isLoading } = useQuery({
    queryKey: ['incidents'],
    queryFn: () => api.get<{ total: number; items: Incident[] }>('/api/v1/incidents?limit=50'),
  });

  const detail = useQuery({
    queryKey: ['incident', selected],
    queryFn: () => api.get<{ incident: Incident; groups: IncidentGroup[] }>(`/api/v1/incidents/${selected}`),
    enabled: selected !== null,
  });

  const cols = [
    { title: '源 IP', dataIndex: 'src_ip', render: (v: string) => <code>{v}</code> },
    {
      title: '攻击链',
      dataIndex: 'stage_summary',
      ellipsis: true,
      render: (v: string | null) =>
        v ? (
          <span>
            {v.split(' → ').map((s, i) => (
              <Tag key={i} color={stageColor[s] ?? 'default'}>
                {stageText(s)}
              </Tag>
            ))}
          </span>
        ) : (
          '-'
        ),
    },
    {
      title: '最高威胁等级',
      dataIndex: 'severity',
      width: 120,
      render: (v: number | null) => (v ? <Tag color={sevMeta[v]?.tag}>{sevText(v)}</Tag> : '-'),
    },
    {
      title: '开始',
      dataIndex: 'start_ts',
      width: 180,
      render: (v: string) => new Date(v).toLocaleString('zh-CN'),
    },
    {
      title: '结束',
      dataIndex: 'end_ts',
      width: 180,
      render: (v: string) => new Date(v).toLocaleString('zh-CN'),
    },
  ];

  const groupCols = [
    { title: '顺序', dataIndex: 'stage_order', width: 70 },
    {
      title: '阶段',
      dataIndex: 'stage',
      width: 110,
      render: (v: string | null) => <Tag color={v ? stageColor[v] : 'default'}>{v ? stageText(v) : '未分类'}</Tag>,
    },
    { title: '签名', dataIndex: 'signature', ellipsis: true },
    { title: '目的', dataIndex: 'dest_ip', render: (v: string) => <code>{v}</code> },
    { title: '端口', dataIndex: 'dest_port', width: 80 },
    { title: '命中', dataIndex: 'hit_count', width: 80 },
    {
      title: 'ATT&CK',
      dataIndex: 'mitre_technique',
      ellipsis: true,
      render: (v: string | null) => v ?? '-',
    },
  ];

  return (
    <>
      <Card title="攻击事件（同源 IP 告警按时间串联，点击查看攻击链）" style={{ marginBottom: 16 }}>
        <Table
          rowKey="id"
          size="small"
          loading={isLoading}
          columns={cols}
          dataSource={data?.items ?? []}
          pagination={{ pageSize: 10, total: data?.total }}
          locale={{ emptyText: <Empty description="暂无事件——回放多阶段攻击 pcap 后生成" /> }}
          onRow={(rec) => ({ onClick: () => setSelected(rec.id), style: { cursor: 'pointer' } })}
          rowClassName={(rec) => (rec.id === selected ? 'ant-table-row-selected' : '')}
        />
      </Card>

      {selected !== null && (
        <Card
          title={`事件 #${selected} 攻击链`}
          extra={
            <Typography.Link onClick={() => setSelected(null)}>收起</Typography.Link>
          }
        >
          <Table
            rowKey="id"
            size="small"
            loading={detail.isLoading}
            columns={groupCols}
            dataSource={detail.data?.groups ?? []}
            pagination={false}
          />
        </Card>
      )}
    </>
  );
}
