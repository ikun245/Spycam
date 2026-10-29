import { Card, Empty, Table, Typography } from 'antd';
import { useQuery } from '@tanstack/react-query';
import { api } from '../api/client';

interface AlertItem {
  id: number;
  task_id: string;
  ts: string;
  src_ip: string;
  src_port: number | null;
  dest_ip: string;
  dest_port: number | null;
  proto: string | null;
  app_proto: string | null;
  sid: number;
  signature: string | null;
  severity: number | null;
  category: string | null;
}

interface AlertsResp {
  total: number;
  items: AlertItem[];
}

const sevColor = (s: number | null) =>
  s === 1 ? '#cf1322' : s === 2 ? '#d46b08' : '#2f54eb';

export default function Alerts() {
  const { data, isLoading, error } = useQuery({
    queryKey: ['alerts'],
    queryFn: () => api.get<AlertsResp>('/api/v1/alerts?limit=100'),
    refetchInterval: 5000,
  });

  const columns = [
    {
      title: '时间',
      dataIndex: 'ts',
      width: 200,
      render: (v: string) => (v ? new Date(v).toLocaleString('zh-CN') : '-'),
    },
    { title: '源 IP', dataIndex: 'src_ip', render: (v: string) => <code>{v}</code> },
    { title: '端口', dataIndex: 'src_port', width: 80 },
    { title: '目的 IP', dataIndex: 'dest_ip', render: (v: string) => <code>{v}</code> },
    { title: '端口', dataIndex: 'dest_port', width: 80 },
    { title: '协议', dataIndex: 'app_proto', width: 90 },
    {
      title: '签名',
      dataIndex: 'signature',
      ellipsis: true,
      render: (v: string, row: AlertItem) => (
        <a onClick={() => window.location.assign(`/alerts/${row.id}`)}>{v || `sid ${row.sid}`}</a>
      ),
    },
    {
      title: 'severity',
      dataIndex: 'severity',
      width: 90,
      render: (v: number | null) => (
        <Typography.Text style={{ color: sevColor(v), fontWeight: 600 }}>{v ?? '-'}</Typography.Text>
      ),
    },
  ];

  return (
    <Card title={`告警列表${data ? `（共 ${data.total} 条）` : ''}`}>
      {error ? (
        <Empty description={`加载失败：${error instanceof Error ? error.message : '未知错误'}`} />
      ) : (
        <Table
          rowKey="id"
          size="small"
          loading={isLoading}
          columns={columns}
          dataSource={data?.items ?? []}
          pagination={{ pageSize: 20, total: data?.total }}
          locale={{ emptyText: <Empty description="暂无告警——上传 pcap 并回放后出现" /> }}
        />
      )}
    </Card>
  );
}
