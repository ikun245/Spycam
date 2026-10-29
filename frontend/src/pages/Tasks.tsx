import { Card, Empty, Table, Tag, Typography } from 'antd';
import { useQuery } from '@tanstack/react-query';
import { api } from '../api/client';

interface TaskItem {
  id: string;
  pcap_id: string;
  status: string;
  started_at: string | null;
  finished_at: string | null;
  error: string | null;
  original_name: string;
  created_at: string;
}

const statusTag = (s: string) => {
  const map: Record<string, { color: string }> = {
    queued: { color: 'default' },
    running: { color: 'processing' },
    done: { color: 'success' },
    failed: { color: 'error' },
  };
  return <Tag color={map[s]?.color ?? 'default'}>{s}</Tag>;
};

export default function Tasks() {
  const { data, isLoading } = useQuery({
    queryKey: ['tasks'],
    queryFn: () => api.get<{ items: TaskItem[] }>('/api/v1/replay-tasks?limit=50'),
    refetchInterval: 3000,
  });

  const columns = [
    { title: 'pcap', dataIndex: 'original_name', ellipsis: true },
    {
      title: '状态',
      dataIndex: 'status',
      width: 100,
      render: (s: string) => statusTag(s),
    },
    {
      title: '开始时间',
      dataIndex: 'started_at',
      width: 180,
      render: (v: string | null) => (v ? new Date(v).toLocaleString('zh-CN') : '-'),
    },
    {
      title: '耗时说明',
      dataIndex: 'error',
      ellipsis: true,
      render: (v: string | null) =>
        v ? <Typography.Text type="danger">{v}</Typography.Text> : '-',
    },
  ];

  return (
    <Card title="回放任务">
      <Table
        rowKey="id"
        size="small"
        loading={isLoading}
        columns={columns}
        dataSource={data?.items ?? []}
        pagination={false}
        locale={{ emptyText: <Empty description="还没有回放任务" /> }}
      />
    </Card>
  );
}
