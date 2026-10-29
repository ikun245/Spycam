import { App, Card, Empty, Segmented, Table, Tag } from 'antd';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { api } from '../api/client';
import { stageColor, stageText, triageMeta, triageText } from '../labels';

interface GroupItem {
  id: number;
  sid: number;
  signature: string;
  src_ip: string;
  dest_ip: string;
  dest_port: number | null;
  proto: string | null;
  first_seen: string;
  last_seen: string;
  hit_count: number;
  status: string;
  stage: string | null;
}

const statusTag = (s: string) => <Tag color={triageMeta[s]?.color ?? 'default'}>{triageText(s)}</Tag>;

// 聚合视图（S1）：同签名+同五元组合并，显示命中计数；处置（S2）直接在行上完成
export default function Groups() {
  const { message } = App.useApp();
  const qc = useQueryClient();
  const [statusFilter, setStatusFilter] = useState<string>('all');

  const { data, isLoading } = useQuery({
    queryKey: ['groups', statusFilter],
    queryFn: () =>
      api.get<{ total: number; items: GroupItem[] }>(
        `/api/v1/alert-groups?limit=100${statusFilter !== 'all' ? `&status=${statusFilter}` : ''}`,
      ),
    refetchInterval: 5000,
  });

  const triage = async (id: number, status: string) => {
    try {
      await api.patch(`/api/v1/alert-groups/${id}/status`, { status });
      message.success(`已标记为「${triageText(status)}」`);
      qc.invalidateQueries({ queryKey: ['groups'] });
    } catch (e) {
      message.error(e instanceof Error ? e.message : '操作失败');
    }
  };

  const columns = [
    { title: '签名', dataIndex: 'signature', ellipsis: true, render: (v: string, r: GroupItem) => v || `sid ${r.sid}` },
    {
      title: '阶段',
      dataIndex: 'stage',
      width: 100,
      render: (v: string | null) => (v ? <Tag color={stageColor[v]}>{stageText(v)}</Tag> : '-'),
    },
    {
      title: '五元组',
      key: 'tuple',
      ellipsis: true,
      render: (_: unknown, r: GroupItem) => (
        <code>
          {r.src_ip} → {r.dest_ip}:{r.dest_port ?? '-'}
        </code>
      ),
    },
    {
      title: '命中',
      dataIndex: 'hit_count',
      width: 70,
      sorter: (a: GroupItem, b: GroupItem) => a.hit_count - b.hit_count,
    },
    {
      title: '首次/最近',
      key: 'time',
      width: 200,
      render: (_: unknown, r: GroupItem) => (
        <span style={{ fontSize: 12 }}>
          {new Date(r.first_seen).toLocaleTimeString('zh-CN')} ~{' '}
          {new Date(r.last_seen).toLocaleTimeString('zh-CN')}
        </span>
      ),
    },
    { title: '状态', dataIndex: 'status', width: 90, render: (s: string) => statusTag(s) },
    {
      title: '处置',
      key: 'action',
      width: 200,
      render: (_: unknown, r: GroupItem) => (
        <span style={{ display: 'flex', gap: 6 }}>
          {r.status !== 'confirmed' && (
            <a onClick={() => triage(r.id, 'confirmed')}>确认</a>
          )}
          {r.status !== 'false_positive' && (
            <a onClick={() => triage(r.id, 'false_positive')}>误报</a>
          )}
          {r.status !== 'ignored' && <a onClick={() => triage(r.id, 'ignored')}>忽略</a>}
        </span>
      ),
    },
  ];

  return (
    <Card
      title="告警聚合组（同签名+同五元组）"
      extra={
        <Segmented
          value={statusFilter}
          onChange={(v) => setStatusFilter(v as string)}
          options={[
            { label: '全部', value: 'all' },
            { label: '待处置', value: 'new' },
            { label: '已确认', value: 'confirmed' },
            { label: '误报', value: 'false_positive' },
            { label: '已忽略', value: 'ignored' },
          ]}
        />
      }
    >
      <Table
        rowKey="id"
        size="small"
        loading={isLoading}
        columns={columns}
        dataSource={data?.items ?? []}
        pagination={{ pageSize: 15, total: data?.total }}
        locale={{ emptyText: <Empty description="暂无聚合组——回放 pcap 后自动生成" /> }}
      />
    </Card>
  );
}
