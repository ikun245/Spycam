import { Alert, Card, Table, Tag, Typography } from 'antd';
import type { ColumnsType } from 'antd/es/table';
import { useQuery } from '@tanstack/react-query';
import { api, ApiError } from '../api/client';

interface AuditItem {
  id: number;
  username: string;
  action: string;
  target: string | null;
  detail: Record<string, unknown> | null;
  created_at: string;
}

const actionMeta: Record<string, { text: string; color: string }> = {
  'login.success': { text: '登录成功', color: 'green' },
  'login.failure': { text: '登录失败', color: 'orange' },
  'login.locked': { text: '登录锁定', color: 'red' },
  logout: { text: '退出登录', color: 'default' },
  'rule.toggle': { text: '规则启停', color: 'blue' },
  'rule.create': { text: '新建规则', color: 'blue' },
  'group.triage': { text: '告警处置', color: 'purple' },
  'pcap.upload': { text: '上传样本', color: 'cyan' },
  'task.create': { text: '创建回放', color: 'cyan' },
};

const columns: ColumnsType<AuditItem> = [
  { title: '时间', dataIndex: 'created_at', width: 180, render: (v: string) => new Date(v).toLocaleString() },
  { title: '操作人', dataIndex: 'username', width: 120, render: (v: string) => v || '-' },
  {
    title: '动作',
    dataIndex: 'action',
    width: 110,
    render: (v: string) => <Tag color={actionMeta[v]?.color}>{actionMeta[v]?.text ?? v}</Tag>,
  },
  { title: '对象', dataIndex: 'target', width: 300, render: (v: string | null) => v ?? '-' },
  {
    title: '详情',
    dataIndex: 'detail',
    // 详情可能包含用户输入（规则原文、处置备注），只作纯文本渲染
    render: (v: AuditItem['detail']) =>
      v ? (
        <Typography.Text code style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
          {JSON.stringify(v)}
        </Typography.Text>
      ) : (
        '-'
      ),
  },
];

export default function AuditLog() {
  const { data, isLoading, error } = useQuery({
    queryKey: ['audit'],
    queryFn: () => api.get<{ items: AuditItem[] }>('/api/v1/audit-log?limit=200'),
    refetchInterval: 15000,
    retry: false,
  });

  if (error instanceof ApiError && error.status === 403) {
    return <Alert type="warning" showIcon message="审计日志仅管理员可查看" />;
  }
  return (
    <Card title="审计日志（最近 200 条）">
      <Table<AuditItem>
        rowKey="id"
        size="small"
        loading={isLoading}
        columns={columns}
        dataSource={data?.items ?? []}
        pagination={{ pageSize: 50, showTotal: (t) => `共 ${t} 条` }}
      />
    </Card>
  );
}
