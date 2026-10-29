import { App, Button, Card, Empty, Table, Typography, Upload } from 'antd';
import { UploadOutlined } from '@ant-design/icons';
import { useRef } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '../api/client';
import Tasks from './Tasks';

interface PcapItem {
  id: string;
  original_name: string;
  size_bytes: number;
  sha256: string | null;
  created_at: string | null;
}

const formatSize = (n: number) =>
  n >= 1 << 20 ? `${(n / (1 << 20)).toFixed(1)} MB` : `${(n / 1024).toFixed(1)} KB`;

// 已上传 pcap 列表：展示全文件 sha256 便于核对样本，支持对已有样本再次回放
function PcapList() {
  const { message } = App.useApp();
  const qc = useQueryClient();
  const { data, isLoading } = useQuery({
    queryKey: ['pcaps'],
    queryFn: () => api.get<{ items: PcapItem[] }>('/api/v1/pcaps?limit=50'),
  });
  const replay = useMutation({
    mutationFn: (pcapId: string) => api.post('/api/v1/replay-tasks', { pcap_id: pcapId }),
    onSuccess: () => {
      message.success('已加入回放队列');
      qc.invalidateQueries({ queryKey: ['tasks'] });
    },
    onError: (e: Error) => message.error(`创建回放任务失败：${e.message}`),
  });

  const columns = [
    { title: '文件名', dataIndex: 'original_name', ellipsis: true },
    { title: '大小', dataIndex: 'size_bytes', width: 100, render: (n: number) => formatSize(n) },
    {
      title: 'SHA-256',
      dataIndex: 'sha256',
      ellipsis: true,
      render: (v: string | null) =>
        v ? <Typography.Text code copyable={{ text: v }}>{v.slice(0, 16)}…</Typography.Text> : '-',
    },
    {
      title: '上传时间（本地时区）',
      dataIndex: 'created_at',
      width: 180,
      render: (v: string | null) => (v ? new Date(v).toLocaleString('zh-CN') : '-'),
    },
    {
      title: '操作',
      width: 100,
      render: (_: unknown, row: PcapItem) => (
        <Button
          size="small"
          loading={replay.isPending && replay.variables === row.id}
          onClick={() => replay.mutate(row.id)}
        >
          重新回放
        </Button>
      ),
    },
  ];

  return (
    <Card title="已上传样本" style={{ marginBottom: 16 }}>
      <Table
        rowKey="id"
        size="small"
        loading={isLoading}
        columns={columns}
        dataSource={data?.items ?? []}
        pagination={false}
        locale={{ emptyText: <Empty description="还没有上传过 pcap" /> }}
      />
    </Card>
  );
}

// 数据与回放页：上传 pcap → 自动创建回放任务 → 任务列表轮询状态
export default function DataPage() {
  const { message } = App.useApp();
  const qc = useQueryClient();
  const creating = useRef(false);

  const customRequest = async (options: { file: unknown; onSuccess?: (b: unknown) => void; onError?: (e: Error) => void }) => {
    const file = options.file as File;
    const form = new FormData();
    form.append('file', file);
    form.append('name', file.name);
    try {
      const resp = await fetch('/api/v1/pcaps', {
        method: 'POST',
        body: form,
        credentials: 'same-origin',
        headers: { 'X-Requested-With': 'spycam' },
      });
      if (resp.status === 401) {
        window.location.href = '/login';
        return;
      }
      if (!resp.ok) {
        const body = (await resp.json().catch(() => ({}))) as { error?: string };
        throw new Error(body.error ?? `HTTP ${resp.status}`);
      }
      const created = (await resp.json()) as { id: string };
      // 上传成功后立即创建回放任务
      if (!creating.current) {
        creating.current = true;
        try {
          const tr = await fetch('/api/v1/replay-tasks', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'spycam' },
            body: JSON.stringify({ pcap_id: created.id }),
            credentials: 'same-origin',
          });
          if (!tr.ok) {
            const tb = (await tr.json().catch(() => ({}))) as { error?: string };
            message.warning(`已上传，但创建回放任务失败：${tb.error ?? tr.status}`);
          } else {
            message.success('已上传并加入回放队列');
          }
        } finally {
          creating.current = false;
        }
      }
      qc.invalidateQueries({ queryKey: ['tasks'] });
      qc.invalidateQueries({ queryKey: ['pcaps'] });
      options.onSuccess?.(created);
    } catch (e) {
      message.error(e instanceof Error ? e.message : '上传失败');
      options.onError?.(e as Error);
    }
  };

  return (
    <>
      <Card title="上传 pcap 并回放" style={{ marginBottom: 16 }}>
        <Upload.Dragger
          name="file"
          accept=".pcap,.pcapng"
          maxCount={1}
          showUploadList={false}
          customRequest={customRequest as never}
        >
          <Button icon={<UploadOutlined />}>选择 pcap 文件</Button>
          <p style={{ marginTop: 8, color: '#888' }}>
            支持 pcap / pcapng（≤64MB）；上传后自动创建回放任务
          </p>
        </Upload.Dragger>
      </Card>
      <PcapList />
      <Tasks />
    </>
  );
}
