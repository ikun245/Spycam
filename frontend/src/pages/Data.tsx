import { App, Button, Card, Upload } from 'antd';
import { UploadOutlined } from '@ant-design/icons';
import { useRef } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import Tasks from './Tasks';

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
      <Tasks />
    </>
  );
}
