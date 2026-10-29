import { Button, Card, Descriptions, Space, Spin, Tag, Tooltip, Typography } from 'antd';
import { DownloadOutlined } from '@ant-design/icons';
import { useQuery } from '@tanstack/react-query';
import { useParams } from 'react-router-dom';
import { api } from '../api/client';
import { sevMeta, sevText, stageColor, stageText } from '../labels';

// 取证下载是同源 GET，浏览器自动带 Cookie；参数经 URLSearchParams 编码
const exportHref = (id: number, scope: 'flow' | 'hosts') =>
  `/api/v1/alerts/${encodeURIComponent(String(id))}/pcap?${new URLSearchParams({ scope })}`;

interface AlertDetail {
  alert: {
    id: number;
    task_id: string;
    ts: string;
    ingested_at: string;
    flow_id: number | null;
    community_id: string | null;
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
    payload_printable: string | null;
  };
  raw: Record<string, unknown>;
  rule_raw?: string;
  rule_stage?: string | null;
  rule_mitre_tactic?: string | null;
  rule_mitre_technique?: string | null;
  flow?: Record<string, unknown>;
}

export default function AlertDetail() {
  const { id } = useParams<{ id: string }>();
  const { data, isLoading, error } = useQuery({
    queryKey: ['alert', id],
    queryFn: () => api.get<AlertDetail>(`/api/v1/alerts/${id}`),
  });

  if (isLoading) return <Spin />;
  if (error || !data)
    return <Card>加载失败：{error instanceof Error ? error.message : '未知错误'}</Card>;

  const a = data.alert;
  return (
    <Card
      title={`告警详情 #${a.id}`}
      extra={
        <Space>
          <Tooltip title="按双向五元组切出告警前 5 分钟至后 1 分钟的报文（需 analyst 权限）">
            <Button size="small" icon={<DownloadOutlined />} href={exportHref(a.id, 'flow')}>
              取证：本会话
            </Button>
          </Tooltip>
          <Tooltip title="仅按 IP 对 + 协议切片，适合扫描类告警（每个探测包源端口不同）">
            <Button size="small" icon={<DownloadOutlined />} href={exportHref(a.id, 'hosts')}>
              取证：主机对
            </Button>
          </Tooltip>
          <Tag>{`sid ${a.sid}`}</Tag>
        </Space>
      }
    >
      <Descriptions bordered size="small" column={2}>
        <Descriptions.Item label="时间">{new Date(a.ts).toLocaleString('zh-CN')}</Descriptions.Item>
        <Descriptions.Item label="入库时间">
          {new Date(a.ingested_at).toLocaleString('zh-CN')}
        </Descriptions.Item>
        <Descriptions.Item label="五元组">
          <code>
            {a.src_ip}:{a.src_port ?? '-'} → {a.dest_ip}:{a.dest_port ?? '-'} {a.proto ?? ''}
          </code>
        </Descriptions.Item>
        <Descriptions.Item label="应用协议">{a.app_proto ?? '-'}</Descriptions.Item>
        <Descriptions.Item label="签名" span={2}>
          {a.signature ?? '-'}
        </Descriptions.Item>
        <Descriptions.Item label="威胁等级">
          <Tag color={a.severity ? sevMeta[a.severity]?.tag : undefined}>{sevText(a.severity)}</Tag>
        </Descriptions.Item>
        <Descriptions.Item label="分类">{a.category ?? '-'}</Descriptions.Item>
        <Descriptions.Item label="攻击阶段">
          {data.rule_stage ? (
            <Tag color={stageColor[data.rule_stage]}>{stageText(data.rule_stage)}</Tag>
          ) : (
            '-'
          )}
        </Descriptions.Item>
        <Descriptions.Item label="ATT&CK">
          {data.rule_mitre_technique ?? '-'}
        </Descriptions.Item>
      </Descriptions>

      {data.rule_raw && (
        <Card type="inner" title="规则原文" style={{ marginTop: 16 }}>
          <Typography.Paragraph code copyable style={{ whiteSpace: 'pre-wrap', marginBottom: 0 }}>
            {data.rule_raw}
          </Typography.Paragraph>
        </Card>
      )}

      {a.payload_printable && (
        <Card type="inner" title="Payload 摘录（纯文本渲染）" style={{ marginTop: 16 }}>
          <pre style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
            {a.payload_printable}
          </pre>
        </Card>
      )}

      {data.flow && (
        <Card type="inner" title="关联 Flow" style={{ marginTop: 16 }}>
          <pre style={{ margin: 0, fontSize: 12 }}>
            {JSON.stringify(data.flow, null, 2)}
          </pre>
        </Card>
      )}

      <Card type="inner" title="原始 JSON" style={{ marginTop: 16 }}>
        <pre style={{ margin: 0, fontSize: 12, maxHeight: 400, overflow: 'auto' }}>
          {JSON.stringify(data.raw, null, 2)}
        </pre>
      </Card>
    </Card>
  );
}
