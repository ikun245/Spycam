import { Alert, Card, Descriptions, Empty, Statistic, Table, Tag } from 'antd';
import { useQuery } from '@tanstack/react-query';
import { api } from '../api/client';

interface Scenario {
  scenario: string;
  pcap: string;
  benign: boolean;
  alert_count: number;
  tp: number;
  fp: number;
  fn: number;
  precision: number;
  recall: number;
  f1: number;
}

interface Variant {
  scenario: string;
  variant_of: string;
  prediction: string;
  prediction_reason: string;
  actual: string;
  actual_alert_count: number;
  prediction_correct: boolean;
}

interface Report {
  generated_at: string;
  criteria: string;
  overall: { tp: number; fp: number; fn: number; precision: number; recall: number };
  scenarios: Scenario[];
  variants?: Variant[];
}

export default function Validation() {
  const { data, error, isLoading } = useQuery({
    queryKey: ['validation'],
    queryFn: () => api.get<{ report: Report }>('/api/v1/validation/latest'),
  });

  if (error) {
    return (
      <Card title="数据自验报告">
        <Empty
          description={
            error instanceof Error && error.message.includes('no validation report')
              ? '尚无报告：执行 docker compose --profile tools run --rm validator'
              : `加载失败：${error instanceof Error ? error.message : '未知错误'}`
          }
        />
      </Card>
    );
  }

  const r = data?.report;
  const scenarioCols = [
    { title: '场景', dataIndex: 'scenario' },
    { title: 'pcap', dataIndex: 'pcap', ellipsis: true },
    { title: '告警数', dataIndex: 'alert_count', width: 90 },
    { title: 'TP', dataIndex: 'tp', width: 70 },
    { title: 'FP', dataIndex: 'fp', width: 70 },
    { title: 'FN', dataIndex: 'fn', width: 70 },
    { title: 'P', dataIndex: 'precision', width: 80 },
    { title: 'R', dataIndex: 'recall', width: 80 },
    { title: 'F1', dataIndex: 'f1', width: 80 },
    {
      title: '类型',
      dataIndex: 'benign',
      width: 100,
      render: (v: boolean) => (v ? <Tag color="green">负样本</Tag> : <Tag color="red">攻击</Tag>),
    },
  ];

  const variantCols = [
    { title: '变种', dataIndex: 'scenario', ellipsis: true },
    { title: '基线场景', dataIndex: 'variant_of', ellipsis: true },
    { title: '预判', dataIndex: 'prediction', width: 80 },
    {
      title: '实际',
      dataIndex: 'actual',
      width: 110,
      render: (v: string, row: Variant) => `${v}（${row.actual_alert_count}）`,
    },
    {
      title: '预判是否成立',
      dataIndex: 'prediction_correct',
      width: 130,
      render: (v: boolean) => (v ? <Tag color="success">✅ 成立</Tag> : <Tag color="error">❌ 不符</Tag>),
    },
    { title: '预判依据', dataIndex: 'prediction_reason', ellipsis: true },
  ];

  return (
    <>
      <Card title="数据自验报告" loading={isLoading}>
        {r && (
          <>
            <Descriptions size="small" column={1} bordered>
              <Descriptions.Item label="生成时间">
                {new Date(r.generated_at).toLocaleString('zh-CN')}
              </Descriptions.Item>
              <Descriptions.Item label="判定口径">{r.criteria}</Descriptions.Item>
            </Descriptions>
            <div style={{ display: 'flex', gap: 32, marginTop: 16 }}>
              <Statistic title="总 TP" value={r.overall.tp} />
              <Statistic title="总 FP" value={r.overall.fp} />
              <Statistic title="总 FN" value={r.overall.fn} />
              <Statistic title="总体 Precision" value={r.overall.precision} />
              <Statistic title="总体 Recall" value={r.overall.recall} />
            </div>
          </>
        )}
      </Card>

      <Card title="分场景指标" style={{ marginTop: 16 }}>
        <Table
          rowKey="scenario"
          size="small"
          columns={scenarioCols}
          dataSource={r?.scenarios ?? []}
          pagination={false}
        />
      </Card>

      <Card title="变异测试（先预判，再验证）" style={{ marginTop: 16 }}>
        {r?.variants?.length ? (
          <Table
            rowKey="scenario"
            size="small"
            columns={variantCols}
            dataSource={r.variants}
            pagination={false}
          />
        ) : (
          <Alert type="info" showIcon message="尚未运行变异测试" />
        )}
      </Card>
    </>
  );
}
