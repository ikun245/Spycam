import { Button, Card, DatePicker, Empty, Form, Input, InputNumber, Select, Space, Table, Tag, Typography } from 'antd';
import type { TablePaginationConfig } from 'antd';
import type { SorterResult } from 'antd/es/table/interface';
import { keepPreviousData, useQuery } from '@tanstack/react-query';
import dayjs from 'dayjs';
import { Link, useSearchParams } from 'react-router-dom';
import { api } from '../api/client';
import { sevMeta, sevText, triageMeta, triageText } from '../labels';

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
  triage_status: string;
}

interface AlertsResp {
  total: number;
  items: AlertItem[];
}

// 与后端 alertSortKeys 白名单一致；列 key 不在此表的不发送 sort
const SORTABLE = new Set(['ts', 'severity', 'sid', 'src_ip', 'dest_ip']);
const FILTER_KEYS = ['from', 'to', 'severity', 'proto', 'status', 'sid', 'src_ip', 'dest_ip', 'task_id'] as const;
const PAGE_SIZE_DEFAULT = 20;

interface FilterForm {
  range?: [dayjs.Dayjs | null, dayjs.Dayjs | null] | null;
  severity?: number;
  proto?: string;
  status?: string;
  sid?: number;
  src_ip?: string;
  dest_ip?: string;
}

export default function Alerts() {
  const [sp, setSp] = useSearchParams();
  const [form] = Form.useForm<FilterForm>();

  const page = Math.max(1, Number(sp.get('page')) || 1);
  const pageSize = Math.min(200, Math.max(1, Number(sp.get('size')) || PAGE_SIZE_DEFAULT));
  const sort = sp.get('sort') ?? 'ts';
  const order = sp.get('order') === 'asc' ? 'asc' : 'desc';

  const apiParams = new URLSearchParams();
  apiParams.set('limit', String(pageSize));
  apiParams.set('offset', String((page - 1) * pageSize));
  apiParams.set('sort', sort);
  apiParams.set('order', order);
  for (const k of FILTER_KEYS) {
    const v = sp.get(k);
    if (v) apiParams.set(k, v);
  }
  const apiQuery = apiParams.toString();

  const { data, isLoading, isFetching, error } = useQuery({
    queryKey: ['alerts', apiQuery],
    queryFn: () => api.get<AlertsResp>(`/api/v1/alerts?${apiQuery}`),
    placeholderData: keepPreviousData,
    refetchInterval: 15000,
  });

  const updateParams = (patch: Record<string, string | undefined>) => {
    const next = new URLSearchParams(sp);
    for (const [k, v] of Object.entries(patch)) {
      if (v === undefined || v === '') next.delete(k);
      else next.set(k, v);
    }
    setSp(next);
  };

  const onSearch = (f: FilterForm) => {
    updateParams({
      from: f.range?.[0]?.toISOString(),
      to: f.range?.[1]?.toISOString(),
      severity: f.severity?.toString(),
      proto: f.proto,
      status: f.status,
      sid: f.sid?.toString(),
      src_ip: f.src_ip?.trim(),
      dest_ip: f.dest_ip?.trim(),
      page: undefined,
    });
  };

  const onReset = () => {
    form.resetFields();
    const next = new URLSearchParams();
    if (sp.get('task_id')) next.set('task_id', sp.get('task_id')!);
    setSp(next);
  };

  const onTableChange = (
    p: TablePaginationConfig,
    _f: unknown,
    s: SorterResult<AlertItem> | SorterResult<AlertItem>[],
  ) => {
    const one = Array.isArray(s) ? s[0] : s;
    const key = one?.order ? String(one.columnKey ?? one.field) : undefined;
    const nextSort = key && SORTABLE.has(key) ? key : 'ts';
    const nextOrder = key && one?.order === 'ascend' ? 'asc' : 'desc';
    const sortChanged = nextSort !== sort || nextOrder !== order;
    updateParams({
      page: !sortChanged && p.current && p.current > 1 ? String(p.current) : undefined,
      size: p.pageSize && p.pageSize !== PAGE_SIZE_DEFAULT ? String(p.pageSize) : undefined,
      sort: nextSort === 'ts' ? undefined : nextSort,
      order: nextOrder === 'asc' ? 'asc' : undefined,
    });
  };

  const sortOrderOf = (key: string) =>
    sort === key ? (order === 'asc' ? ('ascend' as const) : ('descend' as const)) : null;

  const columns = [
    {
      title: '时间（pcap 内时间）',
      dataIndex: 'ts',
      key: 'ts',
      width: 190,
      sorter: true,
      sortOrder: sortOrderOf('ts'),
      render: (v: string) => (v ? new Date(v).toLocaleString('zh-CN') : '-'),
    },
    {
      title: '源 IP',
      dataIndex: 'src_ip',
      key: 'src_ip',
      sorter: true,
      sortOrder: sortOrderOf('src_ip'),
      render: (v: string) => <code>{v}</code>,
    },
    { title: '源端口', dataIndex: 'src_port', width: 80 },
    {
      title: '目的 IP',
      dataIndex: 'dest_ip',
      key: 'dest_ip',
      sorter: true,
      sortOrder: sortOrderOf('dest_ip'),
      render: (v: string) => <code>{v}</code>,
    },
    { title: '目的端口', dataIndex: 'dest_port', width: 90 },
    {
      title: '协议',
      key: 'proto',
      width: 100,
      render: (_: unknown, r: AlertItem) => [r.proto, r.app_proto].filter(Boolean).join(' / ') || '-',
    },
    {
      title: '签名',
      dataIndex: 'signature',
      key: 'sid',
      ellipsis: true,
      sorter: true,
      sortOrder: sortOrderOf('sid'),
      render: (v: string, row: AlertItem) => <Link to={`/alerts/${row.id}`}>{v || `sid ${row.sid}`}</Link>,
    },
    {
      title: '威胁等级',
      dataIndex: 'severity',
      key: 'severity',
      width: 100,
      sorter: true,
      sortOrder: sortOrderOf('severity'),
      render: (v: number | null) => (
        <Typography.Text style={{ color: v ? sevMeta[v]?.color : undefined, fontWeight: 600 }}>
          {sevText(v)}
        </Typography.Text>
      ),
    },
    {
      title: '处置状态',
      dataIndex: 'triage_status',
      width: 90,
      render: (s: string) => <Tag color={triageMeta[s]?.color}>{triageText(s)}</Tag>,
    },
  ];

  const initial: FilterForm = {
    range:
      sp.get('from') || sp.get('to')
        ? [sp.get('from') ? dayjs(sp.get('from')) : null, sp.get('to') ? dayjs(sp.get('to')) : null]
        : undefined,
    severity: sp.get('severity') ? Number(sp.get('severity')) : undefined,
    proto: sp.get('proto') ?? undefined,
    status: sp.get('status') ?? undefined,
    sid: sp.get('sid') ? Number(sp.get('sid')) : undefined,
    src_ip: sp.get('src_ip') ?? undefined,
    dest_ip: sp.get('dest_ip') ?? undefined,
  };

  return (
    <Card title={`告警列表${data ? `（共 ${data.total} 条）` : ''}`}>
      <Form form={form} layout="inline" initialValues={initial} onFinish={onSearch} style={{ marginBottom: 12, rowGap: 8 }}>
        <Form.Item name="range" label="时间">
          <DatePicker.RangePicker showTime allowEmpty={[true, true]} />
        </Form.Item>
        <Form.Item name="severity" label="等级">
          <Select
            allowClear
            style={{ width: 100 }}
            options={Object.entries(sevMeta).map(([v, m]) => ({ value: Number(v), label: m.text }))}
          />
        </Form.Item>
        <Form.Item name="proto" label="协议">
          <Select allowClear style={{ width: 100 }} options={['TCP', 'UDP', 'ICMP'].map((v) => ({ value: v, label: v }))} />
        </Form.Item>
        <Form.Item name="status" label="处置">
          <Select
            allowClear
            style={{ width: 110 }}
            options={Object.entries(triageMeta).map(([v, m]) => ({ value: v, label: m.text }))}
          />
        </Form.Item>
        <Form.Item name="sid" label="SID">
          <InputNumber min={1} style={{ width: 120 }} />
        </Form.Item>
        <Form.Item name="src_ip" label="源 IP">
          <Input allowClear style={{ width: 150 }} />
        </Form.Item>
        <Form.Item name="dest_ip" label="目的 IP">
          <Input allowClear style={{ width: 150 }} />
        </Form.Item>
        <Form.Item>
          <Space>
            <Button type="primary" htmlType="submit">
              查询
            </Button>
            <Button onClick={onReset}>重置</Button>
          </Space>
        </Form.Item>
      </Form>
      {sp.get('task_id') && (
        <Typography.Paragraph type="secondary">
          仅显示回放任务 <code>{sp.get('task_id')}</code> 的告警
        </Typography.Paragraph>
      )}
      {error ? (
        <Empty description={`加载失败：${error instanceof Error ? error.message : '未知错误'}`} />
      ) : (
        <Table<AlertItem>
          rowKey="id"
          size="small"
          loading={isLoading || isFetching}
          columns={columns}
          dataSource={data?.items ?? []}
          onChange={onTableChange}
          pagination={{
            current: page,
            pageSize,
            total: data?.total ?? 0,
            showSizeChanger: true,
            pageSizeOptions: [20, 50, 100, 200],
            showTotal: (t) => `共 ${t} 条`,
          }}
          locale={{ emptyText: <Empty description="暂无告警——上传 pcap 并回放后出现，或调整过滤条件" /> }}
        />
      )}
    </Card>
  );
}
