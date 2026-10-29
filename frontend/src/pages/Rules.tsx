import { App, Button, Card, Col, Drawer, Form, Input, InputNumber, Row, Select, Switch, Table, Tag, Tooltip } from 'antd';
import { PlusOutlined } from '@ant-design/icons';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { api } from '../api/client';

interface RuleItem {
  sid: number;
  msg: string;
  enabled: boolean;
  classtype: string | null;
  severity: number | null;
  stage: string | null;
  mitre_tactic: string | null;
  mitre_technique: string | null;
  source: string;
}

const stageColor: Record<string, string> = {
  recon: 'blue',
  bruteforce: 'orange',
  exploit: 'red',
  c2: 'purple',
  exfil: 'magenta',
};

const stageNames: Record<string, string> = {
  recon: '侦察探测',
  bruteforce: '暴力破解',
  exploit: '漏洞利用',
  c2: '命令控制',
  exfil: '数据外泄',
};

const sevNames: Record<number, string> = { 1: '高危', 2: '中危', 3: '低危' };

interface CreateForm {
  protocol: string;
  src_ip: string;
  src_port: string;
  direction: string;
  dst_ip: string;
  dst_port: string;
  msg: string;
  content?: string;
  stage: string;
  severity: number;
  threshold_count?: number | null;
  threshold_seconds?: number | null;
  mitre_technique?: string;
}

export default function Rules() {
  const { message } = App.useApp();
  const qc = useQueryClient();
  const [toggling, setToggling] = useState<number | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [creating, setCreating] = useState(false);
  const [form] = Form.useForm<CreateForm>();

  const { data, isLoading } = useQuery({
    queryKey: ['rules'],
    queryFn: () => api.get<{ items: RuleItem[] }>('/api/v1/rules'),
  });

  const toggle = async (sid: number, enabled: boolean) => {
    setToggling(sid);
    try {
      await api.patch(`/api/v1/rules/${sid}`, { enabled });
      message.success(`规则 ${sid} 已${enabled ? '启用' : '停用'}并即时生效`);
      qc.invalidateQueries({ queryKey: ['rules'] });
    } catch (e) {
      message.error(e instanceof Error ? e.message : '操作失败');
    } finally {
      setToggling(null);
    }
  };

  const createRule = async (values: CreateForm) => {
    setCreating(true);
    try {
      const body = {
        action: 'alert',
        protocol: values.protocol,
        src_ip: values.src_ip,
        src_port: values.src_port,
        direction: values.direction,
        dst_ip: values.dst_ip,
        dst_port: values.dst_port,
        msg: values.msg,
        content: values.content ?? '',
        stage: values.stage,
        severity: values.severity,
        threshold: {
          count: values.threshold_count ?? 0,
          seconds: values.threshold_seconds ?? 0,
        },
        mitre_technique: values.mitre_technique ?? '',
      };
      const r = await api.post<{ sid: number }>('/api/v1/rules', body);
      message.success(`规则 ${r.sid} 已创建并热加载生效（新攻击手法无需重启引擎）`);
      setCreateOpen(false);
      form.resetFields();
      qc.invalidateQueries({ queryKey: ['rules'] });
    } catch (e) {
      message.error(e instanceof Error ? e.message : '创建失败');
    } finally {
      setCreating(false);
    }
  };

  const columns = [
    {
      title: '规则 ID',
      dataIndex: 'sid',
      width: 100,
      render: (v: number, row: RuleItem) =>
        row.source === 'custom' ? (
          <Tooltip title="自定义规则">
            <Tag color="geekblue">{v}</Tag>
          </Tooltip>
        ) : (
          <Tag>{v}</Tag>
        ),
    },
    { title: '规则描述', dataIndex: 'msg', ellipsis: true },
    {
      title: '攻击阶段',
      dataIndex: 'stage',
      width: 120,
      render: (v: string | null) =>
        v ? <Tag color={stageColor[v] ?? 'default'}>{stageNames[v] ?? v}</Tag> : '-',
    },
    {
      title: 'ATT&CK 技术',
      dataIndex: 'mitre_technique',
      ellipsis: true,
      render: (v: string | null, row: RuleItem) =>
        v ? (
          <Tooltip title={row.mitre_tactic}>
            <span>{v}</span>
          </Tooltip>
        ) : (
          '-'
        ),
    },
    {
      title: '威胁等级',
      dataIndex: 'severity',
      width: 100,
      render: (v: number | null) =>
        v ? <Tag color={v === 1 ? 'red' : v === 2 ? 'orange' : 'blue'}>{sevNames[v] ?? v}</Tag> : '-',
    },
    { title: '来源', dataIndex: 'source', width: 80, render: (v: string) => (v === 'custom' ? '自定义' : '内置') },
    {
      title: '启用',
      dataIndex: 'enabled',
      width: 80,
      render: (v: boolean, row: RuleItem) => (
        <Switch
          checked={v}
          loading={toggling === row.sid}
          onChange={(checked) => toggle(row.sid, checked)}
          size="small"
        />
      ),
    },
  ];

  return (
    <>
      <Card
        title="检测规则管理"
        extra={
          <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateOpen(true)}>
            新建自定义规则
          </Button>
        }
      >
        <Table
          rowKey="sid"
          size="small"
          loading={isLoading}
          columns={columns}
          dataSource={data?.items ?? []}
          pagination={false}
        />
      </Card>

      <Drawer
        title="新建自定义检测规则"
        width={560}
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        destroyOnClose
      >
        <Form
          form={form}
          layout="vertical"
          onFinish={createRule}
          initialValues={{
            protocol: 'tcp',
            direction: '->',
            stage: 'exploit',
            severity: 2,
            src_port: 'any',
            dst_port: 'any',
            src_ip: 'any',
            dst_ip: 'any',
          }}
        >
          <Row gutter={12}>
            <Col span={12}>
              <Form.Item name="protocol" label="协议" rules={[{ required: true }]}>
                <Select
                  options={[
                    { value: 'tcp', label: 'TCP' },
                    { value: 'udp', label: 'UDP' },
                    { value: 'icmp', label: 'ICMP' },
                    { value: 'http', label: 'HTTP' },
                    { value: 'dns', label: 'DNS' },
                    { value: 'tls', label: 'TLS' },
                    { value: 'ssh', label: 'SSH' },
                  ]}
                />
              </Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item name="direction" label="方向">
                <Select
                  options={[
                    { value: '->', label: '源 → 目的' },
                    { value: '<>', label: '双向' },
                  ]}
                />
              </Form.Item>
            </Col>
          </Row>
          <Row gutter={12}>
            <Col span={12}>
              <Form.Item
                name="src_ip"
                label="源地址"
                rules={[{ required: true }]}
                tooltip="支持 any、单 IP、CIDR（如 10.0.0.0/8）"
              >
                <Input placeholder="any / 1.2.3.4 / 10.0.0.0/8" />
              </Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item
                name="src_port"
                label="源端口"
                rules={[{ required: true }]}
                tooltip="支持 any、单端口、[1:200] 范围"
              >
                <Input placeholder="any / 22 / [1:200]" />
              </Form.Item>
            </Col>
          </Row>
          <Row gutter={12}>
            <Col span={12}>
              <Form.Item
                name="dst_ip"
                label="目的地址"
                rules={[{ required: true }]}
                tooltip="内网资产可用 $HOME_NET"
              >
                <Input placeholder="$HOME_NET / 10.0.0.5" />
              </Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item name="dst_port" label="目的端口" rules={[{ required: true }]}>
                <Input placeholder="any / 80 / [1:200]" />
              </Form.Item>
            </Col>
          </Row>
          <Form.Item name="msg" label="规则描述（中文）" rules={[{ required: true, max: 100 }]}>
            <Input placeholder="例如：检测到新型 Webshell 上传行为" />
          </Form.Item>
          <Form.Item
            name="content"
            label="匹配内容（可选）"
            tooltip="命中报文中包含该字符串即告警，忽略大小写；不能包含双引号"
          >
            <Input placeholder="例如：/etc/passwd" />
          </Form.Item>
          <Row gutter={12}>
            <Col span={12}>
              <Form.Item name="stage" label="攻击阶段" rules={[{ required: true }]}>
                <Select options={Object.entries(stageNames).map(([value, label]) => ({ value, label }))} />
              </Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item name="severity" label="威胁等级" rules={[{ required: true }]}>
                <Select
                  options={[
                    { value: 1, label: '高危' },
                    { value: 2, label: '中危' },
                    { value: 3, label: '低危' },
                  ]}
                />
              </Form.Item>
            </Col>
          </Row>
          <Row gutter={12}>
            <Col span={12}>
              <Form.Item
                name="threshold_count"
                label="频次阈值（次数，可选）"
                tooltip="同一来源在时间窗内达到次数才告警，用于扫描/爆破类"
              >
                <InputNumber min={0} style={{ width: '100%' }} placeholder="如 20" />
              </Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item name="threshold_seconds" label="统计时间窗（秒）">
                <InputNumber min={0} style={{ width: '100%' }} placeholder="如 10" />
              </Form.Item>
            </Col>
          </Row>
          <Form.Item name="mitre_technique" label="ATT&CK 技术编号（可选）">
            <Input placeholder="如 T1110 Brute Force" />
          </Form.Item>
          <Button type="primary" htmlType="submit" block loading={creating}>
            创建并热加载生效
          </Button>
        </Form>
      </Drawer>
    </>
  );
}
