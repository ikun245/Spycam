import { App, Card, Switch, Table, Tag, Tooltip } from 'antd';
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

export default function Rules() {
  const { message } = App.useApp();
  const qc = useQueryClient();
  const [toggling, setToggling] = useState<number | null>(null);

  const { data, isLoading } = useQuery({
    queryKey: ['rules'],
    queryFn: () => api.get<{ items: RuleItem[] }>('/api/v1/rules'),
  });

  const toggle = async (sid: number, enabled: boolean) => {
    setToggling(sid);
    try {
      await api.patch(`/api/v1/rules/${sid}`, { enabled });
      message.success(`sid ${sid} 已${enabled ? '启用' : '停用'}并热重载生效`);
      qc.invalidateQueries({ queryKey: ['rules'] });
    } catch (e) {
      message.error(e instanceof Error ? e.message : '操作失败');
    } finally {
      setToggling(null);
    }
  };

  const columns = [
    { title: 'sid', dataIndex: 'sid', width: 100 },
    { title: '签名', dataIndex: 'msg', ellipsis: true },
    {
      title: '阶段',
      dataIndex: 'stage',
      width: 110,
      render: (v: string | null) => (v ? <Tag color={stageColor[v] ?? 'default'}>{v}</Tag> : '-'),
    },
    {
      title: 'ATT&CK',
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
    { title: 'severity', dataIndex: 'severity', width: 90 },
    {
      title: '启用',
      dataIndex: 'enabled',
      width: 90,
      render: (v: boolean, row: RuleItem) => (
        <Switch
          checked={v}
          loading={toggling === row.sid}
          onChange={(checked) => toggle(row.sid, checked)}
        />
      ),
    },
  ];

  return (
    <Card title="规则管理（启停即时热重载生效）">
      <Table
        rowKey="sid"
        size="small"
        loading={isLoading}
        columns={columns}
        dataSource={data?.items ?? []}
        pagination={false}
      />
    </Card>
  );
}
