import { Card, Empty, Table } from 'antd';

// 骨架占位：P1 阶段接 GET /api/v1/alerts（过滤/排序/分页，view=raw|grouped）
const columns = [
  { title: '时间', dataIndex: 'ts' },
  { title: '源 IP', dataIndex: 'src_ip' },
  { title: '目的 IP', dataIndex: 'dest_ip' },
  { title: '签名', dataIndex: 'signature' },
  { title: 'severity', dataIndex: 'severity' },
  { title: '状态', dataIndex: 'status' },
];

export default function Alerts() {
  return (
    <Card title="告警列表（骨架占位）">
      <Table columns={columns} dataSource={[]} locale={{ emptyText: <Empty description="待数据层接入" /> }} />
    </Card>
  );
}
