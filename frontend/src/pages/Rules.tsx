import { Card, Empty, Table } from 'antd';

// 骨架占位：P1 阶段接 GET /api/v1/rules + PATCH /api/v1/rules/{sid}（启停真实生效）
const columns = [
  { title: 'sid', dataIndex: 'sid' },
  { title: '消息', dataIndex: 'msg' },
  { title: '阶段', dataIndex: 'stage' },
  { title: '启用', dataIndex: 'enabled' },
];

export default function Rules() {
  return (
    <Card title="规则管理（骨架占位）">
      <Table columns={columns} dataSource={[]} locale={{ emptyText: <Empty description="待规则管理接入" /> }} />
    </Card>
  );
}
