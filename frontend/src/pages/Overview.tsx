import { Card, Col, Empty, Row, Statistic } from 'antd';

// 骨架占位：P1 阶段接 GET /api/v1/overview（时间趋势、Top 源 IP / 签名 / 目的端口）
export default function Overview() {
  return (
    <Row gutter={16}>
      <Col span={8}>
        <Card>
          <Statistic title="告警总数" value="-" />
        </Card>
      </Col>
      <Col span={8}>
        <Card>
          <Statistic title="待处置" value="-" />
        </Card>
      </Col>
      <Col span={8}>
        <Card>
          <Statistic title="引擎状态" value="骨架期" />
        </Card>
      </Col>
      <Col span={24} style={{ marginTop: 16 }}>
        <Card title="时间趋势 / Top 统计（待接入）">
          <Empty description="数据层落地后展示" />
        </Card>
      </Col>
    </Row>
  );
}
