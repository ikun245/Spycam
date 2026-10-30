import { Alert, Card, Col, Row, Statistic, Tag, Typography } from 'antd';
import { useQuery } from '@tanstack/react-query';
import { api } from '../api/client';

interface EngineStat {
  ts: string;
  uptime_sec: number | null;
  rules_loaded: number | null;
  rule_load_ms: number | null;
  kernel_drops: number | null;
  alerts_total: number | null;
  rules_failed: number | null;
}

interface EngineStatus {
  agent: { running: boolean; rule_load_ms?: number; rules_loaded?: number; kernel_drops?: number };
  latest_stats?: EngineStat;
  live_stats?: EngineStat;
  live_iface?: string;
}

function fmtUptime(sec: number | null | undefined): string {
  if (sec == null) return '-';
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  return h > 0 ? `${h} 小时 ${m} 分` : `${m} 分 ${sec % 60} 秒`;
}

export default function EngineStatus() {
  const { data } = useQuery({
    queryKey: ['engine'],
    queryFn: () => api.get<EngineStatus>('/api/v1/engine/status'),
    refetchInterval: 5000,
  });

  const st = data?.latest_stats;
  const live = data?.live_stats;
  const ruleLoadMs = data?.agent?.rule_load_ms ?? st?.rule_load_ms;
  const drops = st?.kernel_drops ?? data?.agent?.kernel_drops;
  return (
    <Row gutter={[16, 16]}>
      <Col span={6}>
        <Card>
          <Statistic
            title="引擎进程"
            value={data?.agent?.running ? '运行中' : '不可达'}
            valueStyle={{ color: data?.agent?.running ? '#3f8600' : '#cf1322' }}
          />
        </Card>
      </Col>
      <Col span={6}>
        <Card>
          <Statistic title="已加载规则" value={st?.rules_loaded ?? data?.agent?.rules_loaded ?? '-'} />
        </Card>
      </Col>
      <Col span={6}>
        <Card>
          <Statistic
            title="加载失败规则"
            value={st?.rules_failed ?? '-'}
            valueStyle={{ color: (st?.rules_failed ?? 0) > 0 ? '#cf1322' : undefined }}
          />
        </Card>
      </Col>
      <Col span={6}>
        <Card>
          <Statistic title="最近一次规则校验+重载耗时 (ms)" value={ruleLoadMs ?? '尚未重载'} />
        </Card>
      </Col>
      <Col span={6}>
        <Card>
          <Statistic
            title="内核丢包"
            value={drops ?? '不适用（离线 pcap 模式）'}
            valueStyle={{ color: (drops ?? 0) > 0 ? '#cf1322' : undefined, fontSize: drops == null ? 16 : undefined }}
          />
        </Card>
      </Col>
      <Col span={6}>
        <Card>
          <Statistic title="引擎累计告警" value={st?.alerts_total ?? '-'} />
        </Card>
      </Col>
      <Col span={6}>
        <Card>
          <Statistic title="引擎运行时长" value={fmtUptime(st?.uptime_sec)} />
        </Card>
      </Col>
      <Col span={6}>
        <Card>
          <Statistic title="最近统计时间" value={st?.ts ? new Date(st.ts).toLocaleString() : '-'} valueStyle={{ fontSize: 16 }} />
        </Card>
      </Col>
      <Col span={24}>
        <Card title="说明">
          规则数、失败数、累计告警、运行时长来自 Suricata 每 10 秒输出的 stats 事件（worker 落库 engine_stats）；
          规则校验+重载耗时由 engine-agent 在每次 suricata -T 校验并热重载后记录；
          内核丢包仅在实时抓包模式下由 Suricata 上报，离线 pcap 回放模式无此指标，显示为“不适用”。
          以上为离线回放引擎；实时抓包引擎（live profile）的状态与接入方式见下方。刷新间隔 5 秒。
        </Card>
      </Col>
      <LiveEngineSection st={live} iface={data?.live_iface ?? 'eth0'} />
    </Row>
  );
}

// 实时抓包引擎（live profile）的 stats 每 10 秒一条，超过 60 秒无更新视为已停止
function LiveEngineSection({ st, iface }: { st?: EngineStat; iface: string }) {
  const stale = !st || Date.now() - new Date(st.ts).getTime() > 60_000;
  return (
    <Col span={24}>
      <Card
        title="实时抓包引擎（live profile）"
        extra={
          <Tag color={!st ? 'default' : stale ? 'red' : 'green'}>
            {!st ? '未启用' : stale ? '已停止' : '抓包中'}
          </Tag>
        }
      >
        {st && <LiveEngineStats st={st} stale={stale} iface={iface} />}
        {stale && <LiveSetupGuide iface={iface} enabled={!!st} />}
      </Card>
    </Col>
  );
}

function LiveSetupGuide({ iface, enabled }: { iface: string; enabled: boolean }) {
  return (
    <div style={{ marginTop: enabled ? 16 : 0 }}>
      <Alert
        type={enabled ? 'warning' : 'info'}
        showIcon
        message={
          enabled
            ? '实时抓包引擎超过 60 秒没有上报统计，可能已停止或网卡名不正确'
            : '实时抓包未启用：当前只有离线 pcap 回放'
        }
        description="实时抓包由宿主机上的独立 Suricata 容器完成（host 网络 + af-packet）。出于安全设计，Web 界面不能启停容器，需要在服务器上按以下步骤操作。"
      />
      <Typography style={{ marginTop: 16 }}>
        <Typography.Title level={5}>1. 监控本机（Linux 服务器自身）流量</Typography.Title>
        <Typography.Paragraph>
          用 <Typography.Text code>ip -br link</Typography.Text> 查看网卡名，在 .env 中设置
          <Typography.Text code>LIVE_IFACE=网卡名</Typography.Text>（当前配置：
          <Typography.Text code>{iface}</Typography.Text>），可选设置
          <Typography.Text code>LIVE_HOME_NET=[10.0.0.0/8,192.168.0.0/16]</Typography.Text>，然后执行：
        </Typography.Paragraph>
        <Typography.Paragraph>
          <Typography.Text code copyable>docker compose --profile live up -d</Typography.Text>
        </Typography.Paragraph>
        <Typography.Title level={5}>2. 监控其他设备 / 网络的流量</Typography.Title>
        <Typography.Paragraph>
          本系统检测的是“原始流量”，需要把流量镜像到本机的某块网卡上，并把该网卡设为 LIVE_IFACE：
        </Typography.Paragraph>
        <ul>
          <li>交换机端口镜像（SPAN/RSPAN）或网络 TAP，接到服务器的一块专用网卡；</li>
          <li>云厂商流量镜像（如阿里云/腾讯云/AWS VPC 流量镜像），以 VXLAN 封装发到本机，Suricata 会自动解封装；</li>
          <li>防火墙、NDR 等安全产品若支持“流量镜像/抓包外发”，配置为镜像到本机网卡。</li>
        </ul>
        <Typography.Paragraph type="secondary">
          只有日志或告警输出（syslog）的安全产品不提供原始流量，无法接入本引擎；这类设备可先导出 pcap，在「数据与回放」中上传回放。
        </Typography.Paragraph>
        <Typography.Title level={5}>3. 验证</Typography.Title>
        <Typography.Paragraph>
          约 10 秒后本卡片变为“抓包中”；可用
          <Typography.Text code copyable>docker logs -f spycam-suricata-live</Typography.Text>
          查看引擎日志。实时告警会推送到告警列表。
        </Typography.Paragraph>
      </Typography>
    </div>
  );
}

function LiveEngineStats({ st, stale, iface }: { st: EngineStat; stale: boolean; iface: string }) {
  return (
    <Row gutter={[16, 16]}>
      <Col span={6}>
        <Statistic
          title={`状态（网卡 ${iface}）`}
          value={stale ? '无更新（已停止？）' : '抓包中'}
          valueStyle={{ color: stale ? '#cf1322' : '#3f8600' }}
        />
      </Col>
      <Col span={6}>
        <Statistic title="已加载规则" value={st.rules_loaded ?? '-'} />
      </Col>
      <Col span={6}>
        <Statistic
          title="加载失败规则"
          value={st.rules_failed ?? '-'}
          valueStyle={{ color: (st.rules_failed ?? 0) > 0 ? '#cf1322' : undefined }}
        />
      </Col>
      <Col span={6}>
        <Statistic
          title="内核丢包"
          value={st.kernel_drops ?? '-'}
          valueStyle={{ color: (st.kernel_drops ?? 0) > 0 ? '#cf1322' : undefined }}
        />
      </Col>
      <Col span={6}>
        <Statistic title="引擎累计告警" value={st.alerts_total ?? '-'} />
      </Col>
      <Col span={6}>
        <Statistic title="引擎运行时长" value={fmtUptime(st.uptime_sec)} />
      </Col>
      <Col span={12}>
        <Statistic title="最近统计时间" value={new Date(st.ts).toLocaleString()} valueStyle={{ fontSize: 16 }} />
      </Col>
    </Row>
  );
}
