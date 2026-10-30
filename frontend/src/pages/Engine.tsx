import { Card, Col, Empty, Row, Statistic, Tag } from 'antd';
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
      <LiveEngineSection st={live} iface={data?.live_iface || '自动'} />
    </Row>
  );
}

// 实时抓包引擎的 stats 每 10 秒一条，超过 60 秒无更新视为已停止
function LiveEngineSection({ st, iface }: { st?: EngineStat; iface: string }) {
  const stale = !st || Date.now() - new Date(st.ts).getTime() > 60_000;
  return (
    <Col span={24}>
      <Card
        title="实时抓包引擎"
        extra={
          <Tag color={!st ? 'default' : stale ? 'red' : 'green'}>
            {!st ? '未运行' : stale ? '已停止' : '抓包中'}
          </Tag>
        }
      >
        {st ? (
          <LiveEngineStats st={st} stale={stale} iface={iface} />
        ) : (
          <Empty description="暂无实时抓包统计" />
        )}
      </Card>
    </Col>
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
