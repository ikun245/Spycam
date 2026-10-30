import { Card, Col, Row, Statistic } from 'antd';
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
          以上为离线回放引擎；启用 live profile 后，实时抓包引擎的统计单独显示在下方。刷新间隔 5 秒。
        </Card>
      </Col>
      {live && <LiveEngineCards st={live} />}
    </Row>
  );
}

// 实时抓包引擎（live profile）的 stats 每 10 秒一条，超过 60 秒无更新视为已停止
function LiveEngineCards({ st }: { st: EngineStat }) {
  const stale = Date.now() - new Date(st.ts).getTime() > 60_000;
  return (
    <Col span={24}>
      <Card title="实时抓包引擎（live profile）">
        <Row gutter={[16, 16]}>
          <Col span={6}>
            <Statistic
              title="状态"
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
      </Card>
    </Col>
  );
}
