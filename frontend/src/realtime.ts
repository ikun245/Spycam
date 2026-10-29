import { useEffect, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { notification } from 'antd';

// 与后端 realtime.Event 对应（C1 实时推送）
interface TaskEvent {
  type: 'task';
  task_id: string;
  status: 'running' | 'done' | 'failed';
  alerts?: number;
  incidents?: number;
  error?: string;
}

export type StreamState = 'connecting' | 'open' | 'closed';

// 订阅 /api/v1/stream：收到任务事件后让相关查询失效重拉；EventSource 断线自动重连，
// 各页面原有的轮询保留作为兜底。
export function useRealtime(): StreamState {
  const qc = useQueryClient();
  const [state, setState] = useState<StreamState>('connecting');

  useEffect(() => {
    const es = new EventSource('/api/v1/stream', { withCredentials: true });
    es.onopen = () => setState('open');
    es.onerror = () => setState(es.readyState === EventSource.CLOSED ? 'closed' : 'connecting');
    es.addEventListener('task', (e) => {
      let ev: TaskEvent;
      try {
        ev = JSON.parse((e as MessageEvent<string>).data) as TaskEvent;
      } catch {
        return;
      }
      qc.invalidateQueries({ queryKey: ['tasks'] });
      if (ev.status === 'running') return;
      for (const key of ['alerts', 'groups', 'incidents', 'overview', 'engine']) {
        qc.invalidateQueries({ queryKey: [key] });
      }
      const shortId = ev.task_id.slice(0, 8);
      if (ev.status === 'done') {
        notification.info({
          key: ev.task_id,
          message: '回放任务完成',
          description: `任务 ${shortId} 新增告警 ${ev.alerts ?? 0} 条，攻击事件 ${ev.incidents ?? 0} 个`,
        });
      } else {
        notification.error({
          key: ev.task_id,
          message: '回放任务失败',
          description: `任务 ${shortId}：${ev.error ?? '未知错误'}`,
        });
      }
    });
    return () => es.close();
  }, [qc]);

  return state;
}
