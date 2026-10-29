// 统一的中文显示映射：告警等级 / 攻击阶段 / 处置状态 / 任务状态，所有页面复用，避免同一概念多种呈现

export const sevMeta: Record<number, { text: string; color: string; tag: string }> = {
  1: { text: '高危', color: '#cf1322', tag: 'red' },
  2: { text: '中危', color: '#d46b08', tag: 'orange' },
  3: { text: '低危', color: '#2f54eb', tag: 'blue' },
  4: { text: '提示', color: '#8c8c8c', tag: 'default' },
};

export const sevText = (s: number | null | undefined) =>
  s == null ? '-' : (sevMeta[s]?.text ?? `等级 ${s}`);

export const stageNames: Record<string, string> = {
  recon: '侦察探测',
  bruteforce: '暴力破解',
  exploit: '漏洞利用',
  c2: '命令控制',
  exfil: '数据外泄',
  未分类: '未分类',
};

export const stageColor: Record<string, string> = {
  recon: 'blue',
  bruteforce: 'orange',
  exploit: 'red',
  c2: 'purple',
  exfil: 'magenta',
};

export const stageText = (s: string | null | undefined) => (s ? (stageNames[s] ?? s) : '-');

export const triageMeta: Record<string, { text: string; color: string }> = {
  new: { color: 'orange', text: '待处置' },
  confirmed: { color: 'red', text: '已确认' },
  false_positive: { color: 'default', text: '误报' },
  ignored: { color: 'default', text: '已忽略' },
};

export const triageText = (s: string) => triageMeta[s]?.text ?? s;

export const taskStatusMeta: Record<string, { text: string; color: string }> = {
  queued: { text: '排队中', color: 'default' },
  running: { text: '运行中', color: 'processing' },
  done: { text: '已完成', color: 'success' },
  failed: { text: '失败', color: 'error' },
};
