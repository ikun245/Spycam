// 统一 API 客户端：自动携带凭据、401 跳登录、非 GET 带自定义头（CSRF，架构设计 §6.6）

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const method = init?.method ?? 'GET';
  const headers = new Headers(init?.headers);
  if (method !== 'GET') headers.set('X-Requested-With', 'spycam');

  const resp = await fetch(path, {
    ...init,
    method,
    headers,
    credentials: 'same-origin',
  });

  if (resp.status === 401 && !path.includes('/auth/login')) {
    window.location.href = '/login';
    throw new ApiError(401, 'unauthorized');
  }
  if (!resp.ok) {
    let msg = `HTTP ${resp.status}`;
    try {
      const body = (await resp.json()) as { error?: string };
      if (body.error) msg = body.error;
    } catch {
      /* 非 JSON 错误体，保留状态码信息 */
    }
    throw new ApiError(resp.status, msg);
  }
  return (await resp.json()) as T;
}

export const api = {
  get: <T>(path: string) => request<T>(path),
  post: <T>(path: string, body?: unknown) =>
    request<T>(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined,
    }),
};
