import { Button, Card, Form, Input, Typography, App } from 'antd';
import { useNavigate } from 'react-router-dom';
import { api } from '../api/client';

interface LoginResp {
  username: string;
}

export default function Login() {
  const nav = useNavigate();
  const { message } = App.useApp();

  const onFinish = async (values: { username: string; password: string }) => {
    try {
      await api.post<LoginResp>('/api/v1/auth/login', values);
      message.success('登录成功');
      nav('/');
    } catch (e) {
      message.error(e instanceof Error ? e.message : '登录失败');
    }
  };

  return (
    <div
      style={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: '#f0f2f5',
      }}
    >
      <Card style={{ width: 360 }}>
        <Typography.Title level={3} style={{ textAlign: 'center' }}>
          Spycam 登录
        </Typography.Title>
        <Form layout="vertical" onFinish={onFinish}>
          <Form.Item name="username" label="用户名" rules={[{ required: true }]}>
            <Input autoComplete="username" />
          </Form.Item>
          <Form.Item name="password" label="密码" rules={[{ required: true }]}>
            <Input.Password autoComplete="current-password" />
          </Form.Item>
          <Button type="primary" htmlType="submit" block>
            登录
          </Button>
        </Form>
      </Card>
    </div>
  );
}
