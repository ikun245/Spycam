import { Navigate, Route, Routes } from 'react-router-dom';
import { Layout, Menu, Typography } from 'antd';
import Login from './pages/Login';
import Overview from './pages/Overview';
import Alerts from './pages/Alerts';
import Rules from './pages/Rules';
import DataPage from './pages/Data';

const { Header, Sider, Content } = Layout;

const menuItems = [
  { key: '/', label: '总览' },
  { key: '/alerts', label: '告警列表' },
  { key: '/data', label: '数据与回放' },
  { key: '/rules', label: '规则管理' },
];

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route
        path="*"
        element={
          <Layout style={{ minHeight: '100vh' }}>
            <Header style={{ display: 'flex', alignItems: 'center' }}>
              <Typography.Title level={4} style={{ color: '#fff', margin: 0, marginRight: 24 }}>
                Spycam 流量威胁检测
              </Typography.Title>
            </Header>
            <Layout>
              <Sider width={180}>
                <Menu
                  theme="dark"
                  mode="inline"
                  defaultSelectedKeys={['/']}
                  items={menuItems}
                  onClick={({ key }) => (window.location.hash = key)}
                />
              </Sider>
              <Content style={{ padding: 16 }}>
                <Routes>
                  <Route path="/" element={<Overview />} />
                  <Route path="/alerts" element={<Alerts />} />
                  <Route path="/data" element={<DataPage />} />
                  <Route path="/rules" element={<Rules />} />
                  <Route path="*" element={<Navigate to="/" replace />} />
                </Routes>
              </Content>
            </Layout>
          </Layout>
        }
      />
    </Routes>
  );
}
