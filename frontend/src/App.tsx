import { Navigate, Route, Routes, useNavigate } from 'react-router-dom';
import { Layout, Menu, Typography } from 'antd';
import Login from './pages/Login';
import Overview from './pages/Overview';
import Alerts from './pages/Alerts';
import AlertDetail from './pages/AlertDetail';
import Groups from './pages/Groups';
import Rules from './pages/Rules';
import DataPage from './pages/Data';
import Validation from './pages/Validation';
import Incidents from './pages/Incidents';
import Engine from './pages/Engine';

const { Header, Sider, Content } = Layout;

const menuItems = [
  { key: '/', label: '总览' },
  { key: '/alerts', label: '告警列表' },
  { key: '/groups', label: '聚合处置' },
  { key: '/incidents', label: '攻击事件' },
  { key: '/engine', label: '引擎状态' },
  { key: '/data', label: '数据与回放' },
  { key: '/rules', label: '规则管理' },
  { key: '/validation', label: '自验报告' },
];

export default function App() {
  const nav = useNavigate();
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
                  items={menuItems}
                  onClick={({ key }) => nav(key)}
                />
              </Sider>
              <Content style={{ padding: 16 }}>
                <Routes>
                  <Route path="/" element={<Overview />} />
                  <Route path="/alerts" element={<Alerts />} />
                  <Route path="/alerts/:id" element={<AlertDetail />} />
                  <Route path="/groups" element={<Groups />} />
                  <Route path="/incidents" element={<Incidents />} />
                  <Route path="/engine" element={<Engine />} />
                  <Route path="/data" element={<DataPage />} />
                  <Route path="/rules" element={<Rules />} />
                  <Route path="/validation" element={<Validation />} />
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
