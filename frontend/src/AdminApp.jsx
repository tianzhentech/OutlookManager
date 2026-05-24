import { useEffect, useMemo, useState } from 'react';
import {
  ApiOutlined,
  CloudSyncOutlined,
  InboxOutlined,
  LogoutOutlined,
  MailOutlined,
  PlusOutlined,
  UnorderedListOutlined,
} from '@ant-design/icons';
import { PageContainer, ProLayout } from '@ant-design/pro-components';
import { Button, Dropdown, Space, Typography } from 'antd';
import { AccountsPage } from './pages/AccountsPage.jsx';
import { ApiDocsPage } from './pages/ApiDocsPage.jsx';
import { BatchAddPage } from './pages/BatchAddPage.jsx';
import { EmailsPage } from './pages/EmailsPage.jsx';

const routes = [
  {
    path: '/accounts',
    name: '邮箱账户',
    icon: <UnorderedListOutlined />,
  },
  {
    path: '/add-account',
    name: '添加账户',
    icon: <PlusOutlined />,
  },
  {
    path: '/emails',
    name: '邮件查看',
    icon: <InboxOutlined />,
  },
  {
    path: '/api-docs',
    name: 'API 管理',
    icon: <ApiOutlined />,
  },
];

function parseHash() {
  const hash = window.location.hash.replace(/^#/, '') || '/accounts';
  if (hash.startsWith('/emails/')) {
    return {
      pathname: '/emails',
      emailId: decodeURIComponent(hash.replace('/emails/', '')),
    };
  }
  return {
    pathname: hash,
    emailId: '',
  };
}

function titleForRoute(pathname) {
  if (pathname === '/add-account') return '添加邮箱账户';
  if (pathname === '/emails') return '邮件查看';
  if (pathname === '/api-docs') return 'API 管理';
  return '邮箱账户';
}

export function AdminApp() {
  const [route, setRouteState] = useState(parseHash);
  const [refreshKey, setRefreshKey] = useState(0);

  useEffect(() => {
    const syncRoute = () => setRouteState(parseHash());
    window.addEventListener('hashchange', syncRoute);
    return () => window.removeEventListener('hashchange', syncRoute);
  }, []);

  const location = useMemo(() => ({ pathname: route.pathname }), [route.pathname]);

  const navigate = (pathname, emailId = '') => {
    if (pathname === '/emails' && emailId) {
      window.location.hash = `/emails/${encodeURIComponent(emailId)}`;
      return;
    }
    window.location.hash = pathname;
  };

  const content = useMemo(() => {
    if (route.pathname === '/add-account') {
      return <BatchAddPage onDone={() => navigate('/accounts')} />;
    }
    if (route.pathname === '/emails') {
      return <EmailsPage emailId={route.emailId} onPickAccount={(emailId) => navigate('/emails', emailId)} />;
    }
    if (route.pathname === '/api-docs') {
      return <ApiDocsPage />;
    }
    return (
      <AccountsPage
        refreshKey={refreshKey}
        onOpenEmails={(emailId) => navigate('/emails', emailId)}
        onRefresh={() => setRefreshKey((value) => value + 1)}
      />
    );
  }, [route, refreshKey]);

  return (
    <ProLayout
      title="Outlook Manager"
      logo={<MailOutlined />}
      route={{ path: '/', routes }}
      location={location}
      menu={{ type: 'group' }}
      fixedHeader
      fixSiderbar
      layout="mix"
      splitMenus={false}
      siderWidth={238}
      token={{
        header: {
          colorBgHeader: '#ffffff',
        },
        sider: {
          colorMenuBackground: '#ffffff',
          colorTextMenu: '#31415f',
          colorTextMenuSelected: '#1677ff',
          colorBgMenuItemSelected: '#e8f3ff',
        },
      }}
      avatarProps={false}
      menuItemRender={(item, dom) => (
        <button className="menu-link" type="button" onClick={() => navigate(item.path || '/accounts')}>
          {dom}
        </button>
      )}
      actionsRender={() => [
        <Dropdown
          key="account"
          menu={{
            items: [
              {
                key: 'logout',
                icon: <LogoutOutlined />,
                label: <a href="/admin/auth/logout">退出后台</a>,
              },
            ],
          }}
        >
          <Button icon={<LogoutOutlined />}>后台会话</Button>
        </Dropdown>,
      ]}
    >
      <PageContainer
        title={titleForRoute(route.pathname)}
        ghost={false}
        className="admin-page-container"
        extra={
          route.pathname === '/accounts' ? (
            <Space wrap>
              <Button icon={<CloudSyncOutlined />} onClick={() => setRefreshKey((value) => value + 1)}>
                刷新
              </Button>
            </Space>
          ) : null
        }
      >
        <Typography.Paragraph className="page-kicker">
          {route.pathname === '/accounts'
            ? '管理 OAuth 凭证、标签和令牌刷新状态。'
            : route.pathname === '/add-account'
              ? '按行添加一个或多个 Outlook 邮箱账户。'
            : route.pathname === '/emails'
              ? '按账户查看最近邮件，支持筛选、详情预览和导出。'
              : route.pathname === '/api-docs'
                ? '从后端 OpenAPI 自动读取接口清单。'
                : null}
        </Typography.Paragraph>
        {content}
      </PageContainer>
    </ProLayout>
  );
}
