import React from 'react';
import { createRoot } from 'react-dom/client';
import { App as AntApp, ConfigProvider } from 'antd';
import zhCN from 'antd/locale/zh_CN';
import dayjs from 'dayjs';
import 'dayjs/locale/zh-cn';
import 'antd/dist/reset.css';
import './styles.css';
import { AdminApp } from './AdminApp.jsx';
import { WebMailboxApp } from './WebMailboxApp.jsx';

dayjs.locale('zh-cn');

const RootApp = window.location.pathname.startsWith('/web/') ? WebMailboxApp : AdminApp;

createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <ConfigProvider
      locale={zhCN}
      theme={{
        token: {
          colorPrimary: '#1677ff',
          borderRadius: 6,
          colorBgLayout: '#f5f7fb',
          fontFamily:
            'Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif',
        },
        components: {
          Layout: {
            headerBg: '#ffffff',
            bodyBg: '#f5f7fb',
          },
          Card: {
            borderRadiusLG: 6,
          },
        },
      }}
    >
      <AntApp>
        <RootApp />
      </AntApp>
    </ConfigProvider>
  </React.StrictMode>,
);
