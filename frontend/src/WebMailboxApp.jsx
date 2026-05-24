import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  CloudSyncOutlined,
  EyeOutlined,
  InboxOutlined,
  MailOutlined,
  ReloadOutlined,
  SearchOutlined,
} from '@ant-design/icons';
import { PageContainer, ProCard, ProLayout, ProTable } from '@ant-design/pro-components';
import {
  Alert,
  App,
  Badge,
  Button,
  Descriptions,
  Drawer,
  Empty,
  Input,
  Pagination,
  Segmented,
  Space,
  Statistic,
  Tabs,
  Tag,
  Tooltip,
  Typography,
} from 'antd';
import { apiRequest } from './api.js';
import { formatEmailDate } from './utils.js';

const folderOptions = [
  { label: '全部', value: 'all' },
  { label: '收件箱', value: 'inbox' },
  { label: '垃圾箱', value: 'junk' },
];

function safeDecode(value) {
  try {
    return decodeURIComponent(value);
  } catch (_error) {
    return value;
  }
}

function parseWebRoute() {
  const rawPath = window.location.pathname.replace(/^\/web\//, '');
  const detailMarker = '/detail/';
  const detailIndex = rawPath.indexOf(detailMarker);
  const rawCredential = detailIndex >= 0 ? rawPath.slice(0, detailIndex) : rawPath;
  const rawMessageId = detailIndex >= 0 ? rawPath.slice(detailIndex + detailMarker.length) : '';

  return {
    credentialPath: safeDecode(rawCredential),
    messageId: rawMessageId ? safeDecode(rawMessageId) : '',
  };
}

function boundedInt(value, fallback, min, max) {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(Math.max(parsed, min), max);
}

function parseQueryState() {
  const params = new URLSearchParams(window.location.search);
  const folder = folderOptions.some((item) => item.value === params.get('folder')) ? params.get('folder') : 'all';
  const page = boundedInt(params.get('page'), 1, 1, Number.MAX_SAFE_INTEGER);
  const pageSize = boundedInt(params.get('page_size'), 20, 1, 100);
  return { folder, page, pageSize };
}

function mailboxFromCredential(credentialPath) {
  return String(credentialPath || '').split('----')[0] || 'Outlook 邮箱';
}

function buildListUrl(credentialPath, queryState) {
  const params = new URLSearchParams({
    folder: queryState.folder,
    page: String(queryState.page),
    page_size: String(queryState.pageSize),
  });
  return `/web/${encodeURIComponent(credentialPath)}?${params.toString()}`;
}

function buildDetailUrl(credentialPath, messageId, queryState) {
  const listUrl = buildListUrl(credentialPath, queryState);
  const query = listUrl.includes('?') ? listUrl.slice(listUrl.indexOf('?')) : '';
  return `/web/${encodeURIComponent(credentialPath)}/detail/${encodeURIComponent(messageId)}${query}`;
}

function filterEmails(emails, search) {
  const keyword = search.trim().toLowerCase();
  if (!keyword) return emails;

  return emails.filter((email) => {
    const haystack = `${email.subject || ''} ${email.from_email || ''} ${email.folder || ''}`.toLowerCase();
    return haystack.includes(keyword);
  });
}

function WebMailboxDetailDrawer({ credentialPath, messageId, open, onClose, onRead }) {
  const { message } = App.useApp();
  const [detail, setDetail] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!open || !credentialPath || !messageId) return;

    setDetail(null);
    setLoading(true);
    apiRequest(`/web/${encodeURIComponent(credentialPath)}/message/${encodeURIComponent(messageId)}`, {
      redirectOnUnauthorized: false,
    })
      .then((data) => {
        setDetail(data);
        onRead?.(messageId);
      })
      .catch((error) => message.error(`加载邮件详情失败：${error.message}`))
      .finally(() => setLoading(false));
  }, [credentialPath, messageId, open, message, onRead]);

  return (
    <Drawer
      width="min(1040px, 94vw)"
      open={open}
      title={detail?.subject || '邮件详情'}
      onClose={onClose}
      destroyOnClose
    >
      {loading ? (
        <Typography.Text type="secondary">正在加载邮件详情...</Typography.Text>
      ) : detail ? (
        <Space direction="vertical" size={16} className="full-width">
          <Descriptions bordered size="small" column={1}>
            <Descriptions.Item label="发件人">{detail.from_email || '-'}</Descriptions.Item>
            <Descriptions.Item label="收件人">{detail.to_email || '-'}</Descriptions.Item>
            <Descriptions.Item label="日期">{formatEmailDate(detail.date)}</Descriptions.Item>
            <Descriptions.Item label="邮件 ID">
              <Typography.Text copyable>{detail.message_id}</Typography.Text>
            </Descriptions.Item>
          </Descriptions>
          <Tabs
            items={[
              detail.body_html
                ? {
                    key: 'html',
                    label: 'HTML 视图',
                    children: <iframe title="webmail-html" className="email-html-frame" sandbox="" srcDoc={detail.body_html} />,
                  }
                : null,
              detail.body_plain
                ? {
                    key: 'plain',
                    label: '纯文本',
                    children: <pre className="plain-email">{detail.body_plain}</pre>,
                  }
                : null,
              detail.body_html
                ? {
                    key: 'source',
                    label: '源码',
                    children: <pre className="plain-email dark">{detail.body_html}</pre>,
                  }
                : null,
            ].filter(Boolean)}
          />
        </Space>
      ) : (
        <Empty description="暂无邮件内容" />
      )}
    </Drawer>
  );
}

export function WebMailboxApp() {
  const { message } = App.useApp();
  const routeInfo = useMemo(() => parseWebRoute(), []);
  const initialQuery = useMemo(() => parseQueryState(), []);
  const [credentialPath] = useState(routeInfo.credentialPath);
  const [detailMessageId, setDetailMessageId] = useState(routeInfo.messageId);
  const [folder, setFolder] = useState(initialQuery.folder);
  const [page, setPage] = useState(initialQuery.page);
  const [pageSize, setPageSize] = useState(initialQuery.pageSize);
  const [emails, setEmails] = useState([]);
  const [total, setTotal] = useState(0);
  const [mailboxEmail, setMailboxEmail] = useState(mailboxFromCredential(routeInfo.credentialPath));
  const [authMode, setAuthMode] = useState('');
  const [loading, setLoading] = useState(false);
  const [loadError, setLoadError] = useState('');
  const [lastUpdate, setLastUpdate] = useState('');
  const [search, setSearch] = useState('');
  const [hasNewMail, setHasNewMail] = useState(false);
  const [realtime, setRealtime] = useState({ status: 'default', text: '实时监听准备中' });

  const queryState = useMemo(() => ({ folder, page, pageSize }), [folder, page, pageSize]);

  const pushListUrl = useCallback(
    (nextState) => {
      window.history.pushState(null, '', buildListUrl(credentialPath, nextState));
    },
    [credentialPath],
  );

  const loadEmails = useCallback(
    async (forceRefresh = false) => {
      if (!credentialPath) return;

      setLoading(true);
      setLoadError('');
      try {
        const params = new URLSearchParams({
          folder,
          page: String(page),
          page_size: String(pageSize),
        });
        if (forceRefresh) params.set('refresh', 'true');

        const data = await apiRequest(`/web/${encodeURIComponent(credentialPath)}/messages?${params.toString()}`, {
          redirectOnUnauthorized: false,
        });
        setEmails(data.emails || []);
        setTotal(Number(data.total_emails || 0));
        setMailboxEmail(data.email_id || mailboxFromCredential(credentialPath));
        setAuthMode(String(data.auth_mode || 'imap').toUpperCase());
        setLastUpdate(new Date().toLocaleString());
        setHasNewMail(false);
        if (forceRefresh) message.success('邮件列表已刷新');
      } catch (error) {
        setLoadError(error.message);
        message.error(`加载邮件失败：${error.message}`);
      } finally {
        setLoading(false);
      }
    },
    [credentialPath, folder, page, pageSize, message],
  );

  useEffect(() => {
    document.title = `${mailboxEmail} - 邮箱快速查看`;
  }, [mailboxEmail]);

  useEffect(() => {
    loadEmails(false);
  }, [loadEmails]);

  useEffect(() => {
    const syncFromBrowser = () => {
      const nextRoute = parseWebRoute();
      const nextQuery = parseQueryState();
      setDetailMessageId(nextRoute.messageId);
      setFolder(nextQuery.folder);
      setPage(nextQuery.page);
      setPageSize(nextQuery.pageSize);
    };

    window.addEventListener('popstate', syncFromBrowser);
    return () => window.removeEventListener('popstate', syncFromBrowser);
  }, []);

  useEffect(() => {
    if (!credentialPath) return undefined;
    if (typeof EventSource === 'undefined') {
      setRealtime({ status: 'warning', text: '浏览器不支持实时监听' });
      return undefined;
    }

    const params = new URLSearchParams({
      folder,
      page_size: String(pageSize),
    });
    const eventSource = new EventSource(`/web/${encodeURIComponent(credentialPath)}/events?${params.toString()}`);
    setRealtime({ status: 'processing', text: '实时监听连接中' });

    eventSource.addEventListener('ready', (event) => {
      try {
        const payload = JSON.parse(event.data || '{}');
        setRealtime({ status: 'success', text: `实时监听中（当前 ${Number(payload.total_emails || 0)} 封）` });
      } catch (_error) {
        setRealtime({ status: 'success', text: '实时监听中' });
      }
    });

    eventSource.addEventListener('new_mail', () => {
      setHasNewMail(true);
      setRealtime({ status: 'warning', text: '检测到新邮件' });
    });

    eventSource.addEventListener('error', () => {
      setRealtime((state) => (state.status === 'warning' ? state : { status: 'processing', text: '实时监听重连中' }));
    });

    return () => eventSource.close();
  }, [credentialPath, folder, pageSize]);

  const filteredEmails = useMemo(() => filterEmails(emails, search), [emails, search]);

  const markEmailRead = useCallback((messageId) => {
    setEmails((items) =>
      items.map((email) => (email.message_id === messageId ? { ...email, is_read: true } : email)),
    );
  }, []);

  const openDetail = (messageId) => {
    setDetailMessageId(messageId);
    window.history.pushState(null, '', buildDetailUrl(credentialPath, messageId, queryState));
  };

  const closeDetail = () => {
    setDetailMessageId('');
    pushListUrl(queryState);
  };

  const handleFolderChange = (nextFolder) => {
    const nextState = { folder: nextFolder, page: 1, pageSize };
    setFolder(nextFolder);
    setPage(1);
    pushListUrl(nextState);
  };

  const handlePageChange = (nextPage, nextPageSize) => {
    const nextState = { folder, page: nextPage, pageSize: nextPageSize };
    setPage(nextPage);
    setPageSize(nextPageSize);
    pushListUrl(nextState);
  };

  const columns = [
    {
      title: '主题',
      dataIndex: 'subject',
      render: (_, row) => (
        <Space direction="vertical" size={2} className="webmail-subject-cell">
          <Space size={8} wrap>
            {!row.is_read ? <Badge status="processing" /> : <Badge status="default" />}
            <Button type="link" className="webmail-subject-btn" onClick={() => openDetail(row.message_id)}>
              {row.subject || '(无主题)'}
            </Button>
            {row.has_attachments ? <Tag color="purple">附件</Tag> : null}
          </Space>
          <Typography.Text type="secondary" ellipsis>
            {row.from_email || '-'}
          </Typography.Text>
        </Space>
      ),
    },
    {
      title: '文件夹',
      dataIndex: 'folder',
      width: 110,
      render: (value) => <Tag>{String(value || '-').toUpperCase()}</Tag>,
    },
    {
      title: '发件人',
      dataIndex: 'from_email',
      width: 320,
      ellipsis: true,
      responsive: ['md'],
    },
    {
      title: '时间',
      dataIndex: 'date',
      width: 150,
      render: (value) => (
        <Tooltip title={value || '-'}>
          <span>{formatEmailDate(value)}</span>
        </Tooltip>
      ),
    },
    {
      title: '操作',
      valueType: 'option',
      width: 96,
      render: (_, row) => (
        <Button icon={<EyeOutlined />} type="link" onClick={() => openDetail(row.message_id)}>
          查看
        </Button>
      ),
    },
  ];

  return (
    <ProLayout
      title="Outlook Manager"
      logo={<MailOutlined />}
      layout="top"
      fixedHeader
      menuRender={false}
      avatarProps={false}
      className="webmail-pro-layout"
      token={{
        header: {
          colorBgHeader: '#ffffff',
        },
      }}
      actionsRender={() => [
        <Button key="switch-mailbox" href="/" icon={<InboxOutlined />}>
          切换邮箱
        </Button>,
      ]}
    >
      <PageContainer
        title="邮箱快速查看"
        subTitle={mailboxEmail}
        tags={authMode ? <Tag color="blue">{authMode}</Tag> : null}
        ghost={false}
        className="webmail-page-container"
        extra={
          <Space wrap>
            <Badge status={realtime.status} text={realtime.text} />
            <Button
              type={hasNewMail ? 'primary' : 'default'}
              icon={hasNewMail ? <CloudSyncOutlined /> : <ReloadOutlined />}
              loading={loading}
              onClick={() => loadEmails(true)}
            >
              {hasNewMail ? '刷新查看新邮件' : '手动刷新'}
            </Button>
          </Space>
        }
      >
        <Space direction="vertical" size={16} className="full-width webmail-content">
          <ProCard bordered className="webmail-summary-card">
            <Space direction="vertical" size={16} className="full-width">
              <Space align="center" wrap className="full-width webmail-controls">
                <Segmented value={folder} onChange={handleFolderChange} options={folderOptions} />
                <Typography.Text type="secondary">最后更新：{lastUpdate || '-'}</Typography.Text>
              </Space>
              <div className="webmail-stats-grid">
                <Statistic title="总邮件" value={total} />
                <Statistic title="本页邮件" value={emails.length} />
                <Statistic title="未读" value={emails.filter((email) => !email.is_read).length} />
                <Statistic title="附件" value={emails.filter((email) => email.has_attachments).length} />
              </div>
            </Space>
          </ProCard>

          {loadError ? <Alert showIcon type="error" message="加载失败" description={loadError} /> : null}

          <ProTable
            rowKey="message_id"
            columns={columns}
            dataSource={filteredEmails}
            loading={loading}
            search={false}
            options={false}
            cardBordered
            pagination={false}
            rowClassName={(row) => (!row.is_read ? 'webmail-row-unread' : '')}
            locale={{
              emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无邮件" />,
            }}
            toolbar={{
              title: '邮件列表',
              actions: [
                <Input
                  key="search"
                  allowClear
                  prefix={<SearchOutlined />}
                  placeholder="搜索主题、发件人或文件夹"
                  value={search}
                  onChange={(event) => setSearch(event.target.value)}
                  className="webmail-search"
                />,
              ],
            }}
          />
          <div className="webmail-pagination">
            <Pagination
              current={page}
              pageSize={pageSize}
              total={total}
              showSizeChanger
              showQuickJumper
              pageSizeOptions={[10, 20, 50, 100]}
              showTotal={(value) => `共 ${value} 封`}
              onChange={handlePageChange}
            />
          </div>
        </Space>
        <WebMailboxDetailDrawer
          credentialPath={credentialPath}
          messageId={detailMessageId}
          open={Boolean(detailMessageId)}
          onClose={closeDetail}
          onRead={markEmailRead}
        />
      </PageContainer>
    </ProLayout>
  );
}
