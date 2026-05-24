import { useEffect, useMemo, useState } from 'react';
import {
  ClearOutlined,
  DownloadOutlined,
  EyeOutlined,
  InboxOutlined,
  ReloadOutlined,
  SearchOutlined,
} from '@ant-design/icons';
import { ProCard, ProTable } from '@ant-design/pro-components';
import {
  App,
  Badge,
  Button,
  Drawer,
  Empty,
  Input,
  Segmented,
  Select,
  Space,
  Statistic,
  Tabs,
  Tag,
  Typography,
} from 'antd';
import { apiRequest } from '../api.js';
import { downloadText, emailCsv, formatEmailDate } from '../utils.js';

function normalize(value) {
  return String(value || '').toLowerCase();
}

function filterEmails(emails, filters) {
  return emails.filter((email) => {
    const searchText = `${email.subject || ''} ${email.from_email || ''}`.toLowerCase();
    if (filters.search && !searchText.includes(filters.search.toLowerCase())) return false;
    if (filters.status === 'read' && !email.is_read) return false;
    if (filters.status === 'unread' && email.is_read) return false;
    if (filters.attachment === 'with' && !email.has_attachments) return false;
    if (filters.attachment === 'without' && email.has_attachments) return false;
    if (filters.time !== 'all') {
      const date = new Date(email.date);
      const now = new Date();
      if (Number.isNaN(date.getTime())) return false;
      if (filters.time === 'today' && date.toDateString() !== now.toDateString()) return false;
      if (filters.time === 'week' && date < new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000)) return false;
      if (filters.time === 'month' && date < new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000)) return false;
    }
    return true;
  });
}

function EmailDetailDrawer({ account, messageId, open, onClose }) {
  const { message } = App.useApp();
  const [detail, setDetail] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!open || !account || !messageId) return;
    setDetail(null);
    setLoading(true);
    apiRequest(`/emails/${encodeURIComponent(account)}/${encodeURIComponent(messageId)}`)
      .then(setDetail)
      .catch((error) => message.error(`加载邮件详情失败：${error.message}`))
      .finally(() => setLoading(false));
  }, [open, account, messageId]);

  return (
    <Drawer width="min(980px, 92vw)" open={open} title={detail?.subject || '邮件详情'} onClose={onClose}>
      {loading ? (
        <Typography.Text type="secondary">正在加载邮件详情...</Typography.Text>
      ) : detail ? (
        <Space direction="vertical" size={16} className="full-width">
          <ProCard bordered>
            <Space direction="vertical" size={4}>
              <Typography.Text>
                <strong>发件人：</strong>
                {detail.from_email || '-'}
              </Typography.Text>
              <Typography.Text>
                <strong>收件人：</strong>
                {detail.to_email || '-'}
              </Typography.Text>
              <Typography.Text>
                <strong>日期：</strong>
                {formatEmailDate(detail.date)}
              </Typography.Text>
              <Typography.Text copyable>
                <strong>邮件 ID：</strong>
                {detail.message_id}
              </Typography.Text>
            </Space>
          </ProCard>
          <Tabs
            items={[
              detail.body_html
                ? {
                    key: 'html',
                    label: 'HTML 视图',
                    children: <iframe title="email-html" className="email-html-frame" sandbox="" srcDoc={detail.body_html} />,
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

export function EmailsPage({ emailId, onPickAccount }) {
  const { message } = App.useApp();
  const [folder, setFolder] = useState('all');
  const [emails, setEmails] = useState([]);
  const [loading, setLoading] = useState(false);
  const [lastUpdate, setLastUpdate] = useState('');
  const [filters, setFilters] = useState({
    search: '',
    status: 'all',
    time: 'all',
    attachment: 'all',
  });
  const [detailMessageId, setDetailMessageId] = useState('');

  const loadEmails = async (forceRefresh = false) => {
    if (!emailId) return;
    setLoading(true);
    try {
      const refresh = forceRefresh ? '&refresh=true' : '';
      const data = await apiRequest(
        `/emails/${encodeURIComponent(emailId)}?folder=${folder}&page=1&page_size=100${refresh}`,
      );
      setEmails(data.emails || []);
      setLastUpdate(new Date().toLocaleString());
      if (forceRefresh) message.success('邮件列表已刷新');
    } catch (error) {
      message.error(`加载邮件失败：${error.message}`);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    setEmails([]);
    setDetailMessageId('');
    loadEmails(false);
  }, [emailId, folder]);

  const filteredEmails = useMemo(() => filterEmails(emails, filters), [emails, filters]);
  const stats = useMemo(
    () => ({
      total: emails.length,
      unread: emails.filter((email) => !email.is_read).length,
      today: emails.filter((email) => new Date(email.date).toDateString() === new Date().toDateString()).length,
      attachments: emails.filter((email) => email.has_attachments).length,
    }),
    [emails],
  );

  const columns = [
    {
      title: '主题',
      dataIndex: 'subject',
      render: (_, row) => (
        <Space direction="vertical" size={2}>
          <Space>
            {!row.is_read ? <Badge status="processing" /> : <Badge status="default" />}
            <Typography.Text strong={!row.is_read}>{row.subject || '(无主题)'}</Typography.Text>
            {row.has_attachments ? <Tag color="purple">附件</Tag> : null}
          </Space>
          <Typography.Text type="secondary">{row.from_email}</Typography.Text>
        </Space>
      ),
    },
    {
      title: '文件夹',
      dataIndex: 'folder',
      width: 110,
      render: (value) => <Tag>{String(value || '-').toUpperCase()}</Tag>,
      filters: [
        { text: 'INBOX', value: 'inbox' },
        { text: 'JUNK', value: 'junk' },
      ],
      onFilter: (value, row) => normalize(row.folder).includes(value),
    },
    {
      title: '时间',
      dataIndex: 'date',
      width: 150,
      render: (_, row) => formatEmailDate(row.date),
      sorter: (a, b) => new Date(a.date).getTime() - new Date(b.date).getTime(),
      defaultSortOrder: 'descend',
    },
    {
      title: '操作',
      valueType: 'option',
      width: 110,
      render: (_, row) => (
        <Button icon={<EyeOutlined />} type="link" onClick={() => setDetailMessageId(row.message_id)}>
          详情
        </Button>
      ),
    },
  ];

  if (!emailId) {
    return (
      <ProCard className="empty-panel" bordered>
        <Empty
          image={Empty.PRESENTED_IMAGE_SIMPLE}
          description="请从邮箱账户列表中选择一个账户查看邮件"
        />
      </ProCard>
    );
  }

  return (
    <Space direction="vertical" size={16} className="full-width">
      <ProCard bordered>
        <Space direction="vertical" size={16} className="full-width">
          <Space align="center" wrap>
            <InboxOutlined className="section-icon" />
            <Typography.Text strong copyable>
              {emailId}
            </Typography.Text>
            <Typography.Text type="secondary">最后更新：{lastUpdate || '-'}</Typography.Text>
          </Space>
          <Segmented
            value={folder}
            onChange={setFolder}
            options={[
              { label: '全部', value: 'all' },
              { label: '收件箱', value: 'inbox' },
              { label: '垃圾箱', value: 'junk' },
            ]}
          />
          <Space wrap className="stats-row">
            <Statistic title="本页邮件" value={stats.total} />
            <Statistic title="未读" value={stats.unread} />
            <Statistic title="今日" value={stats.today} />
            <Statistic title="附件" value={stats.attachments} />
          </Space>
        </Space>
      </ProCard>
      <ProTable
        rowKey="message_id"
        columns={columns}
        dataSource={filteredEmails}
        loading={loading}
        search={false}
        cardBordered
        pagination={{ pageSize: 12, showSizeChanger: true }}
        toolbar={{
          title: '邮件列表',
          actions: [
            <Input
              key="search"
              allowClear
              prefix={<SearchOutlined />}
              placeholder="搜索主题或发件人"
              value={filters.search}
              onChange={(event) => setFilters((value) => ({ ...value, search: event.target.value }))}
              style={{ width: 240 }}
            />,
            <Select
              key="status"
              value={filters.status}
              onChange={(value) => setFilters((state) => ({ ...state, status: value }))}
              options={[
                { label: '全部状态', value: 'all' },
                { label: '未读', value: 'unread' },
                { label: '已读', value: 'read' },
              ]}
              style={{ width: 120 }}
            />,
            <Select
              key="time"
              value={filters.time}
              onChange={(value) => setFilters((state) => ({ ...state, time: value }))}
              options={[
                { label: '全部时间', value: 'all' },
                { label: '今天', value: 'today' },
                { label: '近7天', value: 'week' },
                { label: '近30天', value: 'month' },
              ]}
              style={{ width: 120 }}
            />,
            <Select
              key="attachment"
              value={filters.attachment}
              onChange={(value) => setFilters((state) => ({ ...state, attachment: value }))}
              options={[
                { label: '全部附件', value: 'all' },
                { label: '有附件', value: 'with' },
                { label: '无附件', value: 'without' },
              ]}
              style={{ width: 120 }}
            />,
            <Button key="refresh" icon={<ReloadOutlined />} onClick={() => loadEmails(true)}>
              刷新
            </Button>,
            <Button
              key="cache"
              icon={<ClearOutlined />}
              onClick={async () => {
                await apiRequest(`/cache/${encodeURIComponent(emailId)}`, { method: 'DELETE' });
                message.success('缓存已清除');
                await loadEmails(true);
              }}
            >
              清缓存
            </Button>,
            <Button
              key="export"
              icon={<DownloadOutlined />}
              onClick={() => {
                if (!filteredEmails.length) {
                  message.warning('没有邮件可导出');
                  return;
                }
                downloadText(`emails_${emailId}_${new Date().toISOString().slice(0, 10)}.csv`, `\uFEFF${emailCsv(filteredEmails)}`, 'text/csv;charset=utf-8');
                message.success(`已导出 ${filteredEmails.length} 封邮件`);
              }}
            >
              导出
            </Button>,
          ],
        }}
      />
      <EmailDetailDrawer
        account={emailId}
        messageId={detailMessageId}
        open={Boolean(detailMessageId)}
        onClose={() => setDetailMessageId('')}
      />
    </Space>
  );
}
