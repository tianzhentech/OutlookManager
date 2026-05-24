import { useEffect, useRef, useState } from 'react';
import {
  DeleteOutlined,
  EditOutlined,
  InboxOutlined,
  ReloadOutlined,
  TagsOutlined,
  ThunderboltOutlined,
} from '@ant-design/icons';
import {
  ModalForm,
  ProDescriptions,
  ProFormSelect,
  ProFormText,
  ProFormTextArea,
  ProTable,
} from '@ant-design/pro-components';
import {
  App,
  Badge,
  Button,
  Card,
  Descriptions,
  Flex,
  InputNumber,
  Popconfirm,
  Select,
  Space,
  Switch,
  Tag,
  Tooltip,
  Typography,
} from 'antd';
import { apiRequest, buildQuery } from '../api.js';
import { formatDateTime, normalizeTags } from '../utils.js';

const authModeOptions = [
  { label: 'auto（自动识别）', value: 'auto' },
  { label: 'imap', value: 'imap' },
  { label: 'graph', value: 'graph' },
];

function statusBadge(status) {
  if (status === 'active') return <Badge status="success" text="正常" />;
  if (status === 'expired') return <Badge status="warning" text="RT过期" />;
  return <Badge status="error" text="异常" />;
}

function unitLabel(unit) {
  if (unit === 'day') return '天';
  if (unit === 'hour') return '小时';
  return '分钟';
}

function TokenRefreshPanel({ onRefreshAccounts }) {
  const { message, modal } = App.useApp();
  const [settings, setSettings] = useState(null);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [refreshing, setRefreshing] = useState(false);

  const loadSettings = async () => {
    setLoading(true);
    try {
      setSettings(await apiRequest('/token-refresh/settings'));
    } catch (error) {
      message.error(`加载定时刷新设置失败：${error.message}`);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadSettings();
  }, []);

  const updateSettings = async () => {
    if (!settings) return;
    setSaving(true);
    try {
      const updated = await apiRequest('/token-refresh/settings', {
        method: 'PUT',
        body: JSON.stringify({
          enabled: Boolean(settings.enabled),
          interval_value: Number(settings.interval_value || 1),
          interval_unit: settings.interval_unit || 'hour',
        }),
      });
      setSettings(updated);
      message.success('定时刷新设置已保存');
    } catch (error) {
      message.error(`保存失败：${error.message}`);
    } finally {
      setSaving(false);
    }
  };

  const refreshAll = () => {
    modal.confirm({
      title: '立即刷新全部账户 RT/AT？',
      content: '该操作会依次请求所有账户的 Microsoft token endpoint，账户较多时可能需要一些时间。',
      okText: '开始刷新',
      cancelText: '取消',
      onOk: async () => {
        setRefreshing(true);
        try {
          const result = await apiRequest('/token-refresh/refresh-all', { method: 'POST' });
          if ((result.failure_count || 0) > 0) {
            message.warning(`完成：成功 ${result.success_count}，失败 ${result.failure_count}`);
          } else {
            message.success(`完成：成功 ${result.success_count}`);
          }
          await loadSettings();
          onRefreshAccounts?.();
        } catch (error) {
          message.error(`刷新失败：${error.message}`);
        } finally {
          setRefreshing(false);
        }
      },
    });
  };

  return (
    <Card loading={loading} className="toolbar-card" variant="borderless">
      <Flex align="center" justify="space-between" gap={16} wrap>
        <Space size="middle" wrap>
          <Switch
            checked={Boolean(settings?.enabled)}
            onChange={(checked) => setSettings((value) => ({ ...(value || {}), enabled: checked }))}
          />
          <Typography.Text strong>定时刷新 RT</Typography.Text>
          <Typography.Text type="secondary">每</Typography.Text>
          <InputNumber
            min={1}
            max={100000}
            value={settings?.interval_value || 12}
            onChange={(value) => setSettings((state) => ({ ...(state || {}), interval_value: value || 1 }))}
            style={{ width: 92 }}
          />
          <Select
            value={settings?.interval_unit || 'hour'}
            onChange={(value) => setSettings((state) => ({ ...(state || {}), interval_unit: value }))}
            options={[
              { label: '分钟', value: 'minute' },
              { label: '小时', value: 'hour' },
              { label: '天', value: 'day' },
            ]}
            style={{ width: 96 }}
          />
          <Typography.Text type="secondary">
            {settings?.enabled
              ? `下次 ${formatDateTime(settings.next_run_at, '未计划')}，上次 ${formatDateTime(settings.last_run_at, '暂无')}`
              : `已关闭，上次 ${formatDateTime(settings?.last_run_at, '暂无')}`}
          </Typography.Text>
        </Space>
        <Space wrap>
          <Button onClick={updateSettings} loading={saving}>
            保存设置
          </Button>
          <Button type="primary" icon={<ThunderboltOutlined />} onClick={refreshAll} loading={refreshing}>
            全部刷新 RT
          </Button>
        </Space>
      </Flex>
      {settings?.enabled ? (
        <Typography.Text className="small-muted">
          当前周期：每 {settings.interval_value}
          {unitLabel(settings.interval_unit)} 自动刷新。
        </Typography.Text>
      ) : null}
    </Card>
  );
}

function AccountEditModal({ emailId, open, onOpenChange, onSaved }) {
  const { message } = App.useApp();
  const formRef = useRef();
  const [detail, setDetail] = useState(null);

  useEffect(() => {
    if (!open || !emailId) return;
    setDetail(null);
    apiRequest(`/accounts/${encodeURIComponent(emailId)}`)
      .then((data) => {
        setDetail(data);
        formRef.current?.setFieldsValue({
          mailbox_password: data.mailbox_password || '',
          refresh_token: data.refresh_token || '',
          client_id: data.client_id || '',
          auth_mode: data.auth_mode || 'auto',
          tags: data.tags || [],
        });
      })
      .catch((error) => {
        message.error(`加载账户信息失败：${error.message}`);
        onOpenChange(false);
      });
  }, [open, emailId]);

  return (
    <ModalForm
      title={`账户信息 - ${emailId || ''}`}
      open={open}
      formRef={formRef}
      width={760}
      modalProps={{ destroyOnClose: true }}
      onOpenChange={onOpenChange}
      submitter={{ searchConfig: { submitText: '保存账户' } }}
      onFinish={async (values) => {
        await apiRequest(`/accounts/${encodeURIComponent(emailId)}`, {
          method: 'PUT',
          body: JSON.stringify({
            mailbox_password: values.mailbox_password || null,
            refresh_token: values.refresh_token,
            client_id: values.client_id,
            auth_mode: values.auth_mode || 'auto',
            tags: normalizeTags(values.tags),
          }),
        });
        message.success('账户信息已更新');
        onSaved?.();
        return true;
      }}
    >
      <ProDescriptions column={2} size="small" className="modal-descriptions">
        <ProDescriptions.Item label="状态">{statusBadge(detail?.status)}</ProDescriptions.Item>
        <ProDescriptions.Item label="认证模式">
          <Tag color="blue">{(detail?.auth_mode || '-').toUpperCase()}</Tag>
        </ProDescriptions.Item>
        <ProDescriptions.Item label="AT 过期">{formatDateTime(detail?.access_token_expires_at)}</ProDescriptions.Item>
        <ProDescriptions.Item label="RT 过期">{formatDateTime(detail?.refresh_token_expires_at)}</ProDescriptions.Item>
      </ProDescriptions>
      <ProFormText name="mailbox_password" label="邮箱密码" placeholder="用于 /web/邮箱----邮箱密码 快速取件" />
      <ProFormTextArea
        name="refresh_token"
        label="Refresh Token"
        fieldProps={{ rows: 4 }}
        rules={[{ required: true, message: '请输入 refresh_token' }]}
      />
      <ProFormText name="client_id" label="Client ID" rules={[{ required: true, message: '请输入 client_id' }]} />
      <ProFormSelect name="auth_mode" label="认证模式" options={authModeOptions} />
      <ProFormSelect
        name="tags"
        label="标签"
        fieldProps={{ mode: 'tags', tokenSeparators: [','] }}
        placeholder="输入标签后回车"
      />
      <ProFormTextArea
        label="当前缓存 Access Token"
        readonly
        fieldProps={{ rows: 3, value: detail?.access_token || '未缓存 AT（取件或刷新后显示）' }}
      />
    </ModalForm>
  );
}

export function AccountsPage({ refreshKey, onOpenEmails, onRefresh }) {
  const { message, modal } = App.useApp();
  const actionRef = useRef();
  const [editingEmail, setEditingEmail] = useState('');
  const [editOpen, setEditOpen] = useState(false);

  useEffect(() => {
    actionRef.current?.reload();
  }, [refreshKey]);

  const reload = () => {
    actionRef.current?.reload();
    onRefresh?.();
  };

  const refreshAccount = async (emailId) => {
    try {
      await apiRequest(`/accounts/${encodeURIComponent(emailId)}/refresh-token`, { method: 'POST' });
      message.success(`${emailId} 的 RT/AT 已刷新`);
      actionRef.current?.reload();
    } catch (error) {
      message.error(`刷新失败：${error.message}`);
    }
  };

  const deleteAccount = (emailId) => {
    modal.confirm({
      title: `删除账户 ${emailId}？`,
      content: '删除后会移除该账户凭证和缓存令牌。',
      okText: '删除',
      okButtonProps: { danger: true },
      cancelText: '取消',
      onOk: async () => {
        await apiRequest(`/accounts/${encodeURIComponent(emailId)}`, { method: 'DELETE' });
        message.success('账户已删除');
        actionRef.current?.reload();
      },
    });
  };

  const columns = [
    {
      title: '邮箱',
      dataIndex: 'email_id',
      width: 260,
      search: false,
      render: (_, row) => (
        <Space direction="vertical" size={2}>
          <Typography.Text strong copyable>
            {row.email_id}
          </Typography.Text>
          <Space wrap size={[4, 4]}>
            {(row.tags || []).map((tag) => (
              <Tag key={tag} icon={<TagsOutlined />}>
                {tag}
              </Tag>
            ))}
          </Space>
        </Space>
      ),
    },
    {
      title: '邮箱搜索',
      dataIndex: 'email_search',
      hideInTable: true,
    },
    {
      title: '标签搜索',
      dataIndex: 'tag_search',
      hideInTable: true,
    },
    {
      title: '状态',
      dataIndex: 'status',
      search: false,
      width: 110,
      render: (_, row) => statusBadge(row.status),
    },
    {
      title: '协议',
      dataIndex: 'auth_mode',
      search: false,
      width: 92,
      render: (_, row) => <Tag color="blue">{(row.auth_mode || 'imap').toUpperCase()}</Tag>,
    },
    {
      title: 'Client ID',
      dataIndex: 'client_id',
      search: false,
      ellipsis: true,
      copyable: true,
    },
    {
      title: 'AT 过期',
      dataIndex: 'access_token_expires_at',
      search: false,
      width: 180,
      render: (_, row) => formatDateTime(row.access_token_expires_at),
    },
    {
      title: 'RT 过期',
      dataIndex: 'refresh_token_expires_at',
      search: false,
      width: 180,
      render: (_, row) => formatDateTime(row.refresh_token_expires_at),
    },
    {
      title: '操作',
      valueType: 'option',
      width: 300,
      render: (_, row) => [
        <Tooltip key="emails" title="查看邮件">
          <Button icon={<InboxOutlined />} type="link" onClick={() => onOpenEmails(row.email_id)}>
            邮件
          </Button>
        </Tooltip>,
        <Button
          key="edit"
          icon={<EditOutlined />}
          type="link"
          onClick={() => {
            setEditingEmail(row.email_id);
            setEditOpen(true);
          }}
        >
          编辑
        </Button>,
        <Popconfirm
          key="refresh"
          title="刷新该账户 RT/AT？"
          okText="刷新"
          cancelText="取消"
          onConfirm={() => refreshAccount(row.email_id)}
        >
          <Button icon={<ReloadOutlined />} type="link">
            刷新
          </Button>
        </Popconfirm>,
        <Button key="delete" icon={<DeleteOutlined />} type="link" danger onClick={() => deleteAccount(row.email_id)}>
          删除
        </Button>,
      ],
    },
  ];

  return (
    <Space direction="vertical" size={16} className="full-width">
      <TokenRefreshPanel onRefreshAccounts={reload} />
      <ProTable
        actionRef={actionRef}
        rowKey="email_id"
        columns={columns}
        cardBordered
        className="admin-table"
        request={async (params) => {
          const query = buildQuery({
            page: params.current || 1,
            page_size: params.pageSize || 10,
            email_search: params.email_search,
            tag_search: params.tag_search,
          });
          const data = await apiRequest(`/accounts?${query}`);
          return {
            data: data.accounts || [],
            total: data.total_accounts || 0,
            success: true,
          };
        }}
        pagination={{
          defaultPageSize: 10,
          showSizeChanger: true,
          pageSizeOptions: [10, 20, 50, 100],
        }}
        toolbar={{
          title: '账户列表',
          tooltip: '点击“邮件”进入账户邮件视图。',
          actions: [
            <Button key="refresh" icon={<ReloadOutlined />} onClick={() => actionRef.current?.reload()}>
              刷新列表
            </Button>,
          ],
        }}
        search={{
          labelWidth: 'auto',
          span: { xs: 24, md: 12, lg: 8 },
        }}
      />
      <Card className="quiet-card">
        <Descriptions size="small" column={{ xs: 1, md: 3 }}>
          <Descriptions.Item label="凭证存储">SQLite / PostgreSQL</Descriptions.Item>
          <Descriptions.Item label="令牌缓存">Redis 或进程内缓存</Descriptions.Item>
          <Descriptions.Item label="邮件协议">IMAP / Microsoft Graph</Descriptions.Item>
        </Descriptions>
      </Card>
      <AccountEditModal
        emailId={editingEmail}
        open={editOpen}
        onOpenChange={setEditOpen}
        onSaved={() => actionRef.current?.reload()}
      />
    </Space>
  );
}
