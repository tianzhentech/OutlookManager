import { useMemo, useState } from 'react';
import { CloudUploadOutlined, ExperimentOutlined, FileTextOutlined, RollbackOutlined } from '@ant-design/icons';
import { ProCard } from '@ant-design/pro-components';
import { App, Button, Input, Progress, Select, Space, Table, Tag, Typography } from 'antd';
import { apiRequest } from '../api.js';
import { parseBatchAccountLine } from '../utils.js';

const sampleData = `example1@outlook.com----password1----refresh_token_here_1----client_id_here_1
example2@outlook.com----password2----client_id_here_2----refresh_token_here_2
example3@outlook.com----password3----refresh_token_here_3----client_id_here_3`;

const authModeOptions = [
  { label: 'auto（自动识别）', value: 'auto' },
  { label: 'imap', value: 'imap' },
  { label: 'graph', value: 'graph' },
];

export function BatchAddPage({ onDone }) {
  const { message } = App.useApp();
  const [text, setText] = useState('');
  const [authMode, setAuthMode] = useState('auto');
  const [running, setRunning] = useState(false);
  const [current, setCurrent] = useState(0);
  const [results, setResults] = useState([]);

  const lines = useMemo(() => text.split('\n').map((line) => line.trim()).filter(Boolean), [text]);
  const percent = lines.length ? Math.round((current / lines.length) * 100) : 0;

  const validate = () => {
    if (!lines.length) {
      message.warning('请先输入账户信息');
      return;
    }

    const parsed = lines.map((line, index) => ({ index: index + 1, ...parseBatchAccountLine(line) }));
    const invalid = parsed.filter((item) => !item.ok);
    if (!invalid.length) {
      const clientRefreshCount = parsed.filter((item) => item.format === 'client-refresh').length;
      message.success(`格式验证通过：${parsed.length} 个账户，客户端ID在前 ${clientRefreshCount} 个`);
    } else {
      message.error(`发现 ${invalid.length} 行格式错误：第 ${invalid.map((item) => item.index).join(', ')} 行`);
    }
  };

  const runBatch = async () => {
    if (!lines.length) {
      message.warning('请输入账户信息');
      return;
    }

    setRunning(true);
    setCurrent(0);
    setResults([]);
    const nextResults = [];

    for (let index = 0; index < lines.length; index += 1) {
      const parsed = parseBatchAccountLine(lines[index]);
      setCurrent(index + 1);

      if (!parsed.ok) {
        nextResults.push({
          key: `${index}-invalid`,
          email: '格式错误',
          status: 'error',
          message: parsed.message,
        });
        setResults([...nextResults]);
        continue;
      }

      try {
        await apiRequest('/accounts', {
          method: 'POST',
          body: JSON.stringify({
            email: parsed.email,
            mailbox_password: parsed.password || null,
            refresh_token: parsed.refreshToken,
            client_id: parsed.clientId,
            auth_mode: authMode,
          }),
        });
        nextResults.push({
          key: parsed.email,
          email: parsed.email,
          status: 'success',
          message: '添加成功',
        });
      } catch (error) {
        nextResults.push({
          key: `${parsed.email}-${index}`,
          email: parsed.email,
          status: 'error',
          message: error.message,
        });
      }
      setResults([...nextResults]);
      await new Promise((resolve) => setTimeout(resolve, 100));
    }

    const successCount = nextResults.filter((item) => item.status === 'success').length;
    const failCount = nextResults.length - successCount;
    if (successCount) {
      message.success(`添加完成：成功 ${successCount}，失败 ${failCount}`);
    } else {
      message.error('所有账户添加失败，请检查凭证');
    }
    setRunning(false);
  };

  return (
    <Space direction="vertical" size={16} className="full-width">
      <ProCard bordered className="form-shell">
        <Space direction="vertical" size={16} className="full-width">
          <Typography.Title level={4}>添加账户</Typography.Title>
          <Typography.Paragraph type="secondary">
            每行一个账户，单行和多行都可以。支持两种格式：邮箱----密码----刷新令牌----客户端ID，或 邮箱----密码----客户端ID----刷新令牌。
          </Typography.Paragraph>
          <Space direction="vertical" size={6} className="full-width">
            <Typography.Text strong>认证模式</Typography.Text>
            <Select value={authMode} options={authModeOptions} onChange={setAuthMode} style={{ maxWidth: 280 }} />
          </Space>
          <Space direction="vertical" size={6} className="full-width">
            <Typography.Text strong>账户数据</Typography.Text>
            <Input.TextArea rows={12} value={text} onChange={(event) => setText(event.target.value)} placeholder={sampleData} />
          </Space>
          <div className="form-actions">
            <Space wrap>
              <Button icon={<FileTextOutlined />} onClick={() => setText(sampleData)}>
                填入示例
              </Button>
              <Button icon={<ExperimentOutlined />} onClick={validate}>
                验证格式
              </Button>
              <Button type="primary" icon={<CloudUploadOutlined />} loading={running} onClick={runBatch}>
                开始添加
              </Button>
              <Button icon={<RollbackOutlined />} onClick={onDone}>
                返回列表
              </Button>
            </Space>
          </div>
        </Space>
      </ProCard>
      {running || results.length ? (
        <ProCard bordered>
          <Space direction="vertical" size={12} className="full-width">
            <Progress percent={percent} status={running ? 'active' : 'normal'} />
            <Typography.Text type="secondary">
              已处理 {current} / {lines.length}
            </Typography.Text>
            <Table
              size="small"
              rowKey="key"
              dataSource={results}
              pagination={{ pageSize: 8 }}
              columns={[
                { title: '邮箱', dataIndex: 'email' },
                {
                  title: '结果',
                  dataIndex: 'status',
                  width: 100,
                  render: (status) =>
                    status === 'success' ? <Tag color="success">成功</Tag> : <Tag color="error">失败</Tag>,
                },
                { title: '说明', dataIndex: 'message' },
              ]}
            />
          </Space>
        </ProCard>
      ) : null}
    </Space>
  );
}
