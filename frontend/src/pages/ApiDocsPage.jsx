import { useEffect, useMemo, useState } from 'react';
import { CopyOutlined, DownloadOutlined, ReloadOutlined } from '@ant-design/icons';
import { ProCard, ProTable } from '@ant-design/pro-components';
import { App, Button, Collapse, Space, Tag, Typography } from 'antd';
import { downloadText } from '../utils.js';

const methodColor = {
  get: 'green',
  post: 'blue',
  put: 'orange',
  delete: 'red',
  patch: 'purple',
};

function operationRows(spec) {
  const paths = spec?.paths || {};
  return Object.entries(paths).flatMap(([path, methods]) =>
    Object.entries(methods)
      .filter(([method]) => ['get', 'post', 'put', 'delete', 'patch'].includes(method))
      .map(([method, operation]) => ({
        key: `${method}-${path}`,
        method: method.toUpperCase(),
        path,
        summary: operation.summary || operation.description || '-',
        tags: operation.tags || [],
        operationId: operation.operationId || '',
      })),
  );
}

function markdownForSpec(spec, rows) {
  const title = spec?.info?.title || 'Outlook Manager API';
  const version = spec?.info?.version || '';
  const lines = [`# ${title}`, '', version ? `Version: ${version}` : '', '', '| Method | Path | Summary |', '| --- | --- | --- |'];
  rows.forEach((row) => {
    lines.push(`| ${row.method} | \`${row.path}\` | ${String(row.summary).replace(/\|/g, '\\|')} |`);
  });
  return lines.filter(Boolean).join('\n');
}

export function ApiDocsPage() {
  const { message } = App.useApp();
  const [spec, setSpec] = useState(null);
  const [loading, setLoading] = useState(false);

  const rows = useMemo(() => operationRows(spec), [spec]);
  const baseUrl = window.location.origin;

  const load = async () => {
    setLoading(true);
    try {
      const response = await fetch('/openapi.json', {
        credentials: 'same-origin',
        headers: { Accept: 'application/json' },
      });
      if (response.status === 401) {
        window.location.href = '/admin';
        return;
      }
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      setSpec(await response.json());
    } catch (error) {
      message.error(`加载 OpenAPI 失败：${error.message}`);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  return (
    <Space direction="vertical" size={16} className="full-width">
      <ProCard bordered>
        <Space direction="vertical" size={12} className="full-width">
          <Typography.Title level={4}>{spec?.info?.title || 'Outlook Manager API'}</Typography.Title>
          <Space wrap>
            <Typography.Text code>{baseUrl}</Typography.Text>
            <Button
              icon={<CopyOutlined />}
              onClick={() => navigator.clipboard.writeText(baseUrl).then(() => message.success('Base URL 已复制'))}
            >
              复制 Base URL
            </Button>
            <Button icon={<ReloadOutlined />} onClick={load} loading={loading}>
              刷新
            </Button>
            <Button
              icon={<DownloadOutlined />}
              onClick={() => {
                downloadText('outlook-email-api-docs.md', markdownForSpec(spec, rows), 'text/markdown;charset=utf-8');
                message.success('API 文档已下载');
              }}
            >
              下载 Markdown
            </Button>
          </Space>
        </Space>
      </ProCard>
      <ProTable
        rowKey="key"
        loading={loading}
        search={false}
        cardBordered
        dataSource={rows}
        pagination={{ pageSize: 12 }}
        columns={[
          {
            title: '方法',
            dataIndex: 'method',
            width: 100,
            render: (_, row) => <Tag color={methodColor[row.method.toLowerCase()] || 'default'}>{row.method}</Tag>,
          },
          {
            title: '路径',
            dataIndex: 'path',
            copyable: true,
            ellipsis: true,
          },
          {
            title: '说明',
            dataIndex: 'summary',
          },
          {
            title: '标签',
            dataIndex: 'tags',
            width: 180,
            render: (_, row) => (row.tags || []).map((tag) => <Tag key={tag}>{tag}</Tag>),
          },
        ]}
        toolbar={{ title: '接口清单' }}
      />
      <Collapse
        items={[
          {
            key: 'raw',
            label: 'OpenAPI 原始 JSON',
            children: <pre className="api-json">{JSON.stringify(spec, null, 2)}</pre>,
          },
        ]}
      />
    </Space>
  );
}
