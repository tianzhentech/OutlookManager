// API文档相关函数
function initApiDocs() {
    // 更新Base URL
    const baseUrl = window.location.origin;
    document.getElementById('baseUrlExample').textContent = baseUrl;
}

function copyApiBaseUrl() {
    const baseUrl = window.location.origin;
    navigator.clipboard.writeText(baseUrl).then(() => {
        showNotification('Base URL已复制到剪贴板', 'success');
    }).catch(() => {
        showNotification('复制失败，请手动复制', 'error');
    });
}

function copyEmailAddress(emailAddress) {
    // 清理邮箱地址（去除可能的空格和特殊字符）
    const cleanEmail = emailAddress.trim();

    if (!cleanEmail) {
        showNotification('邮箱地址为空', 'error');
        return;
    }

    // 复制到剪贴板
    navigator.clipboard.writeText(cleanEmail).then(() => {
        // 显示成功通知
        showNotification(`邮箱地址已复制: ${cleanEmail}`, 'success');

        // 添加视觉反馈
        const emailElement = document.getElementById('currentAccountEmail');
        if (emailElement) {
            emailElement.classList.add('copy-success');
            setTimeout(() => {
                emailElement.classList.remove('copy-success');
            }, 300);
        }
    }).catch((error) => {
        console.error('复制失败:', error);

        // 降级方案：尝试使用旧的复制方法
        try {
            const textArea = document.createElement('textarea');
            textArea.value = cleanEmail;
            textArea.style.position = 'fixed';
            textArea.style.opacity = '0';
            document.body.appendChild(textArea);
            textArea.select();
            document.execCommand('copy');
            document.body.removeChild(textArea);

            showNotification(`邮箱地址已复制: ${cleanEmail}`, 'success');
        } catch (fallbackError) {
            console.error('降级复制方案也失败:', fallbackError);
            showNotification('复制失败，请手动复制邮箱地址', 'error');

            // 选中文本以便用户手动复制
            const emailElement = document.getElementById('currentAccountEmail');
            if (emailElement && window.getSelection) {
                const selection = window.getSelection();
                const range = document.createRange();
                range.selectNodeContents(emailElement);
                selection.removeAllRanges();
                selection.addRange(range);
            }
        }
    });
}

function downloadApiDocs() {
    const apiDocs = generateApiDocsMarkdown();
    const blob = new Blob([apiDocs], { type: 'text/markdown;charset=utf-8;' });
    const link = document.createElement('a');
    const url = URL.createObjectURL(blob);
    link.setAttribute('href', url);
    link.setAttribute('download', 'outlook-email-api-docs.md');
    link.style.visibility = 'hidden';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    showNotification('API文档已下载', 'success');
}

function generateApiDocsMarkdown() {
    const baseUrl = window.location.origin;
    return `# Outlook邮件管理系统 API文档

## 基础信息

- **Base URL**: ${baseUrl}
- **认证方式**: 无需认证
- **响应格式**: JSON

## 接口列表

### 1. 获取邮箱列表

**请求**
\`\`\`
GET /accounts
\`\`\`

**响应示例**
\`\`\`json
{
  "accounts": [
    {
      "email_id": "example@outlook.com",
      "status": "active",
      "last_sync": "2024-01-01T12:00:00Z"
    }
  ],
  "total_count": 1
}
\`\`\`

### 2. 获取邮件列表

**请求**
\`\`\`
GET /emails/{email_id}?folder=inbox&page=1&page_size=20&refresh=false
\`\`\`

**参数说明**
- \`email_id\`: 邮箱地址（URL编码）
- \`folder\`: 文件夹 (all, inbox, junk)
- \`page\`: 页码
- \`page_size\`: 每页数量
- \`refresh\`: 是否强制刷新

**响应示例**
\`\`\`json
{
  "email_id": "example@outlook.com",
  "folder_view": "inbox",
  "page": 1,
  "page_size": 20,
  "total_emails": 150,
  "emails": [...]
}
\`\`\`

### 3. 获取邮件详情

**请求**
\`\`\`
GET /emails/{email_id}/{message_id}
\`\`\`

**参数说明**
- \`email_id\`: 邮箱地址（URL编码）
- \`message_id\`: 邮件ID（IMAP: \`{folder}-{id}\`，Graph: \`GRAPH-{encoded_id}\`）

**响应示例**
\`\`\`json
{
  "message_id": "INBOX-1",
  "subject": "邮件主题",
  "from_email": "sender@example.com",
  "to_email": "example@outlook.com",
  "date": "2024-01-01T12:00:00Z",
  "body_plain": "纯文本内容",
  "body_html": "HTML内容"
}
\`\`\`

---
生成时间: ${new Date().toLocaleString()}
`;
}

async function tryApi(apiType) {
    const baseUrl = window.location.origin;
    let url, responseElementId;

    switch (apiType) {
        case 'accounts':
            url = `${baseUrl}/accounts`;
            responseElementId = 'accountsResponse';
            break;
        case 'emails':
            // 需要先获取一个邮箱账户
            try {
                const accountsData = await apiRequest('/accounts');
                if (accountsData.accounts && accountsData.accounts.length > 0) {
                    const emailId = encodeURIComponent(accountsData.accounts[0].email_id);
                    url = `${baseUrl}/emails/${emailId}?folder=inbox&page=1&page_size=5`;
                    responseElementId = 'emailsResponse';
                } else {
                    showNotification('没有可用的邮箱账户，请先添加账户', 'warning');
                    return;
                }
            } catch (error) {
                showNotification('获取邮箱账户失败: ' + error.message, 'error');
                return;
            }
            break;
        case 'emailDetail':
            // 需要先获取一个邮件ID
            try {
                const accountsData = await apiRequest('/accounts');
                if (accountsData.accounts && accountsData.accounts.length > 0) {
                    const emailId = encodeURIComponent(accountsData.accounts[0].email_id);
                    const emailsData = await apiRequest(`/emails/${emailId}?folder=all&page=1&page_size=1`);
                    if (emailsData.emails && emailsData.emails.length > 0) {
                        const messageId = emailsData.emails[0].message_id;
                        url = `${baseUrl}/emails/${emailId}/${messageId}`;
                        responseElementId = 'emailDetailResponse';
                    } else {
                        showNotification('该邮箱没有邮件', 'warning');
                        return;
                    }
                } else {
                    showNotification('没有可用的邮箱账户，请先添加账户', 'warning');
                    return;
                }
            } catch (error) {
                showNotification('获取邮件数据失败: ' + error.message, 'error');
                return;
            }
            break;
        default:
            return;
    }

    try {
        showNotification('正在调用API...', 'info', '', 2000);
        const response = await fetch(url, { credentials: 'same-origin' });
        if (response.status === 401) {
            window.location.href = '/admin';
            return;
        }
        const data = await response.json();

        // 显示响应结果
        const responseElement = document.getElementById(responseElementId);
        const responseDataElement = document.getElementById(responseElementId.replace('Response', 'ResponseData'));

        responseDataElement.textContent = JSON.stringify(data, null, 2);
        responseElement.classList.add('show');

        showNotification('API调用成功！', 'success');

    } catch (error) {
        showNotification('API调用失败: ' + error.message, 'error');
    }
}
