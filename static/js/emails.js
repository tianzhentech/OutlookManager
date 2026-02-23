// 邮件管理
function viewAccountEmails(emailId) {
    currentAccount = emailId;
    document.getElementById('currentAccountEmail').textContent = emailId;
    document.getElementById('emailsNav').style.display = 'block';

    // 重置过滤器
    clearFilters();

    showPage('emails');
}

function backToAccounts() {
    currentAccount = null;
    document.getElementById('emailsNav').style.display = 'none';
    showPage('accounts');
}

function switchEmailTab(folder, targetElement = null) {
    currentEmailFolder = folder;
    currentEmailPage = 1;

    // 更新标签状态
    document.querySelectorAll('#emailsPage .tab').forEach(t => t.classList.remove('active'));

    if (targetElement) {
        targetElement.classList.add('active');
    } else {
        // 根据folder名称查找对应的标签按钮
        document.querySelectorAll('#emailsPage .tab').forEach(t => {
            if (t.onclick && t.onclick.toString().includes(`'${folder}'`)) {
                t.classList.add('active');
            }
        });
    }

    loadEmails();
}

async function loadEmails(forceRefresh = false) {
    if (!currentAccount) return;

    const emailsList = document.getElementById('emailsList');
    const refreshBtn = document.getElementById('refreshBtn');

    // 显示加载状态
    emailsList.innerHTML = '<div class="loading"><div class="loading-spinner"></div>正在加载邮件...</div>';
    refreshBtn.disabled = true;
    refreshBtn.innerHTML = '<span>⏳</span> 加载中...';

    try {
        const refreshParam = forceRefresh ? '&refresh=true' : '';
        const url = `/emails/${currentAccount}?folder=${currentEmailFolder}&page=${currentEmailPage}&page_size=100${refreshParam}`;
        const data = await apiRequest(url);

        // 存储所有邮件数据
        allEmails = data.emails || [];

        // 更新统计信息
        updateEmailStats(allEmails);

        // 应用当前过滤器
        applyFilters();

        // 更新最后更新时间
        document.getElementById('lastUpdateTime').textContent = new Date().toLocaleString();

        if (forceRefresh) {
            showNotification('邮件列表已刷新', 'success');
        }

    } catch (error) {
        emailsList.innerHTML = '<div class="error">❌ 加载失败: ' + error.message + '</div>';
        showNotification('加载邮件失败: ' + error.message, 'error');
    } finally {
        // 恢复刷新按钮状态
        refreshBtn.disabled = false;
        refreshBtn.innerHTML = '<span>🔄</span> 刷新';
    }
}

function updateEmailStats(emails) {
    const total = emails.length;
    const unread = emails.filter(email => !email.is_read).length;
    const today = emails.filter(email => {
        const emailDate = new Date(email.date);
        const today = new Date();
        return emailDate.toDateString() === today.toDateString();
    }).length;
    const withAttachments = emails.filter(email => email.has_attachments).length;

    document.getElementById('totalEmailCount').textContent = total;
    document.getElementById('unreadEmailCount').textContent = unread;
    document.getElementById('todayEmailCount').textContent = today;
    document.getElementById('attachmentEmailCount').textContent = withAttachments;
}

// 搜索和过滤功能
function searchEmails() {
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(() => {
        applyFilters();
    }, 300); // 防抖，300ms后执行搜索
}

function applyFilters() {
    const searchTerm = document.getElementById('emailSearch').value.toLowerCase();
    const folderFilter = document.getElementById('folderFilter').value;
    const statusFilter = document.getElementById('statusFilter').value;
    const timeFilter = document.getElementById('timeFilter').value;
    const attachmentFilter = document.getElementById('attachmentFilter').value;

    filteredEmails = allEmails.filter(email => {
        // 搜索过滤
        if (searchTerm) {
            const searchableText = `${email.subject || ''} ${email.from_email || ''}`.toLowerCase();
            if (!searchableText.includes(searchTerm)) {
                return false;
            }
        }

        // 文件夹过滤
        if (folderFilter !== 'all' && email.folder.toLowerCase() !== folderFilter) {
            return false;
        }

        // 状态过滤
        if (statusFilter === 'read' && !email.is_read) return false;
        if (statusFilter === 'unread' && email.is_read) return false;

        // 时间过滤
        if (timeFilter !== 'all') {
            const emailDate = new Date(email.date);
            const now = new Date();

            switch (timeFilter) {
                case 'today':
                    if (emailDate.toDateString() !== now.toDateString()) return false;
                    break;
                case 'week':
                    const weekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
                    if (emailDate < weekAgo) return false;
                    break;
                case 'month':
                    const monthAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
                    if (emailDate < monthAgo) return false;
                    break;
            }
        }

        // 附件过滤
        if (attachmentFilter === 'with' && !email.has_attachments) return false;
        if (attachmentFilter === 'without' && email.has_attachments) return false;

        return true;
    });

    renderFilteredEmails();
}

function renderFilteredEmails() {
    const emailsList = document.getElementById('emailsList');

    if (filteredEmails.length === 0) {
        emailsList.innerHTML = '<div class="text-center" style="padding: 40px; color: #64748b;">没有找到匹配的邮件</div>';
        return;
    }

    emailsList.innerHTML = filteredEmails.map(email => createEmailItem(email)).join('');
}

function clearFilters() {
    document.getElementById('emailSearch').value = '';
    document.getElementById('folderFilter').value = 'all';
    document.getElementById('statusFilter').value = 'all';
    document.getElementById('timeFilter').value = 'all';
    document.getElementById('attachmentFilter').value = 'all';

    filteredEmails = [...allEmails];
    renderFilteredEmails();
}

function createEmailItem(email) {
    const unreadClass = email.is_read ? '' : 'unread';
    const attachmentIcon = email.has_attachments ? '<span style="color: #8b5cf6;">📎</span>' : '';
    const readIcon = email.is_read ? '📖' : '📧';

    return `
        <div class="email-item ${unreadClass}" onclick="showEmailDetail('${email.message_id}')">
            <div class="email-avatar">${email.sender_initial}</div>
            <div class="email-content">
                <div class="email-header">
                    <div class="email-subject">${email.subject || '(无主题)'}</div>
                    <div class="email-date">${formatEmailDate(email.date)}</div>
                </div>
                <div class="email-from">${readIcon} ${email.from_email} ${attachmentIcon}</div>
                <div class="email-preview">文件夹: ${email.folder} | 点击查看详情</div>
            </div>
        </div>
    `;
}

async function showEmailDetail(messageId) {
    document.getElementById('emailModal').classList.remove('hidden');
    document.getElementById('emailModalTitle').textContent = '邮件详情';
    document.getElementById('emailModalContent').innerHTML = '<div class="loading">正在加载邮件详情...</div>';

    try {
        const data = await apiRequest(`/emails/${currentAccount}/${messageId}`);

        document.getElementById('emailModalTitle').textContent = data.subject || '(无主题)';
        document.getElementById('emailModalContent').innerHTML = `
            <div class="email-detail-meta">
                <p><strong>发件人:</strong> ${data.from_email}</p>
                <p><strong>收件人:</strong> ${data.to_email}</p>
                <p><strong>日期:</strong> ${formatEmailDate(data.date)} (${new Date(data.date).toLocaleString()})</p>
                <p class="email-id-line"><strong>邮件ID:</strong><span class="email-id-value">${data.message_id}</span></p>
            </div>
            ${renderEmailContent(data)}
        `;

    } catch (error) {
        document.getElementById('emailModalContent').innerHTML = '<div class="error">加载失败: ' + error.message + '</div>';
    }
}

function renderEmailContent(email) {
    const hasHtml = email.body_html && email.body_html.trim();
    const hasPlain = email.body_plain && email.body_plain.trim();

    if (!hasHtml && !hasPlain) {
        return '<p style="color: #9ca3af; font-style: italic;">此邮件无内容</p>';
    }

    if (hasHtml) {
        const sanitizedHtml = email.body_html.replace(/"/g, '&quot;');

        return `
            <div class="email-content-tabs">
                <button class="content-tab active" onclick="showEmailContentTab('html', this)">HTML视图</button>
                ${hasPlain ? '<button class="content-tab" onclick="showEmailContentTab(\'plain\', this)">纯文本</button>' : ''}
                <button class="content-tab" onclick="showEmailContentTab('raw', this)">源码</button>
            </div>

            <div class="email-content-body">
                <div id="htmlContent">
                    <iframe srcdoc="${sanitizedHtml}" style="width: 100%; min-height: 400px; border: none;" sandbox="allow-same-origin"></iframe>
                </div>
                ${hasPlain ? `<div id="plainContent" class="hidden"><pre>${email.body_plain}</pre></div>` : ''}
                <div id="rawContent" class="hidden"><pre style="background: #1e293b; color: #e2e8f0; padding: 16px; border-radius: 6px; overflow-x: auto; font-size: 12px;">${email.body_html.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</pre></div>
            </div>
        `;
    } else {
        return `<div class="email-content-body"><pre>${email.body_plain}</pre></div>`;
    }
}

function showEmailContentTab(type, targetElement = null) {
    // 更新标签状态
    document.querySelectorAll('.content-tab').forEach(tab => tab.classList.remove('active'));

    if (targetElement) {
        targetElement.classList.add('active');
    } else {
        // 根据type查找对应的标签按钮
        document.querySelectorAll('.content-tab').forEach(tab => {
            if (tab.onclick && tab.onclick.toString().includes(`'${type}'`)) {
                tab.classList.add('active');
            }
        });
    }

    // 隐藏所有内容
    document.querySelectorAll('#htmlContent, #plainContent, #rawContent').forEach(content => {
        content.classList.add('hidden');
    });

    // 显示对应内容
    document.getElementById(type + 'Content').classList.remove('hidden');
}

function closeEmailModal() {
    document.getElementById('emailModal').classList.add('hidden');
}

function refreshEmails() {
    loadEmails(true); // 强制刷新
}

async function clearCache() {
    if (!currentAccount) return;

    try {
        await apiRequest(`/cache/${currentAccount}`, { method: 'DELETE' });
        showNotification('缓存已清除', 'success');
        loadEmails(true);
    } catch (error) {
        showNotification('清除缓存失败: ' + error.message, 'error');
    }
}

function exportEmails() {
    if (!filteredEmails || filteredEmails.length === 0) {
        showNotification('没有邮件可导出', 'warning');
        return;
    }

    const csvContent = generateEmailCSV(filteredEmails);
    downloadCSV(csvContent, `emails_${currentAccount}_${new Date().toISOString().split('T')[0]}.csv`);
    showNotification(`已导出 ${filteredEmails.length} 封邮件`, 'success');
}

function generateEmailCSV(emails) {
    const headers = ['主题', '发件人', '日期', '文件夹', '是否已读', '是否有附件'];
    const rows = emails.map(email => [
        `"${(email.subject || '').replace(/"/g, '""')}"`,
        `"${email.from_email.replace(/"/g, '""')}"`,
        `"${email.date}"`,
        `"${email.folder}"`,
        email.is_read ? '已读' : '未读',
        email.has_attachments ? '有附件' : '无附件'
    ]);

    return [headers, ...rows].map(row => row.join(',')).join('\n');
}

function downloadCSV(content, filename) {
    const blob = new Blob(['\uFEFF' + content], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    const url = URL.createObjectURL(blob);
    link.setAttribute('href', url);
    link.setAttribute('download', filename);
    link.style.visibility = 'hidden';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

function updateEmailsPagination(totalEmails, pageSize) {
    const pagination = document.getElementById('emailsPagination');
    const totalPages = Math.ceil(totalEmails / pageSize);

    if (totalPages <= 1) {
        pagination.classList.add('hidden');
        return;
    }

    pagination.classList.remove('hidden');
    pagination.innerHTML = `
        <button class="btn btn-secondary btn-sm" onclick="changeEmailPage(${currentEmailPage - 1})" ${currentEmailPage === 1 ? 'disabled' : ''}>‹ 上一页</button>
        <span style="padding: 0 16px; color: #64748b;">${currentEmailPage} / ${totalPages}</span>
        <button class="btn btn-secondary btn-sm" onclick="changeEmailPage(${currentEmailPage + 1})" ${currentEmailPage === totalPages ? 'disabled' : ''}>下一页 ›</button>
    `;
}

function changeEmailPage(page) {
    currentEmailPage = page;
    loadEmails();
}
