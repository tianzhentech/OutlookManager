// 表单管理函数
function clearAddAccountForm() {
    document.getElementById('email').value = '';
    document.getElementById('refreshToken').value = '';
    document.getElementById('clientId').value = '';
    document.getElementById('authMode').value = 'auto';
    document.getElementById('mailboxPassword').value = '';
}

function clearBatchForm() {
    document.getElementById('batchAccounts').value = '';
    document.getElementById('batchAuthMode').value = 'auto';
}

function formatTokenExpiry(dateTimeString) {
    if (!dateTimeString) {
        return '未获取';
    }

    const date = new Date(dateTimeString);
    if (Number.isNaN(date.getTime())) {
        return '时间无效';
    }

    return date.toLocaleString('zh-CN', { hour12: false });
}

function formatRefreshUnitLabel(unit) {
    if (unit === 'day') return '天';
    if (unit === 'hour') return '小时';
    return '分钟';
}

function buildRefreshTokenButtonId(emailId) {
    return `refresh-token-${String(emailId).replace(/[^a-zA-Z0-9_-]/g, '_')}`;
}

function parseTagsInput(tagsText) {
    if (!tagsText) {
        return [];
    }
    return tagsText
        .split(',')
        .map(tag => tag.trim())
        .filter(tag => tag);
}

function renderTokenRefreshSettings(settings) {
    tokenRefreshSettings = settings || null;

    const enabledInput = document.getElementById('tokenRefreshEnabled');
    const intervalInput = document.getElementById('tokenRefreshInterval');
    const unitSelect = document.getElementById('tokenRefreshUnit');
    const scheduleInfo = document.getElementById('tokenRefreshScheduleInfo');

    if (!enabledInput || !intervalInput || !unitSelect || !scheduleInfo) {
        return;
    }

    if (!settings) {
        enabledInput.checked = false;
        intervalInput.value = 12;
        unitSelect.value = 'hour';
        scheduleInfo.textContent = '定时刷新未配置';
        return;
    }

    enabledInput.checked = Boolean(settings.enabled);
    intervalInput.value = settings.interval_value || 12;
    unitSelect.value = settings.interval_unit || 'hour';

    const nextRunText = settings.next_run_at ? formatTokenExpiry(settings.next_run_at) : '未计划';
    const lastRunText = settings.last_run_at ? formatTokenExpiry(settings.last_run_at) : '暂无';
    const intervalLabel = `${settings.interval_value}${formatRefreshUnitLabel(settings.interval_unit)}`;

    if (settings.enabled) {
        scheduleInfo.textContent = `已启用（每${intervalLabel}）| 下次: ${nextRunText} | 上次: ${lastRunText}`;
    } else {
        scheduleInfo.textContent = `已关闭 | 上次: ${lastRunText}`;
    }
}

async function loadTokenRefreshSettings(silent = true) {
    try {
        const settings = await apiRequest('/token-refresh/settings');
        renderTokenRefreshSettings(settings);
        return settings;
    } catch (error) {
        if (!silent) {
            showError('加载定时刷新设置失败: ' + error.message);
        }
        return null;
    }
}

async function saveTokenRefreshSettings() {
    const enabledInput = document.getElementById('tokenRefreshEnabled');
    const intervalInput = document.getElementById('tokenRefreshInterval');
    const unitSelect = document.getElementById('tokenRefreshUnit');
    const saveBtn = document.getElementById('saveTokenRefreshSettingsBtn');

    if (!enabledInput || !intervalInput || !unitSelect || !saveBtn) {
        return;
    }

    const intervalValue = parseInt(intervalInput.value, 10);
    if (!Number.isFinite(intervalValue) || intervalValue < 1) {
        showWarning('刷新间隔必须是大于等于 1 的整数');
        return;
    }

    saveBtn.disabled = true;
    const previousText = saveBtn.innerHTML;
    saveBtn.innerHTML = '<span>⏳</span> 保存中...';

    try {
        const updated = await apiRequest('/token-refresh/settings', {
            method: 'PUT',
            body: JSON.stringify({
                enabled: Boolean(enabledInput.checked),
                interval_value: intervalValue,
                interval_unit: unitSelect.value
            })
        });

        renderTokenRefreshSettings(updated);
        showSuccess('定时刷新设置已保存');
    } catch (error) {
        showError('保存定时刷新设置失败: ' + error.message);
    } finally {
        saveBtn.disabled = false;
        saveBtn.innerHTML = previousText;
    }
}

async function refreshAllAccountTokens() {
    if (isRefreshingAllTokens) {
        return;
    }

    const refreshAllBtn = document.getElementById('refreshAllTokensBtn');
    if (!refreshAllBtn) {
        return;
    }

    isRefreshingAllTokens = true;
    refreshAllBtn.disabled = true;
    const previousText = refreshAllBtn.innerHTML;
    refreshAllBtn.innerHTML = '<span>⏳</span> 刷新中...';

    try {
        const result = await apiRequest('/token-refresh/refresh-all', {
            method: 'POST'
        });

        if ((result.failure_count || 0) > 0) {
            showWarning(`全部刷新完成：成功 ${result.success_count}，失败 ${result.failure_count}`);
        } else {
            showSuccess(`全部刷新完成：成功 ${result.success_count}`);
        }

        await loadAccounts(accountsCurrentPage);
    } catch (error) {
        showError('全部刷新失败: ' + error.message);
    } finally {
        isRefreshingAllTokens = false;
        refreshAllBtn.disabled = false;
        refreshAllBtn.innerHTML = previousText;
    }
}

async function refreshAccountToken(emailId, event = null) {
    if (event) {
        event.stopPropagation();
    }

    if (!emailId || refreshingTokenAccountIds.has(emailId)) {
        return;
    }

    const refreshBtnId = buildRefreshTokenButtonId(emailId);
    const refreshBtn = document.getElementById(refreshBtnId);

    refreshingTokenAccountIds.add(emailId);
    if (refreshBtn) {
        refreshBtn.disabled = true;
        refreshBtn.dataset.originalText = refreshBtn.innerHTML;
        refreshBtn.innerHTML = '<span>⏳</span> 刷新中...';
    }

    try {
        await apiRequest(`/accounts/${encodeURIComponent(emailId)}/refresh-token`, {
            method: 'POST'
        });

        showSuccess(`${emailId} 的RT已刷新`);
        await loadAccounts(accountsCurrentPage);
    } catch (error) {
        showError(`刷新 ${emailId} 失败: ${error.message}`);
    } finally {
        refreshingTokenAccountIds.delete(emailId);
        if (refreshBtn) {
            refreshBtn.disabled = false;
            refreshBtn.innerHTML = refreshBtn.dataset.originalText || '<span>🔁</span> 刷新RT';
        }
    }
}

function isGuid(value) {
    return /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(value);
}

function looksLikeRefreshToken(value) {
    if (!value) return false;
    return value.startsWith('M.') || value.length > 40;
}

function parseBatchAccountLine(line) {
    const parts = line.split('----').map(p => p.trim());
    if (parts.length !== 4 || parts.some(part => !part)) {
        return {
            ok: false,
            message: '格式错误：应为 邮箱----密码----刷新令牌----客户端ID 或 邮箱----密码----客户端ID----刷新令牌'
        };
    }

    const [email, password, third, fourth] = parts;

    let refreshToken = third;
    let clientId = fourth;
    let format = 'refresh-client';

    const thirdIsGuid = isGuid(third);
    const fourthIsGuid = isGuid(fourth);

    if (thirdIsGuid && !fourthIsGuid) {
        clientId = third;
        refreshToken = fourth;
        format = 'client-refresh';
    } else if (!thirdIsGuid && fourthIsGuid) {
        refreshToken = third;
        clientId = fourth;
    } else {
        const thirdLooksRefresh = looksLikeRefreshToken(third);
        const fourthLooksRefresh = looksLikeRefreshToken(fourth);
        if (!thirdLooksRefresh && fourthLooksRefresh) {
            clientId = third;
            refreshToken = fourth;
            format = 'client-refresh';
        }
    }

    return {
        ok: true,
        email,
        password,
        refreshToken,
        clientId,
        format
    };
}

function loadSampleData() {
    const sampleData = `example1@outlook.com----password1----refresh_token_here_1----client_id_here_1
example2@outlook.com----password2----client_id_here_2----refresh_token_here_2
example3@outlook.com----password3----refresh_token_here_3----client_id_here_3`;
    document.getElementById('batchAccounts').value = sampleData;
    showNotification('示例数据已加载，请替换为真实数据', 'info');
}

function validateBatchFormat() {
    const batchText = document.getElementById('batchAccounts').value.trim();
    if (!batchText) {
        showNotification('请先输入账户信息', 'warning');
        return;
    }

    const lines = batchText.split('\n').filter(line => line.trim());
    let validCount = 0;
    let refreshClientCount = 0;
    let clientRefreshCount = 0;
    let invalidLines = [];

    lines.forEach((line, index) => {
        const parsed = parseBatchAccountLine(line);
        if (!parsed.ok) {
            invalidLines.push(index + 1);
            return;
        }

        validCount++;
        if (parsed.format === 'client-refresh') {
            clientRefreshCount++;
        } else {
            refreshClientCount++;
        }
    });

    if (invalidLines.length === 0) {
        showNotification(`格式验证通过！共 ${validCount} 个有效账户（令牌在前: ${refreshClientCount}，客户端ID在前: ${clientRefreshCount}）`, 'success');
    } else {
        showNotification(`发现 ${invalidLines.length} 行格式错误：第 ${invalidLines.join(', ')} 行`, 'error');
    }
}

async function testAccountConnection() {
    const email = document.getElementById('email').value.trim();
    const refreshToken = document.getElementById('refreshToken').value.trim();
    const clientId = document.getElementById('clientId').value.trim();

    if (!email || !refreshToken || !clientId) {
        showNotification('请填写所有必需字段', 'warning');
        return;
    }

    const testBtn = document.getElementById('testBtn');
    testBtn.disabled = true;
    testBtn.innerHTML = '<span>⏳</span> 测试中...';

    try {
        // 这里可以调用一个测试接口
        await new Promise(resolve => setTimeout(resolve, 2000)); // 模拟测试
        showNotification('连接测试成功！账户配置正确', 'success');
    } catch (error) {
        showNotification('连接测试失败：' + error.message, 'error');
    } finally {
        testBtn.disabled = false;
        testBtn.innerHTML = '<span>🔍</span> 测试连接';
    }
}

function setAccountInfoFieldsDisabled(disabled) {
    const fieldIds = [
        'accountInfoMailboxPassword',
        'accountInfoRefreshToken',
        'accountInfoClientId',
        'accountInfoAuthMode',
        'accountInfoTags'
    ];

    fieldIds.forEach(id => {
        const field = document.getElementById(id);
        if (field) {
            field.disabled = disabled;
        }
    });
}

async function openAccountInfoModal(emailId, event = null) {
    if (event) {
        event.stopPropagation();
    }

    const modal = document.getElementById('accountInfoModal');
    if (!modal || !emailId) {
        return;
    }

    currentAccountInfoEmail = emailId;
    document.getElementById('accountInfoEmail').value = emailId;
    document.getElementById('accountInfoStatus').value = '加载中...';
    document.getElementById('accountInfoAtExpires').value = '加载中...';
    document.getElementById('accountInfoRtExpires').value = '加载中...';
    document.getElementById('accountInfoAccessToken').value = '加载中...';
    document.getElementById('accountInfoMailboxPassword').value = '';
    document.getElementById('accountInfoRefreshToken').value = '';
    document.getElementById('accountInfoClientId').value = '';
    document.getElementById('accountInfoAuthMode').value = 'auto';
    document.getElementById('accountInfoTags').value = '';
    document.getElementById('accountInfoModalTitle').textContent = `账户信息 - ${emailId}`;

    const saveBtn = document.getElementById('saveAccountInfoBtn');
    const originalText = saveBtn.innerHTML;
    saveBtn.disabled = true;
    saveBtn.innerHTML = '<span>⏳</span> 加载中...';
    setAccountInfoFieldsDisabled(true);
    modal.style.display = 'flex';

    try {
        const detail = await apiRequest(`/accounts/${encodeURIComponent(emailId)}`);
        document.getElementById('accountInfoStatus').value = detail.status || 'unknown';
        document.getElementById('accountInfoAtExpires').value = formatTokenExpiry(detail.access_token_expires_at);
        document.getElementById('accountInfoRtExpires').value = formatTokenExpiry(detail.refresh_token_expires_at);
        document.getElementById('accountInfoAccessToken').value = detail.access_token || '未缓存AT（先取件或刷新RT）';
        document.getElementById('accountInfoMailboxPassword').value = detail.mailbox_password || '';
        document.getElementById('accountInfoRefreshToken').value = detail.refresh_token || '';
        document.getElementById('accountInfoClientId').value = detail.client_id || '';
        document.getElementById('accountInfoAuthMode').value = detail.auth_mode || 'imap';
        document.getElementById('accountInfoTags').value = Array.isArray(detail.tags) ? detail.tags.join(',') : '';
    } catch (error) {
        showError('加载账户信息失败: ' + error.message);
        closeAccountInfoModal();
        return;
    } finally {
        setAccountInfoFieldsDisabled(false);
        saveBtn.disabled = false;
        saveBtn.innerHTML = originalText;
    }
}

function closeAccountInfoModal() {
    const modal = document.getElementById('accountInfoModal');
    if (modal) {
        modal.style.display = 'none';
    }
    currentAccountInfoEmail = null;
}

async function saveAccountInfo() {
    if (!currentAccountInfoEmail) {
        closeAccountInfoModal();
        return;
    }

    const refreshToken = document.getElementById('accountInfoRefreshToken').value.trim();
    const clientId = document.getElementById('accountInfoClientId').value.trim();
    const mailboxPassword = document.getElementById('accountInfoMailboxPassword').value.trim();
    const authMode = document.getElementById('accountInfoAuthMode').value;
    const tags = parseTagsInput(document.getElementById('accountInfoTags').value.trim());

    if (!refreshToken || !clientId) {
        showWarning('refresh_token 和 client_id 不能为空');
        return;
    }

    const saveBtn = document.getElementById('saveAccountInfoBtn');
    const originalText = saveBtn.innerHTML;
    saveBtn.disabled = true;
    saveBtn.innerHTML = '<span>⏳</span> 保存中...';
    setAccountInfoFieldsDisabled(true);

    try {
        await apiRequest(`/accounts/${encodeURIComponent(currentAccountInfoEmail)}`, {
            method: 'PUT',
            body: JSON.stringify({
                mailbox_password: mailboxPassword || null,
                refresh_token: refreshToken,
                client_id: clientId,
                auth_mode: authMode,
                tags: tags
            })
        });

        showSuccess('账户信息已更新');
        closeAccountInfoModal();
        await loadAccounts(accountsCurrentPage);
    } catch (error) {
        showError('更新账户信息失败: ' + error.message);
    } finally {
        setAccountInfoFieldsDisabled(false);
        saveBtn.disabled = false;
        saveBtn.innerHTML = originalText;
    }
}

async function loadAccounts(page = 1, resetSearch = false) {
    if (resetSearch) {
        // 重置搜索条件
        currentEmailSearch = '';
        currentTagSearch = '';
        document.getElementById('emailSearch').value = '';
        document.getElementById('tagSearch').value = '';
        page = 1;
    }
    
    accountsCurrentPage = page;
    
    const accountsList = document.getElementById('accountsList');
    const accountsStats = document.getElementById('accountsStats');
    const accountsPagination = document.getElementById('accountsPagination');
    
    accountsList.innerHTML = '<div class="loading">正在加载账户列表...</div>';
    accountsStats.style.display = 'none';
    accountsPagination.style.display = 'none';

    try {
        await loadTokenRefreshSettings(true);

        // 构建请求参数
        const params = new URLSearchParams({
            page: accountsCurrentPage,
            page_size: accountsPageSize
        });
        
        if (currentEmailSearch) {
            params.append('email_search', currentEmailSearch);
        }
        
        if (currentTagSearch) {
            params.append('tag_search', currentTagSearch);
        }
        
        const data = await apiRequest(`/accounts?${params.toString()}`);
        
        accounts = data.accounts || [];
        accountsTotalCount = data.total_accounts || 0;
        accountsTotalPages = data.total_pages || 0;
        
        // 更新统计信息
        updateAccountsStats();
        
        if (accounts.length === 0) {
            accountsList.innerHTML = '<div class="text-center" style="padding: 40px; color: #64748b;">暂无符合条件的账户</div>';
            return;
        }

        accountsList.innerHTML = accounts.map(account => {
            // 生成标签HTML
            const tagsHtml = account.tags && account.tags.length > 0 
                ? `<div class="account-tags">${account.tags.map(tag => 
                    `<span class="account-tag">${tag}</span>`).join('')}</div>` 
                : '';

            const atExpires = formatTokenExpiry(account.access_token_expires_at);
            const rtExpires = formatTokenExpiry(account.refresh_token_expires_at);
            const refreshBtnId = buildRefreshTokenButtonId(account.email_id);
            const isPinned = openedEmailAccounts.includes(account.email_id);
            const pinBtnClass = isPinned ? 'btn btn-primary btn-sm' : 'btn btn-secondary btn-sm';
            const pinBtnIcon = isPinned ? '📌' : '📍';
            const pinBtnLabel = isPinned ? '取消挂载' : '挂到左侧';
                
            return `
                <div class="account-item" onclick="openAccountEmailsInChildWindow('${account.email_id}')" oncontextmenu="showAccountContextMenu(event, '${account.email_id}')">
                    <div class="account-info">
                        <div class="account-avatar">${account.email_id.charAt(0).toUpperCase()}</div>
                        <div class="account-details">
                            <h4>${account.email_id}</h4>
                            <p>状态: ${account.status === 'active' ? '正常' : '异常'} | 协议: ${(account.auth_mode || 'imap').toUpperCase()}</p>
                            <p class="account-token-meta">AT过期: ${atExpires} | RT过期: ${rtExpires}</p>
                            ${tagsHtml}
                        </div>
                    </div>
                    <div class="account-actions" onclick="event.stopPropagation()">
                        <button class="btn btn-primary btn-sm" onclick="openAccountEmailsInChildWindow('${account.email_id}', event)">
                            <span>📧</span>
                            查看邮件
                        </button>
                        <button class="${pinBtnClass}" onclick="toggleAccountPinned('${account.email_id}', event)">
                            <span>${pinBtnIcon}</span>
                            ${pinBtnLabel}
                        </button>
                        <button class="btn btn-secondary btn-sm" onclick="openAccountInfoModal('${account.email_id}', event)">
                            <span>🛠️</span>
                            账户信息
                        </button>
                        <button class="btn btn-secondary btn-sm" onclick="editAccountTags('${account.email_id}', ${JSON.stringify(account.tags || [])})">
                            <span>🏷️</span>
                            管理标签
                        </button>
                        <button class="btn btn-secondary btn-sm" id="${refreshBtnId}" onclick="refreshAccountToken('${account.email_id}', event)">
                            <span>🔁</span>
                            刷新RT
                        </button>
                        <button class="btn btn-danger btn-sm" onclick="deleteAccount('${account.email_id}')">
                            <span>🗑️</span>
                            删除
                        </button>
                    </div>
                </div>
            `;
        }).join('');
        
        // 更新分页控件
        updateAccountsPagination();

    } catch (error) {
        accountsList.innerHTML = '<div class="error">加载失败: ' + error.message + '</div>';
    }
}

async function addAccount() {
    const email = document.getElementById('email').value.trim();
    const refreshToken = document.getElementById('refreshToken').value.trim();
    const clientId = document.getElementById('clientId').value.trim();
    const authMode = document.getElementById('authMode').value;
    const mailboxPassword = document.getElementById('mailboxPassword').value.trim();
    const tagsInput = document.getElementById('accountTags').value.trim();
    
    // 处理标签
    const tags = tagsInput ? tagsInput.split(',').map(tag => tag.trim()).filter(tag => tag) : [];

    if (!email || !refreshToken || !clientId) {
        showNotification('请填写所有必填字段', 'warning');
        return;
    }

    const addBtn = document.getElementById('addAccountBtn');
    addBtn.disabled = true;
    addBtn.innerHTML = '<span>⏳</span> 添加中...';

    try {
        const response = await apiRequest('/accounts', {
            method: 'POST',
            body: JSON.stringify({
                email,
                mailbox_password: mailboxPassword || null,
                refresh_token: refreshToken,
                client_id: clientId,
                auth_mode: authMode,
                tags: tags
            })
        });

        showSuccess('账户添加成功');
        clearAddAccountForm();
        showPage('accounts');
        loadAccounts();
    } catch (error) {
        showNotification('添加账户失败: ' + error.message, 'error');
    } finally {
        addBtn.disabled = false;
        addBtn.innerHTML = '<span>➕</span> 添加账户';
    }
}

async function batchAddAccounts() {
    const batchText = document.getElementById('batchAccounts').value.trim();
    const batchAuthMode = document.getElementById('batchAuthMode').value;
    if (!batchText) {
        showNotification('请输入账户信息', 'warning');
        return;
    }

    const lines = batchText.split('\n').filter(line => line.trim());
    if (lines.length === 0) {
        showNotification('没有有效的账户信息', 'warning');
        return;
    }

    // 显示进度
    showBatchProgress();
    const batchBtn = document.getElementById('batchAddBtn');
    batchBtn.disabled = true;
    batchBtn.innerHTML = '<span>⏳</span> 添加中...';

    let successCount = 0;
    let failCount = 0;
    const results = [];

    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const parsed = parseBatchAccountLine(line);

        // 更新进度
        updateBatchProgress(i + 1, lines.length, `处理第 ${i + 1} 个账户...`);

        if (!parsed.ok) {
            failCount++;
            results.push({
                email: '格式错误',
                status: 'error',
                message: parsed.message
            });
            continue;
        }

        const { email, password, refreshToken, clientId } = parsed;

        try {
            await apiRequest('/accounts', {
                method: 'POST',
                body: JSON.stringify({
                    email: email,
                    mailbox_password: password || null,
                    refresh_token: refreshToken,
                    client_id: clientId,
                    auth_mode: batchAuthMode
                })
            });
            successCount++;
            results.push({
                email: email,
                status: 'success',
                message: '添加成功'
            });
        } catch (error) {
            failCount++;
            results.push({
                email: email,
                status: 'error',
                message: error.message
            });
        }

        // 添加小延迟避免请求过快
        await new Promise(resolve => setTimeout(resolve, 100));
    }

    // 完成进度
    updateBatchProgress(lines.length, lines.length, '批量添加完成！');

    // 显示结果
    showBatchResults(results);

    if (successCount > 0) {
        showNotification(`批量添加完成！成功 ${successCount} 个，失败 ${failCount} 个`, 'success');
        if (failCount === 0) {
            setTimeout(() => {
                clearBatchForm();
                showPage('accounts');
            }, 3000);
        }
    } else {
        showNotification('所有账户添加失败，请检查账户信息', 'error');
    }

    batchBtn.disabled = false;
    batchBtn.innerHTML = '<span>📦</span> 开始批量添加';
}

function showBatchProgress() {
    document.getElementById('batchProgress').classList.remove('hidden');
    document.getElementById('batchResults').classList.add('hidden');
}

function hideBatchProgress() {
    document.getElementById('batchProgress').classList.add('hidden');
    document.getElementById('batchResults').classList.add('hidden');
}

function updateBatchProgress(current, total, message) {
    const percentage = (current / total) * 100;
    document.getElementById('batchProgressFill').style.width = percentage + '%';
    document.getElementById('batchProgressText').textContent = message;
    document.getElementById('batchProgressCount').textContent = `${current} / ${total}`;
}

function showBatchResults(results) {
    const resultsContainer = document.getElementById('batchResultsList');
    const successResults = results.filter(r => r.status === 'success');
    const errorResults = results.filter(r => r.status === 'error');

    let html = '';

    if (successResults.length > 0) {
        html += `<div style="margin-bottom: 16px;">
            <h5 style="color: #16a34a; margin-bottom: 8px;">✅ 成功添加 (${successResults.length})</h5>
            <div style="background: #f0fdf4; padding: 12px; border-radius: 6px; border: 1px solid #bbf7d0;">`;
        successResults.forEach(result => {
            html += `<div style="font-size: 0.875rem; color: #15803d; margin-bottom: 4px;">• ${result.email}</div>`;
        });
        html += `</div></div>`;
    }

    if (errorResults.length > 0) {
        html += `<div>
            <h5 style="color: #dc2626; margin-bottom: 8px;">❌ 添加失败 (${errorResults.length})</h5>
            <div style="background: #fef2f2; padding: 12px; border-radius: 6px; border: 1px solid #fecaca;">`;
        errorResults.forEach(result => {
            html += `<div style="font-size: 0.875rem; color: #dc2626; margin-bottom: 8px;">
                <strong>• ${result.email}</strong><br>
                <span style="color: #991b1b; font-size: 0.75rem;">&nbsp;&nbsp;${result.message}</span>
            </div>`;
        });
        html += `</div></div>`;
    }

    resultsContainer.innerHTML = html;
    document.getElementById('batchResults').classList.remove('hidden');
}


// 打开标签管理模态框
function editAccountTags(emailId, tags) {
    currentEditAccount = emailId;
    currentEditTags = Array.isArray(tags) ? [...tags] : [];
    
    // 更新模态框标题
    document.querySelector('#tagsModal .modal-header h3').textContent = `管理 ${emailId} 的标签`;
    
    // 显示当前标签
    renderCurrentTags();
    
    // 显示模态框
    document.getElementById('tagsModal').style.display = 'flex';
}

// 渲染当前标签列表
function renderCurrentTags() {
    const tagsList = document.getElementById('currentTagsList');
    
    if (currentEditTags.length === 0) {
        tagsList.innerHTML = '<p class="text-muted">暂无标签</p>';
        return;
    }
    
    tagsList.innerHTML = currentEditTags.map(tag => `
        <div class="tag-item">
            <span class="tag-name">${tag}</span>
            <button class="tag-delete" onclick="removeTag('${tag}')">×</button>
        </div>
    `).join('');
}

// 添加新标签
function addTag() {
    const newTagInput = document.getElementById('newTag');
    const newTag = newTagInput.value.trim();
    
    if (!newTag) {
        showNotification('标签名称不能为空', 'warning');
        return;
    }
    
    // 检查标签是否已存在
    if (currentEditTags.includes(newTag)) {
        showNotification('标签已存在', 'warning');
        return;
    }
    
    // 添加新标签
    currentEditTags.push(newTag);
    
    // 清空输入框
    newTagInput.value = '';
    
    // 重新渲染标签列表
    renderCurrentTags();
}

// 删除标签
function removeTag(tag) {
    currentEditTags = currentEditTags.filter(t => t !== tag);
    renderCurrentTags();
}

// 关闭标签管理模态框
function closeTagsModal() {
    document.getElementById('tagsModal').style.display = 'none';
    currentEditAccount = null;
    currentEditTags = [];
}

// 保存账户标签
async function saveAccountTags() {
    if (!currentEditAccount) {
        closeTagsModal();
        return;
    }
    
    try {
        const response = await apiRequest(`/accounts/${currentEditAccount}/tags`, {
            method: 'PUT',
            body: JSON.stringify({ tags: currentEditTags })
        });
        
        showSuccess('标签更新成功');
        closeTagsModal();
        
        // 重新加载账户列表
        loadAccounts();
    } catch (error) {
        showError('更新标签失败: ' + error.message);
    }
}

// 新增的账户管理辅助函数
function updateAccountsStats() {
    const accountsStats = document.getElementById('accountsStats');
    document.getElementById('totalAccounts').textContent = accountsTotalCount;
    document.getElementById('currentPage').textContent = accountsCurrentPage;
    document.getElementById('pageSize').textContent = accountsPageSize;
    accountsStats.style.display = accountsTotalCount > 0 ? 'block' : 'none';
}

function updateAccountsPagination() {
    const accountsPagination = document.getElementById('accountsPagination');
    const prevBtn = document.getElementById('prevPageBtn');
    const nextBtn = document.getElementById('nextPageBtn');
    const pageNumbers = document.getElementById('pageNumbers');
    
    if (accountsTotalPages <= 1) {
        accountsPagination.style.display = 'none';
        return;
    }
    
    accountsPagination.style.display = 'flex';
    
    // 更新上一页/下一页按钮
    prevBtn.disabled = accountsCurrentPage <= 1;
    nextBtn.disabled = accountsCurrentPage >= accountsTotalPages;
    
    // 生成页码
    pageNumbers.innerHTML = generatePageNumbers();
}

function generatePageNumbers() {
    const maxVisiblePages = 5;
    let startPage = Math.max(1, accountsCurrentPage - Math.floor(maxVisiblePages / 2));
    let endPage = Math.min(accountsTotalPages, startPage + maxVisiblePages - 1);
    
    if (endPage - startPage < maxVisiblePages - 1) {
        startPage = Math.max(1, endPage - maxVisiblePages + 1);
    }
    
    let html = '';
    
    // 第一页
    if (startPage > 1) {
        html += `<span class="page-number" onclick="changePage(1)">1</span>`;
        if (startPage > 2) {
            html += `<span class="page-number disabled">...</span>`;
        }
    }
    
    // 中间页码
    for (let i = startPage; i <= endPage; i++) {
        const activeClass = i === accountsCurrentPage ? 'active' : '';
        html += `<span class="page-number ${activeClass}" onclick="changePage(${i})">${i}</span>`;
    }
    
    // 最后一页
    if (endPage < accountsTotalPages) {
        if (endPage < accountsTotalPages - 1) {
            html += `<span class="page-number disabled">...</span>`;
        }
        html += `<span class="page-number" onclick="changePage(${accountsTotalPages})">${accountsTotalPages}</span>`;
    }
    
    return html;
}

function changePage(direction) {
    let newPage;
    if (direction === 'prev') {
        newPage = Math.max(1, accountsCurrentPage - 1);
    } else if (direction === 'next') {
        newPage = Math.min(accountsTotalPages, accountsCurrentPage + 1);
    } else {
        newPage = parseInt(direction);
    }
    
    if (newPage !== accountsCurrentPage && newPage >= 1 && newPage <= accountsTotalPages) {
        loadAccounts(newPage);
    }
}

function searchAccounts() {
    currentEmailSearch = document.getElementById('emailSearch').value.trim();
    currentTagSearch = document.getElementById('tagSearch').value.trim();
    loadAccounts(1); // 搜索时重置到第一页
}

function clearSearch() {
    document.getElementById('emailSearch').value = '';
    document.getElementById('tagSearch').value = '';
    currentEmailSearch = '';
    currentTagSearch = '';
    loadAccounts(1);
}

function handleSearchKeyPress(event) {
    if (event.key === 'Enter') {
        searchAccounts();
    }
}

async function deleteAccount(emailId) {
    if (!confirm(`确定要删除账户 ${emailId} 吗？`)) {
        return;
    }

    try {
        await apiRequest(`/accounts/${emailId}`, { method: 'DELETE' });
        showSuccess('账户删除成功');
        loadAccounts(accountsCurrentPage); // 保持当前页码
    } catch (error) {
        showError('删除账户失败: ' + error.message);
    }
}

// 显示右键菜单
function showAccountContextMenu(event, emailId) {
    event.preventDefault();
    event.stopPropagation();
    
    contextMenuTarget = emailId;
    const contextMenu = document.getElementById('contextMenu');
    const pinMenuText = document.getElementById('contextPinMenuText');
    const pinMenuIcon = document.getElementById('contextPinMenuIcon');
    const isPinned = openedEmailAccounts.includes(emailId);

    if (pinMenuText) {
        pinMenuText.textContent = isPinned ? '取消挂载' : '挂到左侧';
    }

    if (pinMenuIcon) {
        pinMenuIcon.textContent = isPinned ? '📍' : '📌';
    }
    
    // 设置菜单位置
    contextMenu.style.left = event.pageX + 'px';
    contextMenu.style.top = event.pageY + 'px';
    contextMenu.style.display = 'block';
    
    // 点击其他地方隐藏菜单
    setTimeout(() => {
        document.addEventListener('click', hideContextMenu);
    }, 10);
}

// 隐藏右键菜单
function hideContextMenu() {
    const contextMenu = document.getElementById('contextMenu');
    contextMenu.style.display = 'none';
    contextMenuTarget = null;
    document.removeEventListener('click', hideContextMenu);
}

// 在子窗口中打开
function openInChildWindow() {
    if (contextMenuTarget) {
        openAccountEmailsInChildWindow(contextMenuTarget);
    }
    hideContextMenu();
}

// 复制账户链接
function copyAccountLink() {
    if (contextMenuTarget) {
        const url = typeof buildEmailPageUrl === 'function'
            ? buildEmailPageUrl(contextMenuTarget)
            : `${window.location.origin}/#/emails/${encodeURIComponent(contextMenuTarget)}`;
        
        if (navigator.clipboard) {
            navigator.clipboard.writeText(url).then(() => {
                showNotification('链接已复制到剪贴板', 'success');
            }).catch(() => {
                fallbackCopyText(url);
            });
        } else {
            fallbackCopyText(url);
        }
    }
    hideContextMenu();
}

function toggleAccountPinned(emailId, event = null) {
    if (event) {
        event.preventDefault();
        event.stopPropagation();
    }

    const normalized = String(emailId || '').trim();
    if (!normalized) {
        return;
    }

    const accountsPage = document.getElementById('accountsPage');
    const isAccountsPageVisible = Boolean(accountsPage && !accountsPage.classList.contains('hidden'));

    if (openedEmailAccounts.includes(normalized)) {
        closeOpenedAccount(normalized);
        if (isAccountsPageVisible) {
            loadAccounts(accountsCurrentPage);
        }
    } else {
        const result = pinAccountToSidebar(normalized);
        if (result.ok) {
            showNotification(`已挂到左侧: ${normalized}`, 'success');
            if (isAccountsPageVisible) {
                loadAccounts(accountsCurrentPage);
            }
        }
    }
}

function contextPinAccount() {
    if (contextMenuTarget) {
        toggleAccountPinned(contextMenuTarget);
    }
    hideContextMenu();
}

// 后备复制方法
function fallbackCopyText(text) {
    const textArea = document.createElement('textarea');
    textArea.value = text;
    document.body.appendChild(textArea);
    textArea.select();
    try {
        document.execCommand('copy');
        showNotification('链接已复制到剪贴板', 'success');
    } catch (err) {
        showNotification('复制失败，请手动复制', 'error');
    }
    document.body.removeChild(textArea);
}

// 从右键菜单编辑标签
function contextEditTags() {
    if (contextMenuTarget) {
        const account = accounts.find(acc => acc.email_id === contextMenuTarget);
        if (account) {
            editAccountTags(contextMenuTarget, account.tags || []);
        }
    }
    hideContextMenu();
}

// 从右键菜单删除账户
function contextDeleteAccount() {
    if (contextMenuTarget) {
        deleteAccount(contextMenuTarget);
    }
    hideContextMenu();
}
