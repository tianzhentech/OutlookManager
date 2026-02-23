// 页面管理
function showPage(pageName, targetElement = null) {
    const mainBody = document.querySelector('.main-body');
    if (mainBody) {
        mainBody.classList.toggle('accounts-page-active', pageName === 'accounts');
    }

    // 隐藏所有页面
    document.querySelectorAll('.page').forEach(page => page.classList.add('hidden'));

    // 显示指定页面
    document.getElementById(pageName + 'Page').classList.remove('hidden');

    // 更新导航状态
    document.querySelectorAll('.nav-item').forEach(item => item.classList.remove('active'));

    // 如果有目标元素，激活它；否则根据页面名称查找对应的导航项
    if (targetElement) {
        targetElement.classList.add('active');
    } else {
        // 根据页面名称查找对应的导航按钮
        const navButtons = document.querySelectorAll('.nav-item');
        navButtons.forEach(button => {
            if (button.onclick && button.onclick.toString().includes(`'${pageName}'`)) {
                button.classList.add('active');
            }
        });
    }

    // 更新页面标题
    const titles = {
        'accounts': '邮箱账户管理',
        'addAccount': '添加邮箱账户',
        'batchAdd': '批量添加账户',
        'apiDocs': 'API接口文档',
        'emails': '邮件列表'
    };
    document.getElementById('pageTitle').textContent = titles[pageName] || '';

    // 页面特定逻辑
    if (pageName === 'accounts') {
        loadAccounts();
    } else if (pageName === 'addAccount') {
        clearAddAccountForm();
    } else if (pageName === 'batchAdd') {
        clearBatchForm();
        hideBatchProgress();
    } else if (pageName === 'apiDocs') {
        initApiDocs();
    } else if (pageName === 'emails') {
        loadEmails();
    }
}

// 工具函数
function formatEmailDate(dateString) {
    try {
        if (!dateString) return '未知时间';

        let date = new Date(dateString);

        if (isNaN(date.getTime())) {
            if (dateString.includes('T') && !dateString.includes('Z') && !dateString.includes('+')) {
                date = new Date(dateString + 'Z');
            }
            if (isNaN(date.getTime())) {
                return '日期格式错误';
            }
        }

        const now = new Date();
        const diffMs = now - date;
        const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));

        if (diffDays === 0) {
            return date.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' });
        } else if (diffDays === 1) {
            return '昨天 ' + date.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' });
        } else if (diffDays < 7) {
            return `${diffDays}天前`;
        } else if (diffDays < 365) {
            return date.toLocaleDateString('zh-CN', { month: 'short', day: 'numeric' });
        } else {
            return date.toLocaleDateString('zh-CN', { year: 'numeric', month: 'short', day: 'numeric' });
        }
    } catch (error) {
        console.error('Date formatting error:', error);
        return '时间解析失败';
    }
}

// 新的通知系统
function showNotification(message, type = 'info', title = '', duration = 5000) {
    const container = document.getElementById('notificationContainer');
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;

    const icons = {
        success: '✅',
        error: '❌',
        warning: '⚠️',
        info: 'ℹ️'
    };

    const titles = {
        success: title || '成功',
        error: title || '错误',
        warning: title || '警告',
        info: title || '提示'
    };

    notification.innerHTML = `
        <div class="notification-icon">${icons[type]}</div>
        <div class="notification-content">
            <div class="notification-title">${titles[type]}</div>
            <div class="notification-message">${message}</div>
        </div>
        <button class="notification-close" onclick="closeNotification(this)">×</button>
    `;

    container.appendChild(notification);

    // 自动关闭
    if (duration > 0) {
        setTimeout(() => {
            closeNotification(notification.querySelector('.notification-close'));
        }, duration);
    }
}

function closeNotification(closeBtn) {
    const notification = closeBtn.closest('.notification');
    notification.classList.add('slide-out');
    setTimeout(() => notification.remove(), 300);
}

// 兼容旧的消息提示函数
function showError(msg) {
    showNotification(msg, 'error');
}

function showSuccess(msg) {
    showNotification(msg, 'success');
}

function showWarning(msg) {
    showNotification(msg, 'warning');
}

function showInfo(msg) {
    showNotification(msg, 'info');
}

// API请求
async function apiRequest(url, options = {}) {
    try {
        const response = await fetch(API_BASE + url, {
            credentials: 'same-origin',
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            },
            ...options
        });

        if (response.status === 401) {
            window.location.href = '/admin';
            throw new Error('管理员会话已失效，请重新登录');
        }

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        return await response.json();
    } catch (error) {
        console.error('API请求失败:', error);
        throw error;
    }
}
