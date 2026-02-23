// URL routing
function handleUrlRouting() {
    const hash = window.location.hash;

    if (!hash.startsWith('#/emails/')) {
        return;
    }

    const emailId = decodeURIComponent(hash.replace('#/emails/', ''));
    if (!emailId) {
        return;
    }

    currentAccount = emailId;
    document.getElementById('currentAccountEmail').textContent = emailId;
    document.getElementById('emailsNav').style.display = 'block';
    showPage('emails');
}

// Event bindings
const emailModal = document.getElementById('emailModal');
if (emailModal) {
    emailModal.addEventListener('click', function (event) {
        if (event.target === this) {
            closeEmailModal();
        }
    });
}

const changePasswordModal = document.getElementById('changePasswordModal');
if (changePasswordModal) {
    changePasswordModal.addEventListener('click', function (event) {
        if (event.target === this) {
            closeChangePasswordModal();
        }
    });
}

document.addEventListener('keydown', function (event) {
    if ((event.ctrlKey || event.metaKey) && event.key === 'r' && currentAccount) {
        event.preventDefault();
        refreshEmails();
    }

    if (event.key === 'Escape') {
        closeEmailModal();
        if (typeof closeChangePasswordModal === 'function') {
            closeChangePasswordModal();
        }
    }

    const emailSearch = document.getElementById('emailSearch');
    if ((event.ctrlKey || event.metaKey) && event.key === 'f' && emailSearch) {
        event.preventDefault();
        emailSearch.focus();
    }
});

document.addEventListener('visibilitychange', function () {
    if (document.hidden || !currentAccount) {
        return;
    }

    const lastUpdateElement = document.getElementById('lastUpdateTime');
    if (!lastUpdateElement || lastUpdateElement.textContent === '-') {
        return;
    }

    const lastUpdateTime = new Date(lastUpdateElement.textContent);
    const now = new Date();
    const diffMinutes = (now - lastUpdateTime) / (1000 * 60);

    if (diffMinutes > 5) {
        showNotification('检测到数据可能过期，正在刷新...', 'info', '', 2000);
        setTimeout(() => refreshEmails(), 1000);
    }
});

window.addEventListener('popstate', function () {
    handleUrlRouting();
});

window.addEventListener('load', function () {
    handleUrlRouting();

    if (!window.location.hash || window.location.hash === '#') {
        showPage('accounts');
    }

    setTimeout(() => {
        showNotification('欢迎使用邮件管理系统！', 'info', '欢迎', 3000);
    }, 500);
});
