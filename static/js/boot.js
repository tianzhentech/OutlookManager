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

    viewAccountEmails(emailId);
}

function initEmbedMode() {
    if (!isEmbedMode) {
        return;
    }

    document.body.classList.add('embed-mode');
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

const emailChildWindowModal = document.getElementById('emailChildWindowModal');
if (emailChildWindowModal) {
    emailChildWindowModal.addEventListener('click', function (event) {
        if (event.target === this || event.target.dataset.closeChildWindow === 'true') {
            if (typeof closeEmailChildWindow === 'function') {
                closeEmailChildWindow();
            }
        }
    });
}

const accountInfoModal = document.getElementById('accountInfoModal');
if (accountInfoModal) {
    accountInfoModal.addEventListener('click', function (event) {
        if (event.target === this && typeof closeAccountInfoModal === 'function') {
            closeAccountInfoModal();
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
    if ((event.ctrlKey || event.metaKey) && event.key === 'r' && currentAccount && isEmailsPageVisible()) {
        event.preventDefault();
        refreshEmails();
    }

    if (event.key === 'Escape') {
        closeEmailModal();
        if (typeof closeEmailChildWindow === 'function') {
            closeEmailChildWindow();
        }
        if (typeof closeAccountInfoModal === 'function') {
            closeAccountInfoModal();
        }
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
    if (document.hidden || !currentAccount || !isEmailsPageVisible()) {
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

window.addEventListener('message', function (event) {
    if (event.origin !== window.location.origin) {
        return;
    }

    const data = event.data;
    if (!data || typeof data !== 'object') {
        return;
    }

    if (data.type === 'outlook-email-child-window-close' && typeof closeEmailChildWindow === 'function') {
        closeEmailChildWindow();
    }
});

window.addEventListener('load', function () {
    initEmbedMode();

    if (typeof setEmailsNavVisibility === 'function') {
        setEmailsNavVisibility();
    }

    if (typeof renderOpenedAccounts === 'function') {
        renderOpenedAccounts();
    }

    handleUrlRouting();

    if (isEmbedMode) {
        if (!window.location.hash.startsWith('#/emails/')) {
            showPage('emails');
            if (typeof renderNoAccountState === 'function') {
                renderNoAccountState('未指定邮箱账户，请从主页面选择账户后打开子窗口');
            }
        }
        return;
    }

    if (!window.location.hash || window.location.hash === '#') {
        showPage('accounts');
    }

    setTimeout(() => {
        showNotification('欢迎使用邮件管理系统！', 'info', '欢迎', 3000);
    }, 500);
});
