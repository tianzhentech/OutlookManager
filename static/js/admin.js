function openChangePasswordModal() {
    const modal = document.getElementById('changePasswordModal');
    if (!modal) {
        return;
    }

    resetChangePasswordFormState();
    modal.classList.remove('hidden');

    const currentPasswordInput = document.getElementById('currentAdminPassword');
    if (currentPasswordInput) {
        currentPasswordInput.focus();
    }
}

function closeChangePasswordModal() {
    const modal = document.getElementById('changePasswordModal');
    if (!modal) {
        return;
    }

    modal.classList.add('hidden');
    resetChangePasswordFormState();
}

function resetChangePasswordFormState() {
    const form = document.getElementById('changePasswordForm');
    if (form) {
        form.reset();
    }

    const submitBtn = document.getElementById('changePasswordSubmitBtn');
    if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.innerHTML = '<span>🔐</span> 保存新密码';
    }
}

async function submitAdminPasswordChange(event) {
    event.preventDefault();

    const currentPassword = document.getElementById('currentAdminPassword').value.trim();
    const newPassword = document.getElementById('newAdminPassword').value.trim();
    const confirmPassword = document.getElementById('confirmAdminPassword').value.trim();

    if (!currentPassword || !newPassword || !confirmPassword) {
        showWarning('请填写完整的密码信息');
        return;
    }

    if (newPassword.length < 8) {
        showWarning('新密码至少 8 位');
        return;
    }

    if (newPassword !== confirmPassword) {
        showWarning('两次输入的新密码不一致');
        return;
    }

    const submitBtn = document.getElementById('changePasswordSubmitBtn');
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<span>⏳</span> 保存中...';

    try {
        const response = await fetch('/admin/auth/change-password', {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                current_password: currentPassword,
                new_password: newPassword
            })
        });

        if (response.status === 401) {
            window.location.href = '/admin';
            return;
        }

        let data = {};
        try {
            data = await response.json();
        } catch (_error) {
            data = {};
        }

        if (!response.ok) {
            throw new Error(data.detail || `HTTP ${response.status}: ${response.statusText}`);
        }

        showSuccess(data.message || '管理员密码修改成功');
        closeChangePasswordModal();
    } catch (error) {
        showError('修改密码失败: ' + error.message);
    } finally {
        submitBtn.disabled = false;
        submitBtn.innerHTML = '<span>🔐</span> 保存新密码';
    }
}
