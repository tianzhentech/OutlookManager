import dayjs from 'dayjs';

export function formatDateTime(value, fallback = '未获取') {
  if (!value) return fallback;
  const parsed = dayjs(value);
  return parsed.isValid() ? parsed.format('YYYY-MM-DD HH:mm:ss') : '时间无效';
}

export function formatEmailDate(value) {
  if (!value) return '未知时间';
  const parsed = dayjs(value);
  if (!parsed.isValid()) return '时间无效';

  const now = dayjs();
  if (parsed.isSame(now, 'day')) return parsed.format('HH:mm');
  if (parsed.isSame(now.subtract(1, 'day'), 'day')) return `昨天 ${parsed.format('HH:mm')}`;
  if (now.diff(parsed, 'day') < 7) return `${now.diff(parsed, 'day')}天前`;
  return parsed.format(parsed.isSame(now, 'year') ? 'MM月DD日' : 'YYYY年MM月DD日');
}

export function normalizeTags(tags) {
  if (Array.isArray(tags)) {
    return tags.map((tag) => String(tag).trim()).filter(Boolean);
  }
  return String(tags || '')
    .split(',')
    .map((tag) => tag.trim())
    .filter(Boolean);
}

export function isGuid(value) {
  return /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(
    value,
  );
}

export function looksLikeRefreshToken(value) {
  if (!value) return false;
  return value.startsWith('M.') || value.length > 40;
}

export function parseBatchAccountLine(line) {
  const parts = line.split('----').map((part) => part.trim());
  if (parts.length !== 4 || parts.some((part) => !part)) {
    return {
      ok: false,
      message: '格式错误：应为 邮箱----密码----刷新令牌----客户端ID 或 邮箱----密码----客户端ID----刷新令牌',
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
  } else if (!looksLikeRefreshToken(third) && looksLikeRefreshToken(fourth)) {
    clientId = third;
    refreshToken = fourth;
    format = 'client-refresh';
  }

  return {
    ok: true,
    email,
    password,
    refreshToken,
    clientId,
    format,
  };
}

export function downloadText(filename, content, type = 'text/plain;charset=utf-8') {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

export function emailCsv(emails) {
  const headers = ['主题', '发件人', '日期', '文件夹', '是否已读', '是否有附件'];
  const rows = emails.map((email) => [
    email.subject || '',
    email.from_email || '',
    email.date || '',
    email.folder || '',
    email.is_read ? '已读' : '未读',
    email.has_attachments ? '有附件' : '无附件',
  ]);

  return [headers, ...rows]
    .map((row) => row.map((cell) => `"${String(cell).replace(/"/g, '""')}"`).join(','))
    .join('\n');
}
