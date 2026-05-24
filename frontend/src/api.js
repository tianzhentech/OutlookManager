export async function apiRequest(url, options = {}) {
  const { redirectOnUnauthorized = true, ...fetchOptions } = options;
  const headers = {
    Accept: 'application/json',
    ...fetchOptions.headers,
  };

  if (fetchOptions.body && !(fetchOptions.body instanceof FormData) && !headers['Content-Type']) {
    headers['Content-Type'] = 'application/json';
  }

  const response = await fetch(url, {
    credentials: 'same-origin',
    ...fetchOptions,
    headers,
  });

  let payload = null;
  const contentType = response.headers.get('content-type') || '';
  if (contentType.includes('application/json')) {
    try {
      payload = await response.json();
    } catch (_error) {
      payload = null;
    }
  } else {
    const text = await response.text();
    payload = text ? { detail: text } : null;
  }

  if (response.status === 401 && redirectOnUnauthorized) {
    window.location.href = '/admin';
    throw new Error('管理员会话已失效，请重新登录');
  }

  if (!response.ok) {
    const detail = payload?.detail || payload?.message || response.statusText;
    throw new Error(`HTTP ${response.status}: ${detail}`);
  }

  return payload;
}

export function buildQuery(params) {
  const searchParams = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== '') {
      searchParams.set(key, value);
    }
  });
  return searchParams.toString();
}
