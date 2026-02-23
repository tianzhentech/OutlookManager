const OPENAPI_METHODS = ["get", "post", "put", "delete", "patch", "options", "head"];
const METHOD_ORDER = { get: 1, post: 2, put: 3, patch: 4, delete: 5, options: 6, head: 7 };

let openApiSpecCache = null;
let openApiOperations = {};

// API文档相关函数
async function initApiDocs() {
    const baseUrl = window.location.origin;
    const baseUrlElement = document.getElementById('baseUrlExample');
    if (baseUrlElement) {
        baseUrlElement.textContent = baseUrl;
    }

    await loadOpenApiDocs(false);
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
    const cleanEmail = emailAddress.trim();

    if (!cleanEmail) {
        showNotification('邮箱地址为空', 'error');
        return;
    }

    navigator.clipboard.writeText(cleanEmail).then(() => {
        showNotification(`邮箱地址已复制: ${cleanEmail}`, 'success');

        const emailElement = document.getElementById('currentAccountEmail');
        if (emailElement) {
            emailElement.classList.add('copy-success');
            setTimeout(() => {
                emailElement.classList.remove('copy-success');
            }, 300);
        }
    }).catch((error) => {
        console.error('复制失败:', error);
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

async function downloadApiDocs() {
    try {
        const spec = await fetchOpenApiSpec(false);
        const apiDocs = generateApiDocsMarkdown(spec);
        const blob = new Blob([apiDocs], { type: 'text/markdown;charset=utf-8;' });
        const link = document.createElement('a');
        const url = URL.createObjectURL(blob);
        link.setAttribute('href', url);
        link.setAttribute('download', 'outlook-email-api-docs.md');
        link.style.visibility = 'hidden';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        showNotification('API文档已下载（自动生成）', 'success');
    } catch (error) {
        showNotification(`下载文档失败: ${error.message}`, 'error');
    }
}

async function fetchOpenApiSpec(forceRefresh = false) {
    if (!forceRefresh && openApiSpecCache) {
        return openApiSpecCache;
    }

    const response = await fetch(`${API_BASE}/openapi.json`, {
        credentials: 'same-origin',
        headers: {
            'Accept': 'application/json'
        }
    });

    if (response.status === 401) {
        window.location.href = '/admin';
        throw new Error('管理员会话已失效，请重新登录');
    }

    if (!response.ok) {
        throw new Error(`获取 /openapi.json 失败: HTTP ${response.status}`);
    }

    openApiSpecCache = await response.json();
    return openApiSpecCache;
}

async function loadOpenApiDocs(forceRefresh = false) {
    const container = document.getElementById('openApiEndpoints');
    if (!container) {
        return;
    }

    container.innerHTML = `
        <div class="loading">
            <div class="loading-spinner"></div>
            正在加载OpenAPI文档...
        </div>
    `;

    try {
        const spec = await fetchOpenApiSpec(forceRefresh);
        renderOpenApiEndpoints(spec);
    } catch (error) {
        container.innerHTML = `<div class="error">加载OpenAPI文档失败：${escapeHtml(error.message)}</div>`;
    }
}

function escapeHtml(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function resolveRef(spec, nodeOrRef) {
    if (!nodeOrRef) {
        return null;
    }

    if (typeof nodeOrRef === 'string') {
        if (!nodeOrRef.startsWith('#/')) {
            return null;
        }
        const segments = nodeOrRef.slice(2).split('/');
        let current = spec;
        for (const segment of segments) {
            const key = segment.replace(/~1/g, '/').replace(/~0/g, '~');
            current = current?.[key];
            if (current === undefined) {
                return null;
            }
        }
        return current ?? null;
    }

    if (nodeOrRef.$ref) {
        return resolveRef(spec, nodeOrRef.$ref) || nodeOrRef;
    }

    return nodeOrRef;
}

function getSchemaType(schema, spec) {
    const resolved = resolveRef(spec, schema);
    if (!resolved) return 'object';
    if (resolved.type) return resolved.type;
    if (resolved.enum) return 'enum';
    if (resolved.oneOf) return 'oneOf';
    if (resolved.anyOf) return 'anyOf';
    if (resolved.allOf) return 'allOf';
    return 'object';
}

function buildExampleFromSchema(schema, spec, depth = 0) {
    const resolved = resolveRef(spec, schema);
    if (!resolved || depth > 4) {
        return null;
    }

    if (resolved.example !== undefined) {
        return resolved.example;
    }

    if (Array.isArray(resolved.enum) && resolved.enum.length > 0) {
        return resolved.enum[0];
    }

    if (resolved.oneOf?.length) {
        return buildExampleFromSchema(resolved.oneOf[0], spec, depth + 1);
    }
    if (resolved.anyOf?.length) {
        return buildExampleFromSchema(resolved.anyOf[0], spec, depth + 1);
    }
    if (resolved.allOf?.length) {
        return buildExampleFromSchema(resolved.allOf[0], spec, depth + 1);
    }

    const schemaType = getSchemaType(resolved, spec);
    if (schemaType === 'string') {
        if (resolved.format === 'date-time') return new Date().toISOString();
        if (resolved.format === 'email') return 'example@outlook.com';
        return 'string';
    }
    if (schemaType === 'integer') return 0;
    if (schemaType === 'number') return 0;
    if (schemaType === 'boolean') return true;
    if (schemaType === 'array') {
        const itemExample = buildExampleFromSchema(resolved.items, spec, depth + 1);
        return itemExample === null ? [] : [itemExample];
    }
    if (schemaType === 'object') {
        const obj = {};
        const properties = resolved.properties || {};
        for (const [key, value] of Object.entries(properties)) {
            obj[key] = buildExampleFromSchema(value, spec, depth + 1);
        }
        return obj;
    }

    return null;
}

function getExampleFromContent(content, spec) {
    if (!content || typeof content !== 'object') {
        return null;
    }

    const preferredType = content['application/json']
        ? 'application/json'
        : Object.keys(content)[0];

    if (!preferredType) {
        return null;
    }

    const mediaType = resolveRef(spec, content[preferredType]);
    if (!mediaType) {
        return null;
    }

    if (mediaType.example !== undefined) {
        return { contentType: preferredType, value: mediaType.example };
    }

    if (mediaType.examples) {
        const firstKey = Object.keys(mediaType.examples)[0];
        if (firstKey) {
            const exampleObj = resolveRef(spec, mediaType.examples[firstKey]);
            if (exampleObj && exampleObj.value !== undefined) {
                return { contentType: preferredType, value: exampleObj.value };
            }
        }
    }

    const schemaExample = buildExampleFromSchema(mediaType.schema, spec);
    if (schemaExample !== null) {
        return { contentType: preferredType, value: schemaExample };
    }

    return { contentType: preferredType, value: null };
}

function mergeParameters(pathItem, operation, spec) {
    const allParams = [];
    const seen = new Set();
    const source = [
        ...(Array.isArray(pathItem?.parameters) ? pathItem.parameters : []),
        ...(Array.isArray(operation?.parameters) ? operation.parameters : [])
    ];

    for (const rawParam of source) {
        const param = resolveRef(spec, rawParam);
        if (!param || !param.name || !param.in) {
            continue;
        }
        const key = `${param.in}:${param.name}`;
        if (seen.has(key)) {
            continue;
        }
        seen.add(key);
        allParams.push(param);
    }

    return allParams;
}

function buildOperation(path, method, operation, pathItem, spec, index) {
    const params = mergeParameters(pathItem, operation, spec).map(param => {
        const schema = resolveRef(spec, param.schema);
        return {
            name: String(param.name),
            location: String(param.in),
            required: Boolean(param.required),
            description: String(param.description || ''),
            type: getSchemaType(schema, spec),
            schema
        };
    });

    const requestBody = resolveRef(spec, operation.requestBody);
    const requestExample = getExampleFromContent(requestBody?.content, spec);
    const responseEntry = pickPrimaryResponse(operation.responses, spec);
    const responseExample = getExampleFromContent(responseEntry?.response?.content, spec);

    return {
        key: `openapi-op-${index}`,
        method,
        path,
        summary: String(operation.summary || operation.description || '无说明'),
        description: String(operation.description || ''),
        operationId: String(operation.operationId || `${method}_${path}`),
        parameters: params,
        requestBody: requestBody
            ? {
                required: Boolean(requestBody.required),
                contentType: requestExample?.contentType || 'application/json',
                exampleValue: requestExample?.value
            }
            : null,
        responses: operation.responses || {},
        responseCode: responseEntry?.statusCode || '',
        responseDescription: String(responseEntry?.response?.description || ''),
        responseContentType: responseExample?.contentType || '',
        responseExampleValue: responseExample?.value
    };
}

function collectOperations(spec) {
    const operations = [];
    const paths = spec?.paths || {};
    let index = 0;

    for (const path of Object.keys(paths).sort()) {
        const pathItem = paths[path] || {};
        for (const method of OPENAPI_METHODS) {
            const operation = pathItem[method];
            if (!operation) continue;
            index += 1;
            operations.push(buildOperation(path, method, operation, pathItem, spec, index));
        }
    }

    operations.sort((a, b) => {
        if (a.path === b.path) {
            return (METHOD_ORDER[a.method] || 99) - (METHOD_ORDER[b.method] || 99);
        }
        return a.path.localeCompare(b.path);
    });

    return operations;
}

function pickPrimaryResponse(responses, spec) {
    const resolved = resolveRef(spec, responses) || {};
    const priority = ['200', '201', '202', '204', 'default'];
    for (const code of priority) {
        if (resolved[code]) {
            return { statusCode: code, response: resolveRef(spec, resolved[code]) };
        }
    }
    const firstCode = Object.keys(resolved)[0];
    if (!firstCode) {
        return null;
    }
    return { statusCode: firstCode, response: resolveRef(spec, resolved[firstCode]) };
}

function toPrettyJson(value) {
    if (value === undefined || value === null) {
        return '';
    }
    if (typeof value === 'string') {
        return value;
    }
    try {
        return JSON.stringify(value, null, 2);
    } catch (_) {
        return String(value);
    }
}

function renderParametersSection(operation) {
    if (!operation.parameters.length) {
        return '';
    }

    const rows = operation.parameters.map(param => {
        const typeText = param.type || 'object';
        const reqText = param.required ? '必填' : '可选';
        const descText = [param.location, reqText, param.description].filter(Boolean).join(' | ');
        return `
            <div class="api-param">
                <span class="api-param-name">${escapeHtml(param.name)}</span>
                <span class="api-param-type">${escapeHtml(typeText)}</span>
                <span class="api-param-desc">${escapeHtml(descText)}</span>
            </div>
        `;
    }).join('');

    return `
        <div class="api-section">
            <h4>参数</h4>
            <div class="api-params">${rows}</div>
        </div>
    `;
}

function renderRequestBodySection(operation) {
    if (!operation.requestBody) {
        return '';
    }

    const requiredText = operation.requestBody.required ? '必填' : '可选';
    const exampleText = toPrettyJson(operation.requestBody.exampleValue) || '{}';
    return `
        <div class="api-section">
            <h4>请求体 (${escapeHtml(requiredText)} | ${escapeHtml(operation.requestBody.contentType)})</h4>
            <div class="api-example">${escapeHtml(exampleText)}</div>
        </div>
    `;
}

function renderResponseSection(operation) {
    const responseTitleParts = [];
    if (operation.responseCode) {
        responseTitleParts.push(`HTTP ${operation.responseCode}`);
    }
    if (operation.responseContentType) {
        responseTitleParts.push(operation.responseContentType);
    }
    const responseTitle = responseTitleParts.length ? responseTitleParts.join(' | ') : '响应';

    const responseDesc = operation.responseDescription
        ? `<p class="api-description" style="margin-bottom: 8px;">${escapeHtml(operation.responseDescription)}</p>`
        : '';

    const exampleValue = toPrettyJson(operation.responseExampleValue);
    const exampleHtml = exampleValue
        ? `<div class="api-example">${escapeHtml(exampleValue)}</div>`
        : '<div class="api-example">(无返回示例)</div>';

    return `
        <div class="api-section">
            <h4>响应示例 (${escapeHtml(responseTitle)})</h4>
            ${responseDesc}
            ${exampleHtml}
        </div>
    `;
}

function renderOpenApiEndpoints(spec) {
    const container = document.getElementById('openApiEndpoints');
    if (!container) {
        return;
    }

    const operations = collectOperations(spec);
    openApiOperations = {};
    operations.forEach(op => {
        openApiOperations[op.key] = op;
    });

    if (!operations.length) {
        container.innerHTML = '<div class="error">未发现可展示的接口定义。</div>';
        return;
    }

    container.innerHTML = operations.map(operation => `
        <div class="api-endpoint">
            <div class="api-header">
                <div style="display: flex; align-items: center;">
                    <span class="api-method ${escapeHtml(operation.method.toLowerCase())}">${escapeHtml(operation.method.toUpperCase())}</span>
                    <span class="api-path">${escapeHtml(operation.path)}</span>
                </div>
                <button class="api-try-button" onclick="tryApiRequest('${escapeHtml(operation.key)}')">🚀 试用接口</button>
            </div>
            <div class="api-body">
                <p class="api-description">${escapeHtml(operation.summary)}</p>
                ${renderParametersSection(operation)}
                ${renderRequestBodySection(operation)}
                ${renderResponseSection(operation)}
                <div class="api-response" id="${escapeHtml(operation.key)}-response">
                    <h4 style="margin-bottom: 8px; color: #15803d;">响应结果：</h4>
                    <pre id="${escapeHtml(operation.key)}-response-data"></pre>
                </div>
            </div>
        </div>
    `).join('');
}

function getParameterDefaultValue(param) {
    if (!param) return '';
    if (param.schema && param.schema.default !== undefined) {
        return String(param.schema.default);
    }
    if (param.schema && Array.isArray(param.schema.enum) && param.schema.enum.length > 0) {
        return String(param.schema.enum[0]);
    }
    return '';
}

async function tryApiRequest(operationKey) {
    const operation = openApiOperations[operationKey];
    if (!operation) {
        showNotification('接口定义不存在', 'error');
        return;
    }

    let path = operation.path;
    const query = new URLSearchParams();

    const pathParams = operation.parameters.filter(p => p.location === 'path');
    for (const param of pathParams) {
        const defaultValue = getParameterDefaultValue(param);
        const input = window.prompt(`请输入路径参数 ${param.name}`, defaultValue);
        if (input === null) {
            showNotification('已取消请求', 'warning');
            return;
        }
        if (!input.trim()) {
            showNotification(`路径参数 ${param.name} 不能为空`, 'warning');
            return;
        }
        path = path.split(`{${param.name}}`).join(encodeURIComponent(input.trim()));
    }

    const queryParams = operation.parameters.filter(p => p.location === 'query');
    for (const param of queryParams) {
        const defaultValue = getParameterDefaultValue(param);
        const promptText = `查询参数 ${param.name}${param.required ? '（必填）' : '（可选，留空跳过）'}`;
        const input = window.prompt(promptText, defaultValue);
        if (input === null) {
            if (param.required) {
                showNotification(`已取消请求（${param.name} 必填）`, 'warning');
                return;
            }
            continue;
        }
        const value = input.trim();
        if (!value) {
            if (param.required) {
                showNotification(`查询参数 ${param.name} 不能为空`, 'warning');
                return;
            }
            continue;
        }
        query.append(param.name, value);
    }

    const method = operation.method.toUpperCase();
    const requestOptions = {
        method,
        credentials: 'same-origin',
        headers: {}
    };

    if (operation.requestBody && ["POST", "PUT", "PATCH", "DELETE"].includes(method)) {
        const bodyTemplate = toPrettyJson(operation.requestBody.exampleValue) || '{}';
        const bodyInput = window.prompt(
            `请输入请求体JSON（${operation.requestBody.contentType}）`,
            bodyTemplate
        );

        if (bodyInput === null) {
            if (operation.requestBody.required) {
                showNotification('请求体为必填，已取消请求', 'warning');
                return;
            }
        } else if (bodyInput.trim()) {
            try {
                const parsed = JSON.parse(bodyInput);
                requestOptions.body = JSON.stringify(parsed);
                requestOptions.headers['Content-Type'] = operation.requestBody.contentType || 'application/json';
            } catch (error) {
                showNotification(`请求体JSON格式错误: ${error.message}`, 'error');
                return;
            }
        } else if (operation.requestBody.required) {
            showNotification('请求体不能为空', 'warning');
            return;
        }
    }

    const finalUrl = `${window.location.origin}${path}${query.toString() ? `?${query.toString()}` : ''}`;

    try {
        showNotification('正在调用API...', 'info', '', 1500);
        const response = await fetch(finalUrl, requestOptions);

        if (response.status === 401) {
            window.location.href = '/admin';
            return;
        }

        const responseText = await response.text();
        let content = responseText;
        const contentType = response.headers.get('content-type') || '';
        if (contentType.includes('application/json') && responseText) {
            try {
                content = JSON.stringify(JSON.parse(responseText), null, 2);
            } catch (_) {
                content = responseText;
            }
        }

        const responseElement = document.getElementById(`${operation.key}-response`);
        const responseDataElement = document.getElementById(`${operation.key}-response-data`);
        if (responseElement && responseDataElement) {
            responseDataElement.textContent = `HTTP ${response.status}\n${content || '(空响应)'}`;
            responseElement.classList.add('show');
        }

        if (response.ok) {
            showNotification(`API调用成功 (HTTP ${response.status})`, 'success');
        } else {
            showNotification(`API调用失败 (HTTP ${response.status})`, 'warning');
        }
    } catch (error) {
        showNotification(`API调用失败: ${error.message}`, 'error');
    }
}

function generateApiDocsMarkdown(spec) {
    const title = spec?.info?.title || 'API 文档';
    const version = spec?.info?.version || '';
    const description = spec?.info?.description || '';
    const baseUrl = window.location.origin;
    const operations = collectOperations(spec);

    let markdown = `# ${title}\n\n`;
    if (version) markdown += `- 版本: ${version}\n`;
    markdown += `- Base URL: ${baseUrl}\n`;
    if (description) markdown += `- 描述: ${description}\n`;
    markdown += `\n## 接口列表\n\n`;

    operations.forEach((operation, index) => {
        markdown += `### ${index + 1}. ${operation.method.toUpperCase()} ${operation.path}\n\n`;
        markdown += `${operation.summary || '无说明'}\n\n`;

        if (operation.parameters.length > 0) {
            markdown += `参数:\n`;
            operation.parameters.forEach(param => {
                const typeText = param.type || 'object';
                markdown += `- ${param.name} (${param.location}, ${typeText}, ${param.required ? 'required' : 'optional'})`;
                if (param.description) {
                    markdown += `: ${param.description}`;
                }
                markdown += `\n`;
            });
            markdown += `\n`;
        }

        if (operation.requestBody) {
            markdown += `请求体 (${operation.requestBody.contentType}, ${operation.requestBody.required ? 'required' : 'optional'}):\n`;
            markdown += "```json\n";
            markdown += `${toPrettyJson(operation.requestBody.exampleValue) || '{}'}\n`;
            markdown += "```\n\n";
        }

        markdown += `响应:\n`;
        const responseCodes = Object.keys(operation.responses || {});
        if (responseCodes.length) {
            responseCodes.forEach(code => {
                const response = operation.responses[code];
                markdown += `- ${code}: ${response?.description || ''}\n`;
            });
        } else {
            markdown += `- 无定义\n`;
        }
        markdown += `\n`;
    });

    markdown += `---\n生成时间: ${new Date().toLocaleString()}\n`;
    return markdown;
}
