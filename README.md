# 📧 Outlook邮件管理系统

一个基于FastAPI和现代Web技术构建的Outlook邮件管理系统，支持多账户管理、邮件查看、搜索过滤等功能。

## ✨ 功能特性

### 🏠 主要功能

- **📧 邮件管理**: 支持查看、搜索、过滤邮件
- **👥 多账户管理**: 支持添加和管理多个Outlook邮箱账户
- **📦 批量操作**: 支持单行或多行添加邮箱账户
- **🔍 智能搜索**: 实时搜索邮件标题、发件人等信息
- **📊 数据统计**: 显示邮件统计信息（总数、未读、今日邮件等）
- **📤 数据导出**: 支持导出邮件列表为CSV格式
- **🚀 高性能**: 连接池优化、智能缓存、批量处理
- **📖 API文档**: 完整的RESTful API接口文档

### 🎨 用户界面

#### 邮件列表界面
![邮件列表](docs/images/email-list.png)
*邮件列表页面，支持搜索、过滤和统计功能*

#### 邮箱账户管理
![账户管理](docs/images/account-management.png)
![账户批量管理](docs/images/account-add.png)
*邮箱账户管理页面，支持添加、删除和查看邮箱状态*

#### API接口文档
![API文档](docs/images/api-docs.png)
*完整的API接口文档，支持在线测试*

### 🔧 技术特性

- **🏗️ 现代架构**: FastAPI + HTML5 + CSS3 + JavaScript
- **⚡ 高性能**: IMAP连接池 + Graph API、智能缓存机制
- **🎯 用户友好**: 响应式设计、实时通知、键盘快捷键
- **🔒 安全可靠**: OAuth2认证、错误处理、连接管理
- **📱 移动适配**: 支持移动设备访问
- **🌐 RESTful API**: 标准化API接口设计

## 🚀 快速开始

### 📋 系统要求

- Python 3.11+
- uv
- Node.js 20+
- npm
- 现代浏览器（Chrome、Firefox、Safari、Edge）
- 网络连接（用于访问Outlook IMAP和Microsoft Graph服务）

### 📦 安装依赖

```bash
# 克隆项目
git clone <repository-url>
cd OutlookManager

# 安装Python依赖
uv sync

# 安装并构建管理后台前端
npm install
npm run frontend:build
```

### ⚙️ 配置设置

1. **Azure应用注册**（必需）
   - 访问 [Azure Portal](https://portal.azure.com)
   - 注册新的应用程序
   - 配置邮件读取权限
   - 获取Client ID和Refresh Token

2. **环境配置**（可选）
   ```bash
   # 复制配置文件
   cp .env.example .env

   # 编辑配置文件
   nano .env
   ```

### 🎯 启动服务

#### 开发环境

```bash
# 本地默认使用 SQLite: ./data/outlook-manager.db
cp .env.example .env
./start.sh

# 如需后端热重载，先加载 .env，再使用 uvicorn
set -a; source .env; set +a
export DATABASE_URL="${DATABASE_URL_LOCAL:-sqlite:///./data/outlook-manager.db}"
export REDIS_URL="${REDIS_URL_LOCAL-}"
uv run uvicorn main:app --host 0.0.0.0 --port 8000 --reload

# 如需前端热重载，另开一个终端
npm run frontend:dev
```

#### 生产环境

```bash
# 使用gunicorn启动
uv run --with gunicorn gunicorn main:app -w 4 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000

# 或使用uvicorn
uv run uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
```

### 🌐 访问系统

启动成功后，在浏览器中访问：
- **Web界面**: http://localhost:8000
- **管理后台**: http://localhost:8000/admin
- **API文档**: http://localhost:8000/docs
- **API状态**: http://localhost:8000/api

## 📚 使用指南

### 1️⃣ 添加邮箱账户

1. 点击左侧菜单"添加账户"
2. 每行填写一个账户，支持 `邮箱----密码----刷新令牌----客户端ID` 或 `邮箱----密码----客户端ID----刷新令牌`
3. 选择认证模式并点击"验证格式"
4. 点击"开始添加"完成导入

### 2️⃣ 查看邮件

1. 在账户列表中点击"查看邮件"
2. 使用搜索框查找特定邮件
3. 使用过滤器按条件筛选
4. 点击邮件查看详细内容

### 3️⃣ API调用

查看"API管理"页面获取完整的接口文档，支持：
- 获取邮箱列表：`GET /accounts`
- 获取邮件列表：`GET /emails/{email_id}`
- 获取邮件详情：`GET /emails/{email_id}/{message_id}`（IMAP: `{folder}-{id}`，Graph: `GRAPH-{encoded_id}`）

## 🚀 部署指南

### 🐳 Docker部署

```bash
# 构建镜像
docker build -t outlook-manager .

# 运行单容器，本地数据保存到 ./data
docker run -d \
  --name outlook-manager \
  -p 8000:8000 \
  -v $(pwd)/data:/app/data \
  outlook-manager

# 或启动完整 PostgreSQL + Redis 栈
docker compose up --build
```

### ☁️ 云服务器部署

#### 1. 准备服务器
```bash
# 更新系统
sudo apt update && sudo apt upgrade -y

# 安装Python和依赖
sudo apt install python3 python3-pip nginx -y
```

#### 2. 部署应用
```bash
# 上传代码到服务器
scp -r . user@server:/opt/outlook-manager/

# 安装依赖
cd /opt/outlook-manager
uv sync
```

#### 3. 配置Nginx
```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

#### 4. 配置系统服务
```bash
# 创建systemd服务文件
sudo nano /etc/systemd/system/outlook-manager.service
```

```ini
[Unit]
Description=Outlook Manager
After=network.target

[Service]
Type=exec
User=www-data
WorkingDirectory=/opt/outlook-manager
ExecStart=/usr/bin/env uv run uvicorn main:app --host 0.0.0.0 --port 8000
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
# 启动服务
sudo systemctl daemon-reload
sudo systemctl enable outlook-manager
sudo systemctl start outlook-manager
```

### 🔧 性能优化

#### 1. 数据库优化
```bash
# 如果使用SQLite，定期优化
sqlite3 ./data/outlook-manager.db "VACUUM;"
```

#### 2. 缓存配置
```python
# 在main.py中调整缓存设置
CACHE_EXPIRE_TIME = 300  # 5分钟
MAX_CONNECTIONS = 10     # 最大连接数
```

#### 3. 负载均衡
```bash
# 使用多个worker进程
gunicorn main:app -w 8 -k uvicorn.workers.UvicornWorker
```

## 🛠️ 开发指南

### 📁 项目结构
```
OutlookManager/
├── main.py              # 主应用文件
├── pyproject.toml       # uv 项目配置
├── package.json         # React 管理后台依赖和脚本
├── vite.config.js       # 前端构建配置
├── frontend/            # Ant Design Pro + React 管理后台源码
├── static/
│   ├── admin/           # React 管理后台构建产物
│   └── index.html       # 旧版后台页面（构建产物缺失时回退）
├── data/                # 本地 SQLite 数据目录
├── requirements.txt     # Docker兼容依赖清单
├── README.md           # 项目文档
└── docs/               # 文档和图片
    └── images/
```

### 🔧 开发环境设置
```bash
# 安装依赖
uv sync
npm install
npm run frontend:build

# 启动后端开发服务器（热重载）
set -a; source .env; set +a
export DATABASE_URL="${DATABASE_URL_LOCAL:-sqlite:///./data/outlook-manager.db}"
export REDIS_URL="${REDIS_URL_LOCAL-}"
uv run uvicorn main:app --reload --host 0.0.0.0 --port 8000

# 启动前端开发服务器（热重载，自动代理到 8000 后端）
npm run frontend:dev
```

### 🧪 测试
```bash
# 运行测试
python -m pytest tests/

# 代码覆盖率
python -m pytest --cov=main tests/
```

## 📞 支持与反馈

- **问题报告**: 请在GitHub Issues中提交
- **功能建议**: 欢迎提交Pull Request
- **技术支持**: 查看API文档或联系开发团队
---

**🎉 感谢使用Outlook邮件管理系统！**
