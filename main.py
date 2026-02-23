"""
Outlook邮件管理系统 - 主应用模块

基于FastAPI，支持IMAP和Microsoft Graph的高性能邮件管理系统
支持多账户管理、邮件查看、搜索过滤等功能

Author: Outlook Manager Team
Version: 1.0.0
"""

import asyncio
import base64
import email
import imaplib
import json
import logging
import os
import re
import socket
import threading
import time
import hashlib
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from html import escape
from itertools import groupby
from queue import Empty, Queue
from typing import Any, AsyncGenerator, Dict, List, Optional, Tuple
from urllib.parse import quote

import httpx
import psycopg
import redis
from email.header import decode_header
from email.utils import parsedate_to_datetime
from fastapi import FastAPI, HTTPException, Query, Request, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, EmailStr, Field
from psycopg.rows import dict_row



# ============================================================================
# 配置常量
# ============================================================================

# 数据库和缓存配置
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://outlook:outlook@postgres:5432/outlook_manager").strip()
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0").strip()
REDIS_KEY_PREFIX = os.getenv("REDIS_KEY_PREFIX", "outlook-manager").strip() or "outlook-manager"
REDIS_SOCKET_TIMEOUT_SECONDS = float(os.getenv("REDIS_SOCKET_TIMEOUT_SECONDS", "3"))

# OAuth2配置
TOKEN_URL = "https://login.microsoftonline.com/consumers/oauth2/v2.0/token"
IMAP_OAUTH_SCOPE = "https://outlook.office.com/IMAP.AccessAsUser.All offline_access"
GRAPH_OAUTH_SCOPE = "offline_access https://graph.microsoft.com/Mail.Read"
SUPPORTED_AUTH_MODES = {"auto", "imap", "graph"}

# Microsoft Graph配置
GRAPH_API_BASE = "https://graph.microsoft.com/v1.0"
GRAPH_MESSAGES_URL = f"{GRAPH_API_BASE}/me/messages"

# 管理后台鉴权配置
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "change_me_admin_password").strip()
ADMIN_ACCESS_TOKEN_TTL_SECONDS = int(os.getenv("ADMIN_ACCESS_TOKEN_TTL_SECONDS", "1800"))
ADMIN_REFRESH_TOKEN_TTL_SECONDS = int(os.getenv("ADMIN_REFRESH_TOKEN_TTL_SECONDS", "604800"))
ADMIN_COOKIE_SECURE = os.getenv("ADMIN_COOKIE_SECURE", "false").strip().lower() == "true"
ADMIN_ACCESS_COOKIE_NAME = "admin_access_token"
ADMIN_REFRESH_COOKIE_NAME = "admin_refresh_token"
ADMIN_PROTECTED_API_PREFIXES = ("/accounts", "/emails", "/cache", "/token-refresh")
ADMIN_PROTECTED_HTML_PATHS = {"/admin/panel", "/admin/panel/", "/static/index.html"}
ADMIN_PROTECTED_EXACT_PATHS = {"/api", *ADMIN_PROTECTED_HTML_PATHS}

# 账户令牌配置
DEFAULT_ACCOUNT_RT_TTL_SECONDS = int(os.getenv("DEFAULT_ACCOUNT_RT_TTL_SECONDS", str(90 * 24 * 3600)))
DEFAULT_ACCESS_TOKEN_TTL_SECONDS = int(os.getenv("DEFAULT_ACCESS_TOKEN_TTL_SECONDS", "3600"))

# 自动刷新RT配置
TOKEN_REFRESH_DEFAULT_INTERVAL_VALUE = int(os.getenv("TOKEN_REFRESH_DEFAULT_INTERVAL_VALUE", "12"))
TOKEN_REFRESH_DEFAULT_INTERVAL_UNIT = os.getenv("TOKEN_REFRESH_DEFAULT_INTERVAL_UNIT", "hour").strip().lower()
TOKEN_REFRESH_SCHEDULER_CHECK_SECONDS = int(os.getenv("TOKEN_REFRESH_SCHEDULER_CHECK_SECONDS", "30"))
TOKEN_REFRESH_SUPPORTED_UNITS = {"minute", "hour", "day"}

# AT复用/刷新阈值配置
ACCESS_TOKEN_BACKGROUND_REFRESH_SECONDS = int(os.getenv("ACCESS_TOKEN_BACKGROUND_REFRESH_SECONDS", "300"))
ACCESS_TOKEN_FORCE_REFRESH_SECONDS = int(os.getenv("ACCESS_TOKEN_FORCE_REFRESH_SECONDS", "30"))

# IMAP服务器配置
IMAP_SERVER = "outlook.live.com"
IMAP_PORT = 993

# 连接池配置
MAX_CONNECTIONS = 5
CONNECTION_TIMEOUT = 30
SOCKET_TIMEOUT = 15

# 缓存配置
CACHE_EXPIRE_TIME = 60  # 缓存过期时间（秒）
WEB_MAILBOX_SSE_POLL_SECONDS = int(os.getenv("WEB_MAILBOX_SSE_POLL_SECONDS", "5"))

# 临时邮箱 API（GPTMail）配置
TEMP_MAIL_API_BASE_URL = os.getenv("TEMP_MAIL_API_BASE_URL", "https://mail.chatgpt.org.uk").strip().rstrip("/")
TEMP_MAIL_API_KEY = os.getenv("TEMP_MAIL_API_KEY", "gpt-test").strip()
TEMP_MAIL_API_TIMEOUT_SECONDS = float(os.getenv("TEMP_MAIL_API_TIMEOUT_SECONDS", "12"))
TEMP_MAIL_EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# 日志配置
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# 自动刷新任务运行状态
token_refresh_scheduler_task: Optional[asyncio.Task] = None
token_refresh_scheduler_stop_event: Optional[asyncio.Event] = None
token_refresh_run_lock: Optional[asyncio.Lock] = None

# AT缓存与后台续期状态（进程内）
access_token_cache: Dict[str, Dict[str, Any]] = {}
access_token_refresh_locks: Dict[str, asyncio.Lock] = {}
access_token_background_tasks: Dict[str, asyncio.Task] = {}

# Redis客户端（用于邮件缓存和AT缓存）
redis_client: Optional[redis.Redis] = None


# ============================================================================
# 数据模型 (Pydantic Models)
# ============================================================================

class AccountCredentials(BaseModel):
    """账户凭证模型"""
    email: EmailStr
    mailbox_password: Optional[str] = None
    refresh_token: str
    client_id: str
    auth_mode: str = Field(default="auto")
    tags: Optional[List[str]] = Field(default_factory=list)
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "email": "user@outlook.com",
                "mailbox_password": "mailbox-password",
                "refresh_token": "0.AXoA...",
                "client_id": "your-client-id",
                "auth_mode": "auto",
                "tags": ["工作", "个人"]
            }
        }
    )


class EmailItem(BaseModel):
    """邮件项目模型"""
    message_id: str
    folder: str
    subject: str
    from_email: str
    date: str
    is_read: bool = False
    has_attachments: bool = False
    sender_initial: str = "?"

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "message_id": "INBOX-123",
                "folder": "INBOX",
                "subject": "Welcome to Augment Code",
                "from_email": "noreply@augmentcode.com",
                "date": "2024-01-01T12:00:00",
                "is_read": False,
                "has_attachments": False,
                "sender_initial": "A"
            }
        }
    )


class EmailListResponse(BaseModel):
    """邮件列表响应模型"""
    email_id: str
    folder_view: str
    page: int
    page_size: int
    total_emails: int
    emails: List[EmailItem]


class DualViewEmailResponse(BaseModel):
    """双栏视图邮件响应模型"""
    email_id: str
    inbox_emails: List[EmailItem]
    junk_emails: List[EmailItem]
    inbox_total: int
    junk_total: int


class EmailDetailsResponse(BaseModel):
    """邮件详情响应模型"""
    message_id: str
    subject: str
    from_email: str
    to_email: str
    date: str
    body_plain: Optional[str] = None
    body_html: Optional[str] = None


class AccountResponse(BaseModel):
    """账户操作响应模型"""
    email_id: str
    message: str


class AccountInfo(BaseModel):
    """账户信息模型"""
    email_id: str
    client_id: str
    auth_mode: str = "imap"
    status: str = "active"
    tags: List[str] = Field(default_factory=list)
    access_token_expires_at: Optional[str] = None
    refresh_token_expires_at: Optional[str] = None


class AccountListResponse(BaseModel):
    """账户列表响应模型"""
    total_accounts: int
    page: int
    page_size: int
    total_pages: int
    accounts: List[AccountInfo]


class AccountDetailResponse(BaseModel):
    """账户详情响应模型（可编辑字段）"""
    email_id: str
    mailbox_password: Optional[str] = None
    refresh_token: str
    access_token: Optional[str] = None
    client_id: str
    auth_mode: str = "imap"
    status: str = "active"
    tags: List[str] = Field(default_factory=list)
    access_token_expires_at: Optional[str] = None
    refresh_token_expires_at: Optional[str] = None


class AccountUpdateRequest(BaseModel):
    """更新账户信息请求模型"""
    mailbox_password: Optional[str] = None
    refresh_token: str
    client_id: str
    auth_mode: str = Field(default="auto", pattern="^(auto|imap|graph)$")
    tags: List[str] = Field(default_factory=list)


class UpdateTagsRequest(BaseModel):
    """更新标签请求模型"""
    tags: List[str]


class TokenRefreshSettingsUpdateRequest(BaseModel):
    """更新定时刷新设置请求"""
    enabled: bool
    interval_value: int = Field(..., ge=1, le=100000)
    interval_unit: str = Field(..., pattern="^(minute|hour|day)$")


class TokenRefreshSettingsResponse(BaseModel):
    """定时刷新设置响应"""
    enabled: bool
    interval_value: int
    interval_unit: str
    next_run_at: Optional[str] = None
    last_run_at: Optional[str] = None


class TokenRefreshAccountResponse(BaseModel):
    """单账户令牌刷新响应"""
    email_id: str
    auth_mode: str
    access_token_expires_at: Optional[str] = None
    refresh_token_expires_at: Optional[str] = None
    message: str


class TokenRefreshAllResponse(BaseModel):
    """全账户令牌刷新响应"""
    total_accounts: int
    success_count: int
    failure_count: int
    message: str
    details: List[str] = Field(default_factory=list)

# ============================================================================
# IMAP连接池管理
# ============================================================================

class IMAPConnectionPool:
    """
    IMAP连接池管理器

    提供连接复用、自动重连、连接状态监控等功能
    优化IMAP连接性能，减少连接建立开销
    """

    def __init__(self, max_connections: int = MAX_CONNECTIONS):
        """
        初始化连接池

        Args:
            max_connections: 每个邮箱的最大连接数
        """
        self.max_connections = max_connections
        self.connections = {}  # {email: Queue of connections}
        self.connection_count = {}  # {email: active connection count}
        self.lock = threading.Lock()
        logger.info(f"Initialized IMAP connection pool with max_connections={max_connections}")

    def _create_connection(self, email: str, access_token: str) -> imaplib.IMAP4_SSL:
        """
        创建新的IMAP连接

        Args:
            email: 邮箱地址
            access_token: OAuth2访问令牌

        Returns:
            IMAP4_SSL: 已认证的IMAP连接

        Raises:
            Exception: 连接创建失败
        """
        try:
            # 设置全局socket超时
            socket.setdefaulttimeout(SOCKET_TIMEOUT)

            # 创建SSL IMAP连接
            imap_client = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)

            # 设置连接超时
            imap_client.sock.settimeout(CONNECTION_TIMEOUT)

            # XOAUTH2认证
            auth_string = f"user={email}\x01auth=Bearer {access_token}\x01\x01".encode('utf-8')
            imap_client.authenticate('XOAUTH2', lambda _: auth_string)

            logger.info(f"Successfully created IMAP connection for {email}")
            return imap_client

        except Exception as e:
            logger.error(f"Failed to create IMAP connection for {email}: {e}")
            raise

    def get_connection(self, email: str, access_token: str) -> imaplib.IMAP4_SSL:
        """
        获取IMAP连接（从池中复用或创建新连接）

        Args:
            email: 邮箱地址
            access_token: OAuth2访问令牌

        Returns:
            IMAP4_SSL: 可用的IMAP连接

        Raises:
            Exception: 无法获取连接
        """
        with self.lock:
            # 初始化邮箱的连接池
            if email not in self.connections:
                self.connections[email] = Queue(maxsize=self.max_connections)
                self.connection_count[email] = 0

            connection_queue = self.connections[email]

            # 尝试从池中获取现有连接
            try:
                connection = connection_queue.get_nowait()
                # 测试连接有效性
                try:
                    connection.noop()
                    logger.debug(f"Reused existing IMAP connection for {email}")
                    return connection
                except Exception:
                    # 连接已失效，需要创建新连接
                    logger.debug(f"Existing connection invalid for {email}, creating new one")
                    self.connection_count[email] -= 1
            except Empty:
                # 池中没有可用连接
                pass

            # 检查是否可以创建新连接
            if self.connection_count[email] < self.max_connections:
                connection = self._create_connection(email, access_token)
                self.connection_count[email] += 1
                return connection
            else:
                # 达到最大连接数，等待可用连接
                logger.warning(f"Max connections ({self.max_connections}) reached for {email}, waiting...")
                try:
                    return connection_queue.get(timeout=30)
                except Exception as e:
                    logger.error(f"Timeout waiting for connection for {email}: {e}")
                    raise

    def return_connection(self, email: str, connection: imaplib.IMAP4_SSL) -> None:
        """
        归还连接到池中

        Args:
            email: 邮箱地址
            connection: 要归还的IMAP连接
        """
        if email not in self.connections:
            logger.warning(f"Attempting to return connection for unknown email: {email}")
            return

        try:
            # 测试连接状态
            connection.noop()
            # 连接有效，归还到池中
            self.connections[email].put_nowait(connection)
            logger.debug(f"Successfully returned IMAP connection for {email}")
        except Exception as e:
            # 连接已失效，减少计数并丢弃
            with self.lock:
                if email in self.connection_count:
                    self.connection_count[email] = max(0, self.connection_count[email] - 1)
            logger.debug(f"Discarded invalid connection for {email}: {e}")

    def close_all_connections(self, email: str = None) -> None:
        """
        关闭所有连接

        Args:
            email: 指定邮箱地址，如果为None则关闭所有邮箱的连接
        """
        with self.lock:
            if email:
                # 关闭指定邮箱的所有连接
                if email in self.connections:
                    closed_count = 0
                    while not self.connections[email].empty():
                        try:
                            conn = self.connections[email].get_nowait()
                            conn.logout()
                            closed_count += 1
                        except Exception as e:
                            logger.debug(f"Error closing connection: {e}")

                    self.connection_count[email] = 0
                    logger.info(f"Closed {closed_count} connections for {email}")
            else:
                # 关闭所有邮箱的连接
                total_closed = 0
                for email_key in list(self.connections.keys()):
                    count_before = self.connection_count.get(email_key, 0)
                    self.close_all_connections(email_key)
                    total_closed += count_before
                logger.info(f"Closed total {total_closed} connections for all accounts")

# ============================================================================
# 全局实例和缓存管理
# ============================================================================

# 全局连接池实例
imap_pool = IMAPConnectionPool()

# 内存缓存存储
email_cache = {}  # 邮件列表缓存
email_count_cache = {}  # 邮件总数缓存，用于检测新邮件


class PostgresConnection:
    """简化版PostgreSQL连接包装器，尽量保持原有调用风格。"""

    def __init__(self, dsn: str):
        self._conn = psycopg.connect(dsn, row_factory=dict_row)

    @staticmethod
    def _adapt_sql(sql: str) -> str:
        adapted = sql.replace("datetime('now')", "CURRENT_TIMESTAMP")
        return adapted.replace("?", "%s")

    def execute(self, sql: str, params: Optional[List[Any] | Tuple[Any, ...]] = None):
        adapted_sql = self._adapt_sql(sql)
        if params is None:
            return self._conn.execute(adapted_sql)
        return self._conn.execute(adapted_sql, tuple(params))

    def commit(self) -> None:
        self._conn.commit()

    def rollback(self) -> None:
        self._conn.rollback()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type is not None:
            try:
                self._conn.rollback()
            except Exception:
                pass
        self._conn.close()
        return False


def get_db_connection() -> PostgresConnection:
    """获取PostgreSQL连接。"""
    return PostgresConnection(DATABASE_URL)


def get_redis_key(suffix: str) -> str:
    return f"{REDIS_KEY_PREFIX}:{suffix}"


def get_redis_email_cache_key(cache_key: str) -> str:
    return get_redis_key(f"email-cache:{cache_key}")


def get_redis_access_token_key(email_id: str, auth_mode: str) -> str:
    return get_redis_key(f"access-token:{build_access_token_cache_key(email_id, auth_mode)}")


def init_redis_cache_client() -> None:
    global redis_client
    if not REDIS_URL:
        redis_client = None
        logger.warning("REDIS_URL is empty. Redis cache is disabled.")
        return

    try:
        redis_client = redis.Redis.from_url(
            REDIS_URL,
            decode_responses=True,
            socket_timeout=REDIS_SOCKET_TIMEOUT_SECONDS,
            socket_connect_timeout=REDIS_SOCKET_TIMEOUT_SECONDS,
        )
        redis_client.ping()
        logger.info("Redis cache connected.")
    except Exception as e:
        redis_client = None
        logger.warning(f"Redis unavailable, fallback to local memory cache: {e}")


def get_cache_key(email: str, auth_mode: str, folder: str, page: int, page_size: int) -> str:
    """
    生成缓存键

    Args:
        email: 邮箱地址
        auth_mode: 认证模式 (imap/graph)
        folder: 文件夹名称
        page: 页码
        page_size: 每页大小

    Returns:
        str: 缓存键
    """
    return f"{email}:{auth_mode}:{folder}:{page}:{page_size}"


def get_cached_emails(cache_key: str, force_refresh: bool = False):
    """
    获取缓存的邮件列表

    Args:
        cache_key: 缓存键
        force_refresh: 是否强制刷新缓存

    Returns:
        缓存的数据或None
    """
    redis_key = get_redis_email_cache_key(cache_key)

    if force_refresh:
        if redis_client:
            try:
                redis_client.delete(redis_key)
            except Exception as e:
                logger.warning(f"Failed to clear Redis email cache {cache_key}: {e}")

        if cache_key in email_cache:
            del email_cache[cache_key]
            logger.debug(f"Force refresh: removed memory cache for {cache_key}")
        return None

    if redis_client:
        try:
            cached_raw = redis_client.get(redis_key)
            if cached_raw:
                payload = json.loads(cached_raw)
                return EmailListResponse(**payload)
        except Exception as e:
            logger.warning(f"Redis cache read failed for {cache_key}: {e}")

    if cache_key in email_cache:
        cached_data, timestamp = email_cache[cache_key]
        if time.time() - timestamp < CACHE_EXPIRE_TIME:
            logger.debug(f"Memory cache hit for {cache_key}")
            return cached_data
        del email_cache[cache_key]
        logger.debug(f"Memory cache expired for {cache_key}")

    return None


def set_cached_emails(cache_key: str, data) -> None:
    """
    设置邮件列表缓存

    Args:
        cache_key: 缓存键
        data: 要缓存的数据
    """
    email_cache[cache_key] = (data, time.time())

    if redis_client:
        redis_key = get_redis_email_cache_key(cache_key)
        try:
            if hasattr(data, "model_dump"):
                payload = data.model_dump()
            else:
                payload = data
            redis_client.setex(redis_key, CACHE_EXPIRE_TIME, json.dumps(payload, ensure_ascii=False))
        except Exception as e:
            logger.warning(f"Redis cache write failed for {cache_key}: {e}")

    logger.debug(f"Cache set for {cache_key}")


def clear_email_cache(email: str = None) -> None:
    """
    清除邮件缓存

    Args:
        email: 指定邮箱地址，如果为None则清除所有缓存
    """
    if email:
        keys_to_delete = [key for key in email_cache.keys() if key.startswith(f"{email}:")]
        for key in keys_to_delete:
            del email_cache[key]

        if redis_client:
            prefix = get_redis_email_cache_key(f"{email}:")
            try:
                matched_keys = list(redis_client.scan_iter(match=f"{prefix}*"))
                if matched_keys:
                    redis_client.delete(*matched_keys)
            except Exception as e:
                logger.warning(f"Failed to clear Redis cache for {email}: {e}")

        logger.info(f"Cleared cache for {email} ({len(keys_to_delete)} memory entries)")
        return

    cache_count = len(email_cache)
    email_cache.clear()
    email_count_cache.clear()

    if redis_client:
        try:
            matched_keys = list(redis_client.scan_iter(match=f"{get_redis_key('email-cache:')}*"))
            if matched_keys:
                redis_client.delete(*matched_keys)
        except Exception as e:
            logger.warning(f"Failed to clear all Redis email cache: {e}")

    logger.info(f"Cleared all email cache ({cache_count} memory entries)")


def normalize_auth_mode(auth_mode: Optional[str], default: str = "imap") -> str:
    """标准化认证模式"""
    if not auth_mode:
        return default

    normalized = auth_mode.strip().lower()
    if normalized not in SUPPORTED_AUTH_MODES:
        return default
    return normalized


def encode_graph_message_id(raw_message_id: str) -> str:
    """将Graph原始消息ID编码为URL安全的内部message_id"""
    encoded = base64.urlsafe_b64encode(raw_message_id.encode("utf-8")).decode("ascii").rstrip("=")
    return f"GRAPH-{encoded}"


def decode_graph_message_id(encoded_message_id: str) -> str:
    """从内部message_id还原Graph原始消息ID"""
    if not encoded_message_id.startswith("GRAPH-"):
        raise HTTPException(status_code=400, detail="Invalid Graph message_id format")

    payload = encoded_message_id[len("GRAPH-"):]
    if not payload:
        raise HTTPException(status_code=400, detail="Invalid Graph message_id format")

    padding = "=" * ((4 - len(payload) % 4) % 4)
    try:
        return base64.urlsafe_b64decode(payload + padding).decode("utf-8")
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid Graph message_id encoding")


def get_scope_for_auth_mode(auth_mode: str) -> str:
    """根据认证模式返回scope"""
    if auth_mode == "graph":
        return GRAPH_OAUTH_SCOPE
    return IMAP_OAUTH_SCOPE


def get_graph_folders_by_view(folder_view: str) -> List[tuple[str, str]]:
    """根据页面文件夹视图映射Graph文件夹"""
    if folder_view == "inbox":
        return [("inbox", "inbox")]
    if folder_view == "junk":
        return [("junk", "junkemail")]
    return [("inbox", "inbox"), ("junk", "junkemail")]


def normalize_email(email_id: str) -> str:
    return email_id.strip().lower()


def parse_tags(tags_raw: Optional[str]) -> List[str]:
    if not tags_raw:
        return []
    try:
        parsed = json.loads(tags_raw)
        if isinstance(parsed, list):
            return [str(tag) for tag in parsed if str(tag).strip()]
    except Exception:
        pass
    return []


def serialize_tags(tags: Optional[List[str]]) -> str:
    clean_tags = []
    if tags:
        clean_tags = [str(tag).strip() for tag in tags if str(tag).strip()]
    return json.dumps(clean_tags, ensure_ascii=False)


def normalize_token_refresh_unit(unit: Optional[str], default: str = "hour") -> str:
    normalized = (unit or "").strip().lower()
    if normalized in TOKEN_REFRESH_SUPPORTED_UNITS:
        return normalized
    return default


def token_refresh_interval_to_seconds(interval_value: int, interval_unit: str) -> int:
    normalized_unit = normalize_token_refresh_unit(interval_unit)
    if normalized_unit == "day":
        return interval_value * 24 * 3600
    if normalized_unit == "hour":
        return interval_value * 3600
    return interval_value * 60


def datetime_to_utc_iso(timestamp: Optional[int]) -> Optional[str]:
    if timestamp is None:
        return None
    try:
        parsed = int(timestamp)
    except (TypeError, ValueError):
        return None
    if parsed <= 0:
        return None
    return datetime.fromtimestamp(parsed, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def safe_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def resolve_account_status(
    refresh_token: Optional[str],
    client_id: Optional[str],
    refresh_token_expires_at: Optional[int],
    now_ts: Optional[int] = None
) -> str:
    """根据凭证完整性和RT过期时间计算账户状态。"""
    token_value = str(refresh_token or "").strip()
    client_value = str(client_id or "").strip()
    current_ts = int(time.time()) if now_ts is None else int(now_ts)

    if not token_value or not client_value:
        return "invalid"

    if refresh_token_expires_at is not None and refresh_token_expires_at <= current_ts:
        return "expired"

    return "active"


def ensure_table_column(conn: PostgresConnection, table_name: str, column_name: str, column_sql: str) -> None:
    conn.execute(f"ALTER TABLE {table_name} ADD COLUMN IF NOT EXISTS {column_name} {column_sql}")


def build_access_token_cache_key(email_id: str, auth_mode: str) -> str:
    return f"{normalize_email(email_id)}::{normalize_auth_mode(auth_mode, default='imap')}"


def get_cached_access_token(email_id: str, auth_mode: str) -> Tuple[Optional[str], Optional[int]]:
    cache_key = build_access_token_cache_key(email_id, auth_mode)
    redis_key = get_redis_access_token_key(email_id, auth_mode)

    if redis_client:
        try:
            cached_raw = redis_client.get(redis_key)
            if cached_raw:
                payload = json.loads(cached_raw)
                token_value = str(payload.get("token") or "").strip()
                expires_at = safe_int(payload.get("expires_at"))
                if token_value and expires_at:
                    access_token_cache[cache_key] = {
                        "token": token_value,
                        "expires_at": expires_at,
                        "updated_at": int(time.time()),
                    }
                    return token_value, expires_at
        except Exception as e:
            logger.warning(f"Failed to read Redis access token cache {cache_key}: {e}")

    cached = access_token_cache.get(cache_key)
    if not cached:
        return None, None

    token_value = str(cached.get("token") or "").strip()
    expires_at = safe_int(cached.get("expires_at"))
    if not token_value or not expires_at:
        access_token_cache.pop(cache_key, None)
        return None, None

    if expires_at <= int(time.time()):
        access_token_cache.pop(cache_key, None)
        return None, None

    return token_value, expires_at


def set_cached_access_token(email_id: str, auth_mode: str, token: str, expires_at: int) -> None:
    cache_key = build_access_token_cache_key(email_id, auth_mode)
    now_ts = int(time.time())
    access_token_cache[cache_key] = {
        "token": token,
        "expires_at": int(expires_at),
        "updated_at": now_ts
    }

    if redis_client:
        redis_key = get_redis_access_token_key(email_id, auth_mode)
        ttl = max(1, int(expires_at) - now_ts)
        payload = {
            "token": token,
            "expires_at": int(expires_at),
            "updated_at": now_ts,
        }
        try:
            redis_client.setex(redis_key, ttl, json.dumps(payload, ensure_ascii=False))
        except Exception as e:
            logger.warning(f"Failed to write Redis access token cache {cache_key}: {e}")


def clear_cached_access_token(email_id: str, auth_mode: str) -> None:
    cache_key = build_access_token_cache_key(email_id, auth_mode)
    access_token_cache.pop(cache_key, None)
    if redis_client:
        redis_key = get_redis_access_token_key(email_id, auth_mode)
        try:
            redis_client.delete(redis_key)
        except Exception as e:
            logger.warning(f"Failed to clear Redis access token cache {cache_key}: {e}")
    task = access_token_background_tasks.pop(cache_key, None)
    if task and not task.done():
        task.cancel()


def get_access_token_refresh_lock(email_id: str, auth_mode: str) -> asyncio.Lock:
    cache_key = build_access_token_cache_key(email_id, auth_mode)
    existing = access_token_refresh_locks.get(cache_key)
    if existing:
        return existing
    new_lock = asyncio.Lock()
    access_token_refresh_locks[cache_key] = new_lock
    return new_lock


def should_background_refresh_access_token(expires_at: int, now_ts: int) -> bool:
    return (expires_at - now_ts) <= max(60, ACCESS_TOKEN_BACKGROUND_REFRESH_SECONDS)


def should_force_refresh_access_token(expires_at: int, now_ts: int) -> bool:
    return (expires_at - now_ts) <= max(5, ACCESS_TOKEN_FORCE_REFRESH_SECONDS)


def init_account_db() -> None:
    """初始化账户数据库"""
    try:
        with get_db_connection() as conn:
            now_ts = int(time.time())
            default_rt_expires_at = now_ts + DEFAULT_ACCOUNT_RT_TTL_SECONDS

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS accounts (
                    email_id TEXT PRIMARY KEY,
                    mailbox_password TEXT NOT NULL DEFAULT '',
                    refresh_token TEXT NOT NULL,
                    client_id TEXT NOT NULL,
                    auth_mode TEXT NOT NULL DEFAULT 'imap',
                    tags TEXT NOT NULL DEFAULT '[]',
                    access_token_expires_at INTEGER,
                    refresh_token_expires_at INTEGER,
                    token_last_refreshed_at INTEGER,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            ensure_table_column(conn, "accounts", "access_token_expires_at", "INTEGER")
            ensure_table_column(conn, "accounts", "refresh_token_expires_at", "INTEGER")
            ensure_table_column(conn, "accounts", "token_last_refreshed_at", "INTEGER")

            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_accounts_mailbox_password
                ON accounts (mailbox_password)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_accounts_updated_at
                ON accounts (updated_at)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_accounts_rt_expires
                ON accounts (refresh_token_expires_at)
                """
            )

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS token_refresh_settings (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    enabled INTEGER NOT NULL DEFAULT 0,
                    interval_value INTEGER NOT NULL DEFAULT 12,
                    interval_unit TEXT NOT NULL DEFAULT 'hour',
                    next_run_at INTEGER,
                    last_run_at INTEGER,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            ensure_table_column(conn, "token_refresh_settings", "enabled", "INTEGER NOT NULL DEFAULT 0")
            ensure_table_column(conn, "token_refresh_settings", "interval_value", "INTEGER NOT NULL DEFAULT 12")
            ensure_table_column(conn, "token_refresh_settings", "interval_unit", "TEXT NOT NULL DEFAULT 'hour'")
            ensure_table_column(conn, "token_refresh_settings", "next_run_at", "INTEGER")
            ensure_table_column(conn, "token_refresh_settings", "last_run_at", "INTEGER")

            conn.execute(
                """
                INSERT INTO token_refresh_settings (
                    id, enabled, interval_value, interval_unit, next_run_at, last_run_at
                ) VALUES (?, ?, ?, ?, NULL, NULL)
                ON CONFLICT (id) DO NOTHING
                """,
                (
                    1,
                    0,
                    max(1, TOKEN_REFRESH_DEFAULT_INTERVAL_VALUE),
                    normalize_token_refresh_unit(TOKEN_REFRESH_DEFAULT_INTERVAL_UNIT)
                )
            )

            conn.execute(
                """
                UPDATE token_refresh_settings
                SET interval_unit = ?, updated_at = datetime('now')
                WHERE interval_unit NOT IN ('minute', 'hour', 'day')
                """,
                (normalize_token_refresh_unit(TOKEN_REFRESH_DEFAULT_INTERVAL_UNIT),)
            )
            conn.execute(
                """
                UPDATE token_refresh_settings
                SET interval_value = ?, updated_at = datetime('now')
                WHERE interval_value IS NULL OR interval_value < 1
                """,
                (max(1, TOKEN_REFRESH_DEFAULT_INTERVAL_VALUE),)
            )

            conn.execute(
                """
                UPDATE accounts
                SET refresh_token_expires_at = ?, updated_at = datetime('now')
                WHERE refresh_token_expires_at IS NULL OR refresh_token_expires_at <= 0
                """,
                (default_rt_expires_at,)
            )

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS admin_sessions (
                    refresh_token_hash TEXT PRIMARY KEY,
                    access_token_hash TEXT NOT NULL,
                    access_expires_at INTEGER NOT NULL,
                    refresh_expires_at INTEGER NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_admin_sessions_refresh_exp
                ON admin_sessions (refresh_expires_at)
                """
            )
            conn.commit()
    except Exception as e:
        logger.error(f"Failed to initialize PostgreSQL schema: {e}")
        raise


def get_token_refresh_settings_row(conn: PostgresConnection) -> Dict[str, Any]:
    row = conn.execute(
        """
        SELECT enabled, interval_value, interval_unit, next_run_at, last_run_at
        FROM token_refresh_settings
        WHERE id = 1
        LIMIT 1
        """
    ).fetchone()
    if row:
        return row

    conn.execute(
        """
        INSERT INTO token_refresh_settings (id, enabled, interval_value, interval_unit)
        VALUES (?, ?, ?, ?)
        ON CONFLICT (id) DO NOTHING
        """,
        (
            1,
            0,
            max(1, TOKEN_REFRESH_DEFAULT_INTERVAL_VALUE),
            normalize_token_refresh_unit(TOKEN_REFRESH_DEFAULT_INTERVAL_UNIT)
        )
    )
    conn.commit()
    return conn.execute(
        """
        SELECT enabled, interval_value, interval_unit, next_run_at, last_run_at
        FROM token_refresh_settings
        WHERE id = 1
        LIMIT 1
        """
    ).fetchone()


def build_token_refresh_settings_response(row: Dict[str, Any]) -> TokenRefreshSettingsResponse:
    return TokenRefreshSettingsResponse(
        enabled=bool(int(row["enabled"] or 0)),
        interval_value=max(1, int(row["interval_value"] or 1)),
        interval_unit=normalize_token_refresh_unit(row["interval_unit"]),
        next_run_at=datetime_to_utc_iso(safe_int(row["next_run_at"])),
        last_run_at=datetime_to_utc_iso(safe_int(row["last_run_at"]))
    )


def get_token_refresh_settings() -> TokenRefreshSettingsResponse:
    with get_db_connection() as conn:
        row = get_token_refresh_settings_row(conn)
        return build_token_refresh_settings_response(row)


def compute_next_token_refresh_at(interval_value: int, interval_unit: str, base_ts: Optional[int] = None) -> int:
    start_ts = base_ts if base_ts is not None else int(time.time())
    safe_interval = max(1, int(interval_value))
    interval_seconds = token_refresh_interval_to_seconds(safe_interval, interval_unit)
    return start_ts + interval_seconds


def set_token_refresh_settings(
    enabled: bool,
    interval_value: int,
    interval_unit: str
) -> TokenRefreshSettingsResponse:
    safe_interval = max(1, int(interval_value))
    safe_unit = normalize_token_refresh_unit(interval_unit)
    now_ts = int(time.time())
    next_run_at = compute_next_token_refresh_at(safe_interval, safe_unit, now_ts) if enabled else None

    with get_db_connection() as conn:
        get_token_refresh_settings_row(conn)
        conn.execute(
            """
            UPDATE token_refresh_settings
            SET enabled = ?, interval_value = ?, interval_unit = ?, next_run_at = ?, updated_at = datetime('now')
            WHERE id = 1
            """,
            (1 if enabled else 0, safe_interval, safe_unit, next_run_at)
        )
        conn.commit()
        row = get_token_refresh_settings_row(conn)
        return build_token_refresh_settings_response(row)


def mark_token_refresh_run_completed(interval_value: int, interval_unit: str, enabled: bool) -> None:
    now_ts = int(time.time())
    next_run_at = compute_next_token_refresh_at(interval_value, interval_unit, now_ts) if enabled else None
    with get_db_connection() as conn:
        get_token_refresh_settings_row(conn)
        conn.execute(
            """
            UPDATE token_refresh_settings
            SET last_run_at = ?, next_run_at = ?, updated_at = datetime('now')
            WHERE id = 1
            """,
            (now_ts, next_run_at)
        )
        conn.commit()


def hash_admin_token(token: str) -> str:
    """对管理员token做SHA-256哈希存储"""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def verify_admin_password(password: str) -> bool:
    """校验管理员密码"""
    expected = ADMIN_PASSWORD
    provided = (password or "").strip()
    return bool(expected) and secrets.compare_digest(provided, expected)


def create_admin_session_tokens() -> tuple[str, str]:
    """创建管理员会话并返回(access_token, refresh_token)"""
    now_ts = int(time.time())
    access_token = secrets.token_urlsafe(48)
    refresh_token = secrets.token_urlsafe(64)
    access_token_hash = hash_admin_token(access_token)
    refresh_token_hash = hash_admin_token(refresh_token)
    access_expires_at = now_ts + ADMIN_ACCESS_TOKEN_TTL_SECONDS
    refresh_expires_at = now_ts + ADMIN_REFRESH_TOKEN_TTL_SECONDS

    with get_db_connection() as conn:
        conn.execute(
            """
            INSERT INTO admin_sessions (
                refresh_token_hash, access_token_hash, access_expires_at, refresh_expires_at, updated_at
            ) VALUES (?, ?, ?, ?, datetime('now'))
            ON CONFLICT (refresh_token_hash) DO UPDATE SET
                access_token_hash = EXCLUDED.access_token_hash,
                access_expires_at = EXCLUDED.access_expires_at,
                refresh_expires_at = EXCLUDED.refresh_expires_at,
                updated_at = CURRENT_TIMESTAMP
            """,
            (
                refresh_token_hash,
                access_token_hash,
                access_expires_at,
                refresh_expires_at,
            )
        )
        conn.commit()

    return access_token, refresh_token


def validate_admin_token_pair(access_token: str, refresh_token: str) -> tuple[bool, Optional[str]]:
    """
    验证管理员双token。
    返回 (是否有效, 新access_token[若触发续签])
    """
    now_ts = int(time.time())
    access_hash = hash_admin_token(access_token)
    refresh_hash = hash_admin_token(refresh_token)

    with get_db_connection() as conn:
        row = conn.execute(
            """
            SELECT access_token_hash, access_expires_at, refresh_expires_at
            FROM admin_sessions
            WHERE refresh_token_hash = ?
            LIMIT 1
            """,
            (refresh_hash,)
        ).fetchone()

        if not row:
            return False, None

        if int(row["refresh_expires_at"]) <= now_ts:
            conn.execute(
                "DELETE FROM admin_sessions WHERE refresh_token_hash = ?",
                (refresh_hash,)
            )
            conn.commit()
            return False, None

        if not secrets.compare_digest(row["access_token_hash"], access_hash):
            return False, None

        if int(row["access_expires_at"]) > now_ts:
            return True, None

        new_access_token = secrets.token_urlsafe(48)
        conn.execute(
            """
            UPDATE admin_sessions
            SET access_token_hash = ?, access_expires_at = ?, updated_at = datetime('now')
            WHERE refresh_token_hash = ?
            """,
            (
                hash_admin_token(new_access_token),
                now_ts + ADMIN_ACCESS_TOKEN_TTL_SECONDS,
                refresh_hash
            )
        )
        conn.commit()
        return True, new_access_token


def revoke_admin_session(refresh_token: Optional[str]) -> None:
    """按refresh_token撤销管理员会话"""
    if not refresh_token:
        return

    refresh_hash = hash_admin_token(refresh_token)
    with get_db_connection() as conn:
        conn.execute(
            "DELETE FROM admin_sessions WHERE refresh_token_hash = ?",
            (refresh_hash,)
        )
        conn.commit()


def set_admin_auth_cookies(response, access_token: str, refresh_token: str) -> None:
    """写入管理员access/refresh cookie"""
    response.set_cookie(
        key=ADMIN_ACCESS_COOKIE_NAME,
        value=access_token,
        httponly=True,
        secure=ADMIN_COOKIE_SECURE,
        samesite="lax",
        path="/",
        max_age=ADMIN_ACCESS_TOKEN_TTL_SECONDS
    )
    response.set_cookie(
        key=ADMIN_REFRESH_COOKIE_NAME,
        value=refresh_token,
        httponly=True,
        secure=ADMIN_COOKIE_SECURE,
        samesite="lax",
        path="/",
        max_age=ADMIN_REFRESH_TOKEN_TTL_SECONDS
    )


def clear_admin_auth_cookies(response) -> None:
    """清空管理员鉴权cookie"""
    response.delete_cookie(ADMIN_ACCESS_COOKIE_NAME, path="/")
    response.delete_cookie(ADMIN_REFRESH_COOKIE_NAME, path="/")


def is_admin_protected_path(path: str) -> bool:
    """判断路径是否需要管理员鉴权"""
    if path in ADMIN_PROTECTED_EXACT_PATHS:
        return True
    return any(path == prefix or path.startswith(f"{prefix}/") for prefix in ADMIN_PROTECTED_API_PREFIXES)


def is_admin_html_path(path: str) -> bool:
    return path in ADMIN_PROTECTED_HTML_PATHS


def build_admin_unauthorized_response(path: str):
    """未认证时：HTML跳转登录页，API返回401"""
    if is_admin_html_path(path):
        return RedirectResponse(url="/admin", status_code=303)
    return JSONResponse(status_code=401, content={"detail": "Admin authentication required"})


def render_admin_login_page(error_message: Optional[str] = None) -> str:
    """管理员登录页"""
    error_html = ""
    if error_message:
        error_html = f'<div class="auth-error">{escape(error_message)}</div>'

    return f"""
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>后台登录</title>
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link href="https://fonts.googleapis.com/css2?family=Manrope:wght@400;500;600;700;800&family=Outfit:wght@600;700;800&display=swap" rel="stylesheet" />
  <link rel="stylesheet" href="/static/auth-pages.css" />
</head>
<body class="auth-page auth-page-admin">
  <div class="auth-card">
    <div class="auth-chip"><span class="auth-dot"></span>Outlook Manager Console</div>
    <h2>后台管理登录</h2>
    <p>请输入管理员密码。</p>
    {error_html}
    <form class="auth-form" method="post" action="/admin/auth/login">
      <label for="password">管理员密码</label>
      <input id="password" name="password" type="password" autocomplete="current-password" required />
      <button type="submit">登录后台</button>
    </form>
  </div>
</body>
</html>
"""


def row_to_credentials(row: Dict[str, Any]) -> AccountCredentials:
    """数据库行转换为凭证对象"""
    return AccountCredentials(
        email=row["email_id"],
        mailbox_password=(row["mailbox_password"] or None),
        refresh_token=row["refresh_token"],
        client_id=row["client_id"],
        auth_mode=normalize_auth_mode(row["auth_mode"], default="imap"),
        tags=parse_tags(row["tags"])
    )


def get_account_credentials_by_email_and_password(
    email_id: str,
    mailbox_password: str
) -> Optional[AccountCredentials]:
    """按邮箱+邮箱密码查询账户（用于 /web 路由）"""
    normalized_email = normalize_email(email_id)
    normalized_password = mailbox_password.strip()

    if not normalized_email or not normalized_password:
        return None

    try:
        with get_db_connection() as conn:
            row = conn.execute(
                """
                SELECT email_id, mailbox_password, refresh_token, client_id, auth_mode, tags
                FROM accounts
                WHERE email_id = ? AND mailbox_password = ?
                LIMIT 1
                """,
                (normalized_email, normalized_password)
            ).fetchone()
    except Exception as e:
        logger.error(f"Failed to query account by email/password from PostgreSQL: {e}")
        return None

    if not row:
        return None
    return row_to_credentials(row)


def update_account_token_state(
    email_id: str,
    access_token_expires_at: Optional[int] = None,
    refresh_token_expires_at: Optional[int] = None,
    refresh_token: Optional[str] = None,
    auth_mode: Optional[str] = None,
    mark_refreshed: bool = True
) -> bool:
    """更新账户令牌状态，返回账户是否存在。"""
    normalized_email = normalize_email(email_id)
    if not normalized_email:
        return False

    assignments: List[str] = []
    params: List[Any] = []

    if access_token_expires_at is not None:
        assignments.append("access_token_expires_at = ?")
        params.append(int(access_token_expires_at))

    if refresh_token_expires_at is not None:
        assignments.append("refresh_token_expires_at = ?")
        params.append(int(refresh_token_expires_at))

    if refresh_token:
        assignments.append("refresh_token = ?")
        params.append(refresh_token)

    if auth_mode:
        assignments.append("auth_mode = ?")
        params.append(normalize_auth_mode(auth_mode, default="imap"))

    if mark_refreshed:
        assignments.append("token_last_refreshed_at = ?")
        params.append(int(time.time()))

    assignments.append("updated_at = datetime('now')")

    with get_db_connection() as conn:
        cursor = conn.execute(
            f"UPDATE accounts SET {', '.join(assignments)} WHERE email_id = ?",
            params + [normalized_email]
        )
        conn.commit()
        return cursor.rowcount > 0


def get_account_token_expiry(email_id: str) -> Tuple[Optional[int], Optional[int]]:
    normalized_email = normalize_email(email_id)
    if not normalized_email:
        return None, None
    with get_db_connection() as conn:
        row = conn.execute(
            """
            SELECT access_token_expires_at, refresh_token_expires_at
            FROM accounts
            WHERE email_id = ?
            LIMIT 1
            """,
            (normalized_email,)
        ).fetchone()
    if not row:
        return None, None
    return safe_int(row["access_token_expires_at"]), safe_int(row["refresh_token_expires_at"])

# ============================================================================
# 邮件处理辅助函数
# ============================================================================

def decode_header_value(header_value: str) -> str:
    """
    解码邮件头字段

    处理各种编码格式的邮件头部信息，如Subject、From等

    Args:
        header_value: 原始头部值

    Returns:
        str: 解码后的字符串
    """
    if not header_value:
        return ""

    try:
        decoded_parts = decode_header(str(header_value))
        decoded_string = ""

        for part, charset in decoded_parts:
            if isinstance(part, bytes):
                try:
                    # 使用指定编码或默认UTF-8解码
                    encoding = charset if charset else 'utf-8'
                    decoded_string += part.decode(encoding, errors='replace')
                except (LookupError, UnicodeDecodeError):
                    # 编码失败时使用UTF-8强制解码
                    decoded_string += part.decode('utf-8', errors='replace')
            else:
                decoded_string += str(part)

        return decoded_string.strip()
    except Exception as e:
        logger.warning(f"Failed to decode header value '{header_value}': {e}")
        return str(header_value) if header_value else ""


def extract_email_content(email_message: email.message.EmailMessage) -> tuple[str, str]:
    """
    提取邮件的纯文本和HTML内容

    Args:
        email_message: 邮件消息对象

    Returns:
        tuple[str, str]: (纯文本内容, HTML内容)
    """
    body_plain = ""
    body_html = ""

    try:
        if email_message.is_multipart():
            # 处理多部分邮件
            for part in email_message.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))

                # 跳过附件
                if 'attachment' not in content_disposition.lower():
                    try:
                        charset = part.get_content_charset() or 'utf-8'
                        payload = part.get_payload(decode=True)

                        if payload:
                            decoded_content = payload.decode(charset, errors='replace')

                            if content_type == 'text/plain' and not body_plain:
                                body_plain = decoded_content
                            elif content_type == 'text/html' and not body_html:
                                body_html = decoded_content

                    except Exception as e:
                        logger.warning(f"Failed to decode email part ({content_type}): {e}")
        else:
            # 处理单部分邮件
            try:
                charset = email_message.get_content_charset() or 'utf-8'
                payload = email_message.get_payload(decode=True)

                if payload:
                    content = payload.decode(charset, errors='replace')
                    content_type = email_message.get_content_type()

                    if content_type == 'text/plain':
                        body_plain = content
                    elif content_type == 'text/html':
                        body_html = content
                    else:
                        # 默认当作纯文本处理
                        body_plain = content

            except Exception as e:
                logger.warning(f"Failed to decode single-part email body: {e}")

    except Exception as e:
        logger.error(f"Error extracting email content: {e}")

    return body_plain.strip(), body_html.strip()


# ============================================================================
# 账户凭证管理模块
# ============================================================================

async def get_account_credentials(email_id: str) -> AccountCredentials:
    """
    从PostgreSQL获取指定邮箱的账户凭证

    Args:
        email_id: 邮箱地址

    Returns:
        AccountCredentials: 账户凭证对象

    Raises:
        HTTPException: 账户不存在或读取失败
    """
    try:
        normalized_email = normalize_email(email_id)
        if not normalized_email:
            raise HTTPException(status_code=400, detail="Invalid email_id")

        with get_db_connection() as conn:
            row = conn.execute(
                """
                SELECT email_id, mailbox_password, refresh_token, client_id, auth_mode, tags
                FROM accounts
                WHERE email_id = ?
                LIMIT 1
                """,
                (normalized_email,)
            ).fetchone()

        if not row:
            logger.warning(f"Account {normalized_email} not found in PostgreSQL")
            raise HTTPException(status_code=404, detail=f"Account {normalized_email} not found")

        return row_to_credentials(row)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error getting account credentials for {email_id} from PostgreSQL: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


async def save_account_credentials(email_id: str, credentials: AccountCredentials) -> None:
    """保存账户凭证到PostgreSQL"""
    try:
        normalized_email = normalize_email(email_id)
        if not normalized_email:
            raise HTTPException(status_code=400, detail="Invalid email_id")

        normalized_auth_mode = normalize_auth_mode(credentials.auth_mode, default="imap")
        mailbox_password = (credentials.mailbox_password or "").strip()
        tags_json = serialize_tags(credentials.tags if hasattr(credentials, "tags") else [])
        now_ts = int(time.time())
        default_rt_expires_at = now_ts + DEFAULT_ACCOUNT_RT_TTL_SECONDS

        with get_db_connection() as conn:
            existing = conn.execute(
                """
                SELECT mailbox_password, refresh_token, access_token_expires_at,
                       refresh_token_expires_at, token_last_refreshed_at
                FROM accounts
                WHERE email_id = ?
                LIMIT 1
                """,
                (normalized_email,)
            ).fetchone()

            if not mailbox_password and existing and existing["mailbox_password"]:
                mailbox_password = existing["mailbox_password"]

            access_token_expires_at = safe_int(existing["access_token_expires_at"]) if existing else None
            token_last_refreshed_at = safe_int(existing["token_last_refreshed_at"]) if existing else None
            existing_rt_expires_at = safe_int(existing["refresh_token_expires_at"]) if existing else None
            existing_refresh_token = str(existing["refresh_token"]) if existing else None

            if existing_refresh_token and existing_refresh_token == credentials.refresh_token and existing_rt_expires_at:
                refresh_token_expires_at = existing_rt_expires_at
            else:
                refresh_token_expires_at = default_rt_expires_at

            if existing:
                conn.execute(
                    """
                    UPDATE accounts
                    SET mailbox_password = ?, refresh_token = ?, client_id = ?, auth_mode = ?, tags = ?,
                        access_token_expires_at = ?, refresh_token_expires_at = ?, token_last_refreshed_at = ?,
                        updated_at = datetime('now')
                    WHERE email_id = ?
                    """,
                    (
                        mailbox_password,
                        credentials.refresh_token,
                        credentials.client_id,
                        normalized_auth_mode,
                        tags_json,
                        access_token_expires_at,
                        refresh_token_expires_at,
                        token_last_refreshed_at,
                        normalized_email
                    )
                )
            else:
                conn.execute(
                    """
                    INSERT INTO accounts (
                        email_id, mailbox_password, refresh_token, client_id, auth_mode, tags,
                        access_token_expires_at, refresh_token_expires_at, token_last_refreshed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        normalized_email,
                        mailbox_password,
                        credentials.refresh_token,
                        credentials.client_id,
                        normalized_auth_mode,
                        tags_json,
                        access_token_expires_at,
                        refresh_token_expires_at,
                        token_last_refreshed_at
                    )
                )
            conn.commit()

        # 凭证被修改后，清理旧AT缓存，避免继续使用过时token
        clear_cached_access_token(normalized_email, "imap")
        clear_cached_access_token(normalized_email, "graph")
        logger.info(f"Account credentials saved to PostgreSQL for {normalized_email}")
    except Exception as e:
        logger.error(f"Error saving account credentials to PostgreSQL: {e}")
        raise HTTPException(status_code=500, detail="Failed to save account")


async def get_all_accounts(
    page: int = 1, 
    page_size: int = 10, 
    email_search: Optional[str] = None,
    tag_search: Optional[str] = None
) -> AccountListResponse:
    """获取所有已加载的邮箱账户列表，支持分页和搜索"""
    try:
        where_conditions = ["1=1"]
        where_params: List[str] = []

        if email_search:
            where_conditions.append("email_id LIKE ?")
            where_params.append(f"%{email_search.strip().lower()}%")

        if tag_search:
            where_conditions.append("LOWER(tags) LIKE ?")
            where_params.append(f"%{tag_search.strip().lower()}%")

        where_sql = " AND ".join(where_conditions)
        offset = (page - 1) * page_size

        with get_db_connection() as conn:
            total_accounts = conn.execute(
                f"SELECT COUNT(*) AS total FROM accounts WHERE {where_sql}",
                where_params
            ).fetchone()["total"]

            rows = conn.execute(
                f"""
                SELECT email_id, mailbox_password, refresh_token, client_id, auth_mode, tags,
                       access_token_expires_at, refresh_token_expires_at
                FROM accounts
                WHERE {where_sql}
                ORDER BY updated_at DESC
                LIMIT ? OFFSET ?
                """,
                where_params + [page_size, offset]
            ).fetchall()

        total_pages = (total_accounts + page_size - 1) // page_size if total_accounts > 0 else 0
        now_ts = int(time.time())

        paginated_accounts: List[AccountInfo] = []
        for row in rows:
            rt_expires_at = safe_int(row["refresh_token_expires_at"])
            status = resolve_account_status(
                refresh_token=row["refresh_token"],
                client_id=row["client_id"],
                refresh_token_expires_at=rt_expires_at,
                now_ts=now_ts
            )

            paginated_accounts.append(
                AccountInfo(
                    email_id=row["email_id"],
                    client_id=row["client_id"],
                    auth_mode=normalize_auth_mode(row["auth_mode"], default="imap"),
                    status=status,
                    tags=parse_tags(row["tags"]),
                    access_token_expires_at=datetime_to_utc_iso(safe_int(row["access_token_expires_at"])),
                    refresh_token_expires_at=datetime_to_utc_iso(rt_expires_at)
                )
            )

        return AccountListResponse(
            total_accounts=total_accounts,
            page=page,
            page_size=page_size,
            total_pages=total_pages,
            accounts=paginated_accounts
        )

    except Exception as e:
        logger.error(f"Error getting accounts list from PostgreSQL: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


async def get_account_detail(email_id: str) -> AccountDetailResponse:
    """获取单个账户的完整可编辑信息。"""
    normalized_email = normalize_email(email_id)
    if not normalized_email:
        raise HTTPException(status_code=400, detail="Invalid email_id")

    try:
        with get_db_connection() as conn:
            row = conn.execute(
                """
                SELECT email_id, mailbox_password, refresh_token, client_id, auth_mode, tags,
                       access_token_expires_at, refresh_token_expires_at
                FROM accounts
                WHERE email_id = ?
                LIMIT 1
                """,
                (normalized_email,)
            ).fetchone()
    except Exception as e:
        logger.error(f"Failed to get account detail from PostgreSQL for {normalized_email}: {e}")
        raise HTTPException(status_code=500, detail="Failed to get account detail")

    if not row:
        raise HTTPException(status_code=404, detail=f"Account {normalized_email} not found")

    rt_expires_at = safe_int(row["refresh_token_expires_at"])
    normalized_mode = normalize_auth_mode(row["auth_mode"], default="imap")
    status = resolve_account_status(
        refresh_token=row["refresh_token"],
        client_id=row["client_id"],
        refresh_token_expires_at=rt_expires_at
    )
    cached_access_token, _ = get_cached_access_token(normalized_email, normalized_mode)

    return AccountDetailResponse(
        email_id=row["email_id"],
        mailbox_password=row["mailbox_password"] or None,
        refresh_token=row["refresh_token"],
        access_token=cached_access_token,
        client_id=row["client_id"],
        auth_mode=normalized_mode,
        status=status,
        tags=parse_tags(row["tags"]),
        access_token_expires_at=datetime_to_utc_iso(safe_int(row["access_token_expires_at"])),
        refresh_token_expires_at=datetime_to_utc_iso(rt_expires_at)
    )


async def update_account_detail(email_id: str, request: AccountUpdateRequest) -> AccountResponse:
    """更新单个账户的可编辑信息。"""
    normalized_email = normalize_email(email_id)
    if not normalized_email:
        raise HTTPException(status_code=400, detail="Invalid email_id")

    # 先确认账户存在，避免误更新。
    await get_account_credentials(normalized_email)

    refresh_token = (request.refresh_token or "").strip()
    client_id = (request.client_id or "").strip()
    if not refresh_token:
        raise HTTPException(status_code=400, detail="refresh_token is required")
    if not client_id:
        raise HTTPException(status_code=400, detail="client_id is required")

    mailbox_password = (request.mailbox_password or "").strip() or None
    tags = [str(tag).strip() for tag in (request.tags or []) if str(tag).strip()]
    desired_mode = normalize_auth_mode(request.auth_mode, default="auto")

    updated_credentials = AccountCredentials(
        email=normalized_email,
        mailbox_password=mailbox_password,
        refresh_token=refresh_token,
        client_id=client_id,
        auth_mode=desired_mode,
        tags=tags
    )

    resolved_mode = await resolve_account_auth_mode(updated_credentials)
    updated_credentials.auth_mode = resolved_mode
    await save_account_credentials(normalized_email, updated_credentials)

    # 尽快更新AT/RT时间，便于前台立即看到最新状态。
    try:
        await refresh_account_tokens_by_email(
            email_id=normalized_email,
            extend_refresh_expires_at=True,
            preferred_mode=resolved_mode
        )
    except Exception as refresh_error:
        logger.warning(f"Account token metadata refresh failed for {normalized_email}: {refresh_error}")

    return AccountResponse(
        email_id=normalized_email,
        message=f"Account updated successfully. mode={resolved_mode}"
    )


# ============================================================================
# OAuth2令牌管理模块
# ============================================================================

def get_payload_positive_int(payload: Dict[str, Any], keys: List[str], default_value: int) -> int:
    for key in keys:
        value = safe_int(payload.get(key))
        if value and value > 0:
            return value
    return default_value


def get_access_token_ttl_seconds(token_payload: Dict[str, Any]) -> int:
    ttl = get_payload_positive_int(token_payload, ["expires_in", "ext_expires_in"], DEFAULT_ACCESS_TOKEN_TTL_SECONDS)
    return max(60, ttl)


def get_refresh_token_ttl_seconds(token_payload: Dict[str, Any]) -> int:
    ttl = get_payload_positive_int(
        token_payload,
        ["refresh_token_expires_in", "refresh_expires_in", "refresh_token_ttl"],
        DEFAULT_ACCOUNT_RT_TTL_SECONDS
    )
    return max(60, ttl)


async def request_access_token_payload(credentials: AccountCredentials, auth_mode: str = "imap") -> Dict[str, Any]:
    """向微软令牌端点请求token原始响应。"""
    normalized_mode = normalize_auth_mode(auth_mode, default="imap")
    oauth_scope = get_scope_for_auth_mode(normalized_mode)

    token_request_data = {
        'client_id': credentials.client_id,
        'grant_type': 'refresh_token',
        'refresh_token': credentials.refresh_token,
        'scope': oauth_scope
    }

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(TOKEN_URL, data=token_request_data)
            response.raise_for_status()

            token_data = response.json()
            access_token = token_data.get('access_token')
            if not access_token:
                logger.error(f"No access token in response for {credentials.email} with mode={normalized_mode}")
                raise HTTPException(
                    status_code=401,
                    detail=f"Failed to obtain access token from response ({normalized_mode})"
                )

            logger.info(f"Successfully obtained access token for {credentials.email} with mode={normalized_mode}")
            return token_data

    except httpx.HTTPStatusError as e:
        error_code = None
        error_description = None
        response_preview = e.response.text[:800]

        try:
            error_payload = e.response.json()
            error_code = error_payload.get('error')
            error_description = error_payload.get('error_description')
        except Exception:
            error_payload = None

        logger.error(
            "HTTP %s error getting access token for %s (mode=%s, scope=%s): error=%s description=%s response=%s",
            e.response.status_code,
            credentials.email,
            normalized_mode,
            oauth_scope,
            error_code,
            error_description,
            response_preview
        )

        if e.response.status_code == 400:
            detail = f"Microsoft token endpoint rejected the request ({normalized_mode})"
            if error_code:
                detail += f": {error_code}"
            if error_description:
                detail += f" ({error_description})"
            raise HTTPException(status_code=401, detail=detail)
        raise HTTPException(status_code=401, detail=f"Authentication failed ({normalized_mode})")
    except httpx.RequestError as e:
        logger.error(f"Request error getting access token for {credentials.email} with mode={normalized_mode}: {e}")
        raise HTTPException(status_code=500, detail="Network error during token acquisition")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error getting access token for {credentials.email} with mode={normalized_mode}: {e}")
        raise HTTPException(status_code=500, detail="Token acquisition failed")


async def acquire_access_token_with_mode(
    credentials: AccountCredentials,
    requested_mode: str = "auto"
) -> Tuple[str, str, Dict[str, Any]]:
    """获取(access_token, 实际认证模式, token响应)。"""
    normalized_mode = normalize_auth_mode(requested_mode, default="auto")

    if normalized_mode in {"imap", "graph"}:
        payload = await request_access_token_payload(credentials, normalized_mode)
        return str(payload["access_token"]), normalized_mode, payload

    imap_error: Optional[HTTPException] = None
    try:
        payload = await request_access_token_payload(credentials, "imap")
        return str(payload["access_token"]), "imap", payload
    except HTTPException as e:
        imap_error = e

    try:
        payload = await request_access_token_payload(credentials, "graph")
        return str(payload["access_token"]), "graph", payload
    except HTTPException as graph_error:
        imap_detail = imap_error.detail if imap_error else "unknown"
        raise HTTPException(
            status_code=401,
            detail=f"IMAP verification failed: {imap_detail}; Graph verification failed: {graph_error.detail}"
        )


async def fetch_and_persist_access_token(
    credentials: AccountCredentials,
    requested_mode: str = "imap",
    extend_refresh_expires_at: bool = False
) -> Tuple[str, str, int]:
    """使用RT获取AT并写入数据库/缓存，返回(access_token, used_mode, access_expires_at)。"""
    access_token, used_mode, token_payload = await acquire_access_token_with_mode(credentials, requested_mode)
    if not access_token:
        raise HTTPException(status_code=500, detail="Failed to refresh token")

    now_ts = int(time.time())
    access_expires_at = now_ts + get_access_token_ttl_seconds(token_payload)
    refresh_token_value = token_payload.get("refresh_token")
    refresh_expires_at: Optional[int] = None

    if extend_refresh_expires_at or refresh_token_value:
        refresh_expires_at = now_ts + get_refresh_token_ttl_seconds(token_payload)

    if refresh_token_value:
        credentials.refresh_token = str(refresh_token_value)

    update_account_token_state(
        credentials.email,
        access_token_expires_at=access_expires_at,
        refresh_token_expires_at=refresh_expires_at,
        refresh_token=str(refresh_token_value) if refresh_token_value else None,
        auth_mode=used_mode,
        mark_refreshed=True
    )
    set_cached_access_token(str(credentials.email), used_mode, access_token, access_expires_at)
    return access_token, used_mode, access_expires_at


async def _background_refresh_access_token(email_id: str, auth_mode: str) -> None:
    normalized_mode = normalize_auth_mode(auth_mode, default="imap")
    cache_key = build_access_token_cache_key(email_id, normalized_mode)
    try:
        lock = get_access_token_refresh_lock(email_id, normalized_mode)
        async with lock:
            now_ts = int(time.time())
            cached_token, cached_expires_at = get_cached_access_token(email_id, normalized_mode)
            if cached_token and cached_expires_at and not should_background_refresh_access_token(cached_expires_at, now_ts):
                return

            latest_credentials = await get_account_credentials(email_id)
            await fetch_and_persist_access_token(
                latest_credentials,
                requested_mode=normalized_mode,
                extend_refresh_expires_at=False
            )
            logger.info(f"Background access token refresh completed for {normalize_email(email_id)} mode={normalized_mode}")
    except Exception as e:
        logger.warning(f"Background access token refresh failed for {normalize_email(email_id)} mode={normalized_mode}: {e}")
    finally:
        access_token_background_tasks.pop(cache_key, None)


def schedule_background_access_token_refresh(email_id: str, auth_mode: str) -> None:
    normalized_mode = normalize_auth_mode(auth_mode, default="imap")
    if normalized_mode not in {"imap", "graph"}:
        return

    cache_key = build_access_token_cache_key(email_id, normalized_mode)
    running_task = access_token_background_tasks.get(cache_key)
    if running_task and not running_task.done():
        return
    access_token_background_tasks[cache_key] = asyncio.create_task(
        _background_refresh_access_token(email_id, normalized_mode)
    )


async def get_access_token(credentials: AccountCredentials, auth_mode: str = "imap") -> str:
    """
    优先复用缓存AT；仅在快过期/已过期时使用RT刷新AT。
    """
    requested_mode = normalize_auth_mode(auth_mode, default="imap")

    if requested_mode not in {"imap", "graph"}:
        access_token, _, _ = await fetch_and_persist_access_token(
            credentials,
            requested_mode=requested_mode,
            extend_refresh_expires_at=False
        )
        return access_token

    now_ts = int(time.time())
    cached_token, cached_expires_at = get_cached_access_token(str(credentials.email), requested_mode)
    if cached_token and cached_expires_at and not should_force_refresh_access_token(cached_expires_at, now_ts):
        if should_background_refresh_access_token(cached_expires_at, now_ts):
            schedule_background_access_token_refresh(str(credentials.email), requested_mode)
        return cached_token

    refresh_lock = get_access_token_refresh_lock(str(credentials.email), requested_mode)
    async with refresh_lock:
        now_ts = int(time.time())
        cached_token, cached_expires_at = get_cached_access_token(str(credentials.email), requested_mode)
        if cached_token and cached_expires_at and not should_force_refresh_access_token(cached_expires_at, now_ts):
            if should_background_refresh_access_token(cached_expires_at, now_ts):
                schedule_background_access_token_refresh(str(credentials.email), requested_mode)
            return cached_token

        latest_credentials = await get_account_credentials(str(credentials.email))
        access_token, _, _ = await fetch_and_persist_access_token(
            latest_credentials,
            requested_mode=requested_mode,
            extend_refresh_expires_at=False
        )

        # 将数据库最新refresh_token回写到当前上下文对象，避免后续请求使用旧RT
        credentials.refresh_token = latest_credentials.refresh_token
        credentials.auth_mode = latest_credentials.auth_mode
        return access_token


async def resolve_account_auth_mode(credentials: AccountCredentials) -> str:
    """
    自动解析账户认证模式。
    auto模式下优先尝试IMAP，失败后回退Graph。
    """
    _, used_mode, _ = await acquire_access_token_with_mode(credentials, credentials.auth_mode)
    return used_mode


async def refresh_account_tokens_by_email(
    email_id: str,
    extend_refresh_expires_at: bool = True,
    preferred_mode: Optional[str] = None
) -> TokenRefreshAccountResponse:
    """刷新指定账户AT，按需刷新RT过期时间。"""
    credentials = await get_account_credentials(email_id)
    requested_mode = preferred_mode if preferred_mode else credentials.auth_mode
    _, used_mode, _ = await fetch_and_persist_access_token(
        credentials,
        requested_mode=requested_mode,
        extend_refresh_expires_at=extend_refresh_expires_at
    )

    stored_access_expires_at, stored_refresh_expires_at = get_account_token_expiry(credentials.email)
    return TokenRefreshAccountResponse(
        email_id=normalize_email(email_id),
        auth_mode=used_mode,
        access_token_expires_at=datetime_to_utc_iso(stored_access_expires_at),
        refresh_token_expires_at=datetime_to_utc_iso(stored_refresh_expires_at),
        message="Token refreshed successfully."
    )


async def refresh_all_accounts_tokens(extend_refresh_expires_at: bool = True) -> TokenRefreshAllResponse:
    """刷新所有账户的令牌。"""
    with get_db_connection() as conn:
        rows = conn.execute(
            "SELECT email_id, auth_mode FROM accounts ORDER BY updated_at DESC"
        ).fetchall()

    total_accounts = len(rows)
    success_count = 0
    failure_count = 0
    details: List[str] = []

    for row in rows:
        email_id = row["email_id"]
        auth_mode = normalize_auth_mode(row["auth_mode"], default="auto")
        try:
            await refresh_account_tokens_by_email(
                email_id=email_id,
                extend_refresh_expires_at=extend_refresh_expires_at,
                preferred_mode=auth_mode
            )
            success_count += 1
        except HTTPException as e:
            failure_count += 1
            details.append(f"{email_id}: {e.detail}")
        except Exception as e:
            failure_count += 1
            details.append(f"{email_id}: {str(e)}")

    message = f"Refreshed {success_count}/{total_accounts} account tokens."
    return TokenRefreshAllResponse(
        total_accounts=total_accounts,
        success_count=success_count,
        failure_count=failure_count,
        message=message,
        details=details
    )


# ============================================================================
# 邮件核心服务 - IMAP / Graph
# ============================================================================

async def list_emails_imap(
    credentials: AccountCredentials,
    folder: str,
    page: int,
    page_size: int,
    force_refresh: bool = False
) -> EmailListResponse:
    """通过IMAP获取邮件列表"""
    cache_key = get_cache_key(credentials.email, "imap", folder, page, page_size)
    cached_result = get_cached_emails(cache_key, force_refresh)
    if cached_result:
        return cached_result

    access_token = await get_access_token(credentials, "imap")

    def _sync_list_emails():
        imap_client = None
        try:
            imap_client = imap_pool.get_connection(credentials.email, access_token)

            all_emails_data = []
            if folder == "inbox":
                folders_to_check = ["INBOX"]
            elif folder == "junk":
                folders_to_check = ["Junk"]
            else:
                folders_to_check = ["INBOX", "Junk"]

            for folder_name in folders_to_check:
                try:
                    imap_client.select(f'"{folder_name}"', readonly=True)
                    status, messages = imap_client.search(None, "ALL")
                    if status != 'OK' or not messages or not messages[0]:
                        continue

                    message_ids = messages[0].split()
                    message_ids.reverse()

                    for msg_id in message_ids:
                        all_emails_data.append({
                            "message_id_raw": msg_id,
                            "folder": folder_name
                        })
                except Exception as e:
                    logger.warning(f"Failed to access folder {folder_name}: {e}")
                    continue

            total_emails = len(all_emails_data)
            start_index = (page - 1) * page_size
            end_index = start_index + page_size
            paginated_email_meta = all_emails_data[start_index:end_index]

            email_items = []
            paginated_email_meta.sort(key=lambda x: x['folder'])

            for folder_name, group in groupby(paginated_email_meta, key=lambda x: x['folder']):
                try:
                    imap_client.select(f'"{folder_name}"', readonly=True)
                    msg_ids_to_fetch = [item['message_id_raw'] for item in group]
                    if not msg_ids_to_fetch:
                        continue

                    msg_id_sequence = b','.join(msg_ids_to_fetch)
                    status, msg_data = imap_client.fetch(
                        msg_id_sequence,
                        '(FLAGS BODY.PEEK[HEADER.FIELDS (SUBJECT DATE FROM MESSAGE-ID)])'
                    )
                    if status != 'OK':
                        continue

                    for i in range(0, len(msg_data), 2):
                        if not isinstance(msg_data[i], tuple) or len(msg_data[i]) < 2:
                            continue

                        header_data = msg_data[i][1]
                        match = re.match(rb'(\d+)\s+\(', msg_data[i][0])
                        if not match:
                            continue
                        fetched_msg_id = match.group(1)

                        msg = email.message_from_bytes(header_data)
                        subject = decode_header_value(msg.get('Subject', '(No Subject)'))
                        from_email = decode_header_value(msg.get('From', '(Unknown Sender)'))
                        date_str = msg.get('Date', '')

                        try:
                            date_obj = parsedate_to_datetime(date_str) if date_str else datetime.now()
                            formatted_date = date_obj.isoformat()
                        except Exception:
                            formatted_date = datetime.now().isoformat()

                        sender_initial = "?"
                        if from_email:
                            email_match = re.search(r'([a-zA-Z])', from_email)
                            if email_match:
                                sender_initial = email_match.group(1).upper()

                        email_items.append(
                            EmailItem(
                                message_id=f"{folder_name}-{fetched_msg_id.decode()}",
                                folder=folder_name,
                                subject=subject,
                                from_email=from_email,
                                date=formatted_date,
                                is_read=False,
                                has_attachments=False,
                                sender_initial=sender_initial
                            )
                        )

                except Exception as e:
                    logger.warning(f"Failed to fetch bulk emails from {folder_name}: {e}")
                    continue

            email_items.sort(key=lambda x: x.date, reverse=True)
            imap_pool.return_connection(credentials.email, imap_client)

            result = EmailListResponse(
                email_id=credentials.email,
                folder_view=folder,
                page=page,
                page_size=page_size,
                total_emails=total_emails,
                emails=email_items
            )
            set_cached_emails(cache_key, result)
            return result

        except Exception as e:
            logger.error(f"Error listing IMAP emails: {e}")
            if imap_client:
                try:
                    if hasattr(imap_client, 'state') and imap_client.state != 'LOGOUT':
                        imap_pool.return_connection(credentials.email, imap_client)
                except Exception:
                    pass
            raise HTTPException(status_code=500, detail="Failed to retrieve emails")

    return await asyncio.to_thread(_sync_list_emails)


async def list_emails_graph(
    credentials: AccountCredentials,
    folder: str,
    page: int,
    page_size: int,
    force_refresh: bool = False
) -> EmailListResponse:
    """通过Graph API获取邮件列表"""
    cache_key = get_cache_key(credentials.email, "graph", folder, page, page_size)
    cached_result = get_cached_emails(cache_key, force_refresh)
    if cached_result:
        return cached_result

    access_token = await get_access_token(credentials, "graph")
    headers = {"Authorization": f"Bearer {access_token}"}
    folders = get_graph_folders_by_view(folder)
    email_items: List[EmailItem] = []
    total_emails = 0

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            for folder_label, folder_id in folders:
                # 获取文件夹总数
                folder_info_url = f"{GRAPH_API_BASE}/me/mailFolders/{folder_id}"
                folder_info_resp = await client.get(
                    folder_info_url,
                    headers=headers,
                    params={"$select": "totalItemCount"}
                )
                if folder_info_resp.status_code == 404:
                    continue
                folder_info_resp.raise_for_status()
                folder_info = folder_info_resp.json()
                total_emails += int(folder_info.get("totalItemCount", 0))

                if folder == "all":
                    query_top = min(max(page * page_size, page_size), 500)
                    query_skip = 0
                else:
                    query_top = min(page_size, 500)
                    query_skip = max((page - 1) * page_size, 0)

                messages_url = f"{GRAPH_API_BASE}/me/mailFolders/{folder_id}/messages"
                response = await client.get(
                    messages_url,
                    headers=headers,
                    params={
                        "$top": str(query_top),
                        "$skip": str(query_skip),
                        "$orderby": "receivedDateTime desc",
                        "$select": "id,subject,from,receivedDateTime,isRead,hasAttachments"
                    }
                )
                if response.status_code == 404:
                    continue
                response.raise_for_status()

                for message in response.json().get("value", []):
                    raw_message_id = message.get("id")
                    if not raw_message_id:
                        continue

                    from_email = (
                        message.get("from", {})
                        .get("emailAddress", {})
                        .get("address", "(Unknown Sender)")
                    )
                    sender_initial = "?"
                    email_match = re.search(r'([a-zA-Z])', from_email or "")
                    if email_match:
                        sender_initial = email_match.group(1).upper()

                    folder_display = "INBOX" if folder_label == "inbox" else "Junk"
                    received_at = message.get("receivedDateTime") or datetime.now().isoformat()

                    email_items.append(
                        EmailItem(
                            message_id=encode_graph_message_id(raw_message_id),
                            folder=folder_display,
                            subject=message.get("subject") or "(No Subject)",
                            from_email=from_email,
                            date=received_at,
                            is_read=bool(message.get("isRead", False)),
                            has_attachments=bool(message.get("hasAttachments", False)),
                            sender_initial=sender_initial
                        )
                    )

        email_items.sort(key=lambda x: x.date, reverse=True)

        if folder == "all":
            start_index = (page - 1) * page_size
            end_index = start_index + page_size
            email_items = email_items[start_index:end_index]

        result = EmailListResponse(
            email_id=credentials.email,
            folder_view=folder,
            page=page,
            page_size=page_size,
            total_emails=total_emails,
            emails=email_items
        )
        set_cached_emails(cache_key, result)
        return result
    except httpx.HTTPStatusError as e:
        logger.error(f"Graph API error listing emails for {credentials.email}: {e.response.status_code} {e.response.text[:800]}")
        if e.response.status_code in {401, 403}:
            raise HTTPException(status_code=401, detail="Graph authorization failed while retrieving emails")
        raise HTTPException(status_code=500, detail="Graph API request failed while retrieving emails")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected Graph error listing emails for {credentials.email}: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve emails")


async def list_emails(
    credentials: AccountCredentials,
    folder: str,
    page: int,
    page_size: int,
    force_refresh: bool = False
) -> EmailListResponse:
    """按账户认证模式获取邮件列表"""
    auth_mode = normalize_auth_mode(credentials.auth_mode, default="imap")
    if auth_mode == "graph":
        return await list_emails_graph(credentials, folder, page, page_size, force_refresh)
    return await list_emails_imap(credentials, folder, page, page_size, force_refresh)


async def get_email_details_imap(credentials: AccountCredentials, message_id: str) -> EmailDetailsResponse:
    """通过IMAP获取邮件详情"""
    try:
        folder_name, msg_id = message_id.split('-', 1)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid message_id format")

    access_token = await get_access_token(credentials, "imap")

    def _sync_get_email_details():
        imap_client = None
        try:
            imap_client = imap_pool.get_connection(credentials.email, access_token)
            imap_client.select(folder_name)
            status, msg_data = imap_client.fetch(msg_id, '(RFC822)')

            if status != 'OK' or not msg_data:
                raise HTTPException(status_code=404, detail="Email not found")

            raw_email = msg_data[0][1]
            msg = email.message_from_bytes(raw_email)

            subject = decode_header_value(msg.get('Subject', '(No Subject)'))
            from_email = decode_header_value(msg.get('From', '(Unknown Sender)'))
            to_email = decode_header_value(msg.get('To', '(Unknown Recipient)'))
            date_str = msg.get('Date', '')

            try:
                if date_str:
                    date_obj = parsedate_to_datetime(date_str)
                    formatted_date = date_obj.isoformat()
                else:
                    formatted_date = datetime.now().isoformat()
            except Exception:
                formatted_date = datetime.now().isoformat()

            body_plain, body_html = extract_email_content(msg)
            imap_pool.return_connection(credentials.email, imap_client)

            return EmailDetailsResponse(
                message_id=message_id,
                subject=subject,
                from_email=from_email,
                to_email=to_email,
                date=formatted_date,
                body_plain=body_plain if body_plain else None,
                body_html=body_html if body_html else None
            )

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error getting IMAP email details: {e}")
            if imap_client:
                try:
                    if hasattr(imap_client, 'state') and imap_client.state != 'LOGOUT':
                        imap_pool.return_connection(credentials.email, imap_client)
                except Exception:
                    pass
            raise HTTPException(status_code=500, detail="Failed to retrieve email details")

    return await asyncio.to_thread(_sync_get_email_details)


async def get_email_details_graph(credentials: AccountCredentials, message_id: str) -> EmailDetailsResponse:
    """通过Graph API获取邮件详情"""
    raw_message_id = decode_graph_message_id(message_id)
    access_token = await get_access_token(credentials, "graph")
    headers = {"Authorization": f"Bearer {access_token}"}

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(
                f"{GRAPH_MESSAGES_URL}/{quote(raw_message_id, safe='')}",
                headers=headers,
                params={
                    "$select": "id,subject,from,toRecipients,receivedDateTime,body"
                }
            )
            if response.status_code == 404:
                raise HTTPException(status_code=404, detail="Email not found")
            response.raise_for_status()
            data = response.json()

            from_email = (
                data.get("from", {})
                .get("emailAddress", {})
                .get("address", "(Unknown Sender)")
            )
            recipients = data.get("toRecipients") or []
            to_email = ", ".join(
                item.get("emailAddress", {}).get("address", "")
                for item in recipients
                if item.get("emailAddress", {}).get("address")
            ) or "(Unknown Recipient)"

            received_at = data.get("receivedDateTime") or datetime.now().isoformat()
            body_obj = data.get("body") or {}
            body_content = body_obj.get("content") or ""
            body_type = str(body_obj.get("contentType", "")).lower()

            if body_type == "html":
                body_html = body_content
                body_plain = None
            else:
                body_plain = body_content
                body_html = None

            return EmailDetailsResponse(
                message_id=message_id,
                subject=data.get("subject") or "(No Subject)",
                from_email=from_email,
                to_email=to_email,
                date=received_at,
                body_plain=body_plain,
                body_html=body_html
            )
    except httpx.HTTPStatusError as e:
        logger.error(f"Graph API error getting email details for {credentials.email}: {e.response.status_code} {e.response.text[:800]}")
        if e.response.status_code in {401, 403}:
            raise HTTPException(status_code=401, detail="Graph authorization failed while retrieving email detail")
        raise HTTPException(status_code=500, detail="Graph API request failed while retrieving email details")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected Graph error getting email details for {credentials.email}: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve email details")


async def get_email_details(credentials: AccountCredentials, message_id: str) -> EmailDetailsResponse:
    """按账户认证模式获取邮件详情"""
    auth_mode = normalize_auth_mode(credentials.auth_mode, default="imap")
    if auth_mode == "graph" or message_id.startswith("GRAPH-"):
        return await get_email_details_graph(credentials, message_id)
    return await get_email_details_imap(credentials, message_id)


def parse_temp_mail_datetime(timestamp_value: Any, created_at_value: Any) -> str:
    """将临时邮箱API时间字段标准化为ISO字符串。"""
    if isinstance(timestamp_value, (int, float)):
        try:
            return datetime.fromtimestamp(float(timestamp_value), tz=timezone.utc).isoformat()
        except Exception:
            pass

    if isinstance(timestamp_value, str) and timestamp_value.strip():
        try:
            return datetime.fromtimestamp(float(timestamp_value.strip()), tz=timezone.utc).isoformat()
        except Exception:
            pass

    if isinstance(created_at_value, str) and created_at_value.strip():
        raw_value = created_at_value.strip()
        try:
            return datetime.fromisoformat(raw_value.replace("Z", "+00:00")).isoformat()
        except Exception:
            return raw_value

    return datetime.now(timezone.utc).isoformat()


def parse_temp_mail_sort_timestamp(timestamp_value: Any, created_at_value: Any) -> float:
    """提取临时邮箱邮件排序时间戳。"""
    if isinstance(timestamp_value, (int, float)):
        return float(timestamp_value)

    if isinstance(timestamp_value, str) and timestamp_value.strip():
        try:
            return float(timestamp_value.strip())
        except Exception:
            pass

    if isinstance(created_at_value, str) and created_at_value.strip():
        try:
            return datetime.fromisoformat(created_at_value.strip().replace("Z", "+00:00")).timestamp()
        except Exception:
            return 0.0

    return 0.0


def parse_temp_mail_api_error(payload: Any, fallback: str = "Unknown error") -> str:
    """解析临时邮箱API返回错误信息。"""
    if isinstance(payload, dict):
        raw_error = payload.get("error")
        if isinstance(raw_error, str) and raw_error.strip():
            return raw_error.strip()
    return fallback


async def request_temp_mail_api(path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """请求 GPTMail 临时邮箱 API。"""
    if not TEMP_MAIL_API_BASE_URL:
        raise HTTPException(status_code=500, detail="Temporary mailbox API base URL is not configured")

    request_url = f"{TEMP_MAIL_API_BASE_URL}{path}"
    headers = {"Accept": "application/json"}
    if TEMP_MAIL_API_KEY:
        headers["X-API-Key"] = TEMP_MAIL_API_KEY

    try:
        async with httpx.AsyncClient(timeout=TEMP_MAIL_API_TIMEOUT_SECONDS) as client:
            response = await client.get(request_url, headers=headers, params=params)
    except httpx.RequestError as e:
        logger.error(f"Temporary mailbox API request error: {e}")
        raise HTTPException(status_code=502, detail="Failed to connect to temporary mailbox API")

    try:
        payload = response.json()
    except ValueError:
        logger.error(f"Temporary mailbox API returned invalid JSON: {response.text[:500]}")
        raise HTTPException(status_code=502, detail="Temporary mailbox API returned invalid JSON")

    if response.status_code >= 400:
        error_detail = parse_temp_mail_api_error(payload, response.reason_phrase or "HTTP error")
        mapped_status = response.status_code if response.status_code in {400, 401, 403, 404, 429} else 502
        raise HTTPException(
            status_code=mapped_status,
            detail=f"Temporary mailbox API request failed: {error_detail}"
        )

    if not isinstance(payload, dict):
        raise HTTPException(status_code=502, detail="Temporary mailbox API returned invalid payload")

    if payload.get("success") is False:
        error_detail = parse_temp_mail_api_error(payload, "API returned success=false")
        raise HTTPException(status_code=502, detail=f"Temporary mailbox API request failed: {error_detail}")

    data = payload.get("data")
    if not isinstance(data, dict):
        raise HTTPException(status_code=502, detail="Temporary mailbox API returned invalid data field")

    return data


async def list_emails_temp_mail(
    temp_email: str,
    folder: str,
    page: int,
    page_size: int,
    force_refresh: bool = False
) -> EmailListResponse:
    """从临时邮箱API获取邮件列表。"""
    normalized_email = normalize_email(temp_email)
    cache_key = get_cache_key(normalized_email, "temp-mail", folder, page, page_size)
    cached_result = get_cached_emails(cache_key, force_refresh)
    if cached_result:
        return cached_result

    if folder == "junk":
        empty_result = EmailListResponse(
            email_id=normalized_email,
            folder_view=folder,
            page=page,
            page_size=page_size,
            total_emails=0,
            emails=[]
        )
        set_cached_emails(cache_key, empty_result)
        return empty_result

    data = await request_temp_mail_api("/api/emails", params={"email": normalized_email})
    raw_emails = data.get("emails")
    if not isinstance(raw_emails, list):
        raise HTTPException(status_code=502, detail="Temporary mailbox API returned invalid emails format")

    sortable_items: List[Tuple[float, EmailItem]] = []
    for raw_item in raw_emails:
        if not isinstance(raw_item, dict):
            continue

        message_id = str(raw_item.get("id") or "").strip()
        if not message_id:
            continue

        from_email = str(raw_item.get("from_address") or "")
        sender_initial = "?"
        sender_match = re.search(r"([a-zA-Z])", from_email)
        if sender_match:
            sender_initial = sender_match.group(1).upper()

        timestamp_value = raw_item.get("timestamp")
        created_at_value = raw_item.get("created_at")
        normalized_date = parse_temp_mail_datetime(timestamp_value, created_at_value)
        sort_ts = parse_temp_mail_sort_timestamp(timestamp_value, created_at_value)

        sortable_items.append(
            (
                sort_ts,
                EmailItem(
                    message_id=message_id,
                    folder="INBOX",
                    subject=str(raw_item.get("subject") or "(No Subject)"),
                    from_email=from_email,
                    date=normalized_date,
                    is_read=bool(raw_item.get("is_read", False)),
                    has_attachments=bool(raw_item.get("has_attachments", False)),
                    sender_initial=sender_initial
                )
            )
        )

    sortable_items.sort(key=lambda item: item[0], reverse=True)
    all_items = [item for _, item in sortable_items]

    start_index = (page - 1) * page_size
    end_index = start_index + page_size
    paged_items = all_items[start_index:end_index]

    result = EmailListResponse(
        email_id=normalized_email,
        folder_view=folder,
        page=page,
        page_size=page_size,
        total_emails=len(all_items),
        emails=paged_items
    )
    set_cached_emails(cache_key, result)
    return result


async def get_email_details_temp_mail(message_id: str) -> EmailDetailsResponse:
    """从临时邮箱API获取单封邮件详情。"""
    normalized_message_id = str(message_id or "").strip()
    if not normalized_message_id:
        raise HTTPException(status_code=400, detail="Invalid temporary mailbox message_id")

    data = await request_temp_mail_api(f"/api/email/{quote(normalized_message_id, safe='')}")

    plain_content = data.get("content")
    html_content = data.get("html_content")

    body_plain = str(plain_content).strip() if plain_content is not None else ""
    body_html = str(html_content).strip() if html_content is not None else ""

    return EmailDetailsResponse(
        message_id=str(data.get("id") or normalized_message_id),
        subject=str(data.get("subject") or "(No Subject)"),
        from_email=str(data.get("from_address") or "(Unknown Sender)"),
        to_email=str(data.get("email_address") or "(Unknown Recipient)"),
        date=parse_temp_mail_datetime(data.get("timestamp"), data.get("created_at")),
        body_plain=body_plain or None,
        body_html=body_html or None
    )


async def run_refresh_all_accounts_with_lock(extend_refresh_expires_at: bool = True) -> TokenRefreshAllResponse:
    global token_refresh_run_lock
    if token_refresh_run_lock is None:
        token_refresh_run_lock = asyncio.Lock()
    async with token_refresh_run_lock:
        return await refresh_all_accounts_tokens(extend_refresh_expires_at=extend_refresh_expires_at)


async def maybe_run_scheduled_token_refresh() -> Optional[TokenRefreshAllResponse]:
    now_ts = int(time.time())
    with get_db_connection() as conn:
        row = get_token_refresh_settings_row(conn)
        enabled = bool(int(row["enabled"] or 0))
        if not enabled:
            return None

        interval_value = max(1, int(row["interval_value"] or 1))
        interval_unit = normalize_token_refresh_unit(row["interval_unit"])
        next_run_at = safe_int(row["next_run_at"])
        if next_run_at and next_run_at > now_ts:
            return None

    refresh_result = await run_refresh_all_accounts_with_lock(extend_refresh_expires_at=True)
    mark_token_refresh_run_completed(interval_value, interval_unit, enabled=True)
    return refresh_result


async def token_refresh_scheduler_loop(stop_event: asyncio.Event) -> None:
    """后台定时任务：到点自动刷新全部账户RT。"""
    logger.info("Token refresh scheduler started.")
    try:
        while not stop_event.is_set():
            try:
                await maybe_run_scheduled_token_refresh()
            except Exception as e:
                logger.error(f"Token refresh scheduler error: {e}")

            try:
                await asyncio.wait_for(stop_event.wait(), timeout=max(5, TOKEN_REFRESH_SCHEDULER_CHECK_SECONDS))
            except asyncio.TimeoutError:
                continue
    finally:
        logger.info("Token refresh scheduler stopped.")


# ============================================================================
# FastAPI应用和API端点
# ============================================================================

@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncGenerator[None, None]:
    """
    FastAPI应用生命周期管理

    处理应用启动和关闭时的资源管理
    """
    # 应用启动
    logger.info("Starting Outlook Email Management System...")
    init_account_db()
    logger.info("PostgreSQL schema initialization completed")
    init_redis_cache_client()
    if ADMIN_PASSWORD == "change_me_admin_password":
        logger.warning("ADMIN_PASSWORD is using default value. Please set ADMIN_PASSWORD in environment.")
    logger.info(f"IMAP connection pool initialized with max_connections={MAX_CONNECTIONS}")
    global token_refresh_scheduler_task, token_refresh_scheduler_stop_event, token_refresh_run_lock
    token_refresh_run_lock = asyncio.Lock()
    token_refresh_scheduler_stop_event = asyncio.Event()
    token_refresh_scheduler_task = asyncio.create_task(token_refresh_scheduler_loop(token_refresh_scheduler_stop_event))

    yield

    # 应用关闭
    logger.info("Shutting down Outlook Email Management System...")
    if token_refresh_scheduler_stop_event:
        token_refresh_scheduler_stop_event.set()
    if token_refresh_scheduler_task:
        try:
            await token_refresh_scheduler_task
        except Exception:
            pass
    for background_task in list(access_token_background_tasks.values()):
        if background_task and not background_task.done():
            background_task.cancel()
    access_token_background_tasks.clear()
    access_token_cache.clear()
    access_token_refresh_locks.clear()
    if redis_client:
        try:
            redis_client.close()
        except Exception:
            pass
    logger.info("Closing IMAP connection pool...")
    imap_pool.close_all_connections()
    logger.info("Application shutdown complete.")


app = FastAPI(
    title="Outlook邮件API服务",
    description="基于FastAPI，支持IMAP和Microsoft Graph的高性能邮件管理系统",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 挂载静态文件服务
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.middleware("http")
async def admin_auth_middleware(request: Request, call_next):
    """管理员鉴权中间件：使用 refresh_token + access_token 双token校验"""
    if request.method.upper() == "OPTIONS":
        return await call_next(request)

    path = request.url.path
    if not is_admin_protected_path(path):
        return await call_next(request)

    access_token = request.cookies.get(ADMIN_ACCESS_COOKIE_NAME, "")
    refresh_token = request.cookies.get(ADMIN_REFRESH_COOKIE_NAME, "")

    if not access_token or not refresh_token:
        response = build_admin_unauthorized_response(path)
        clear_admin_auth_cookies(response)
        return response

    try:
        is_valid, rotated_access_token = validate_admin_token_pair(access_token, refresh_token)
    except Exception as e:
        logger.error(f"Failed to validate admin session: {e}")
        if is_admin_html_path(path):
            return RedirectResponse(url="/admin", status_code=303)
        return JSONResponse(status_code=500, content={"detail": "Admin authentication error"})

    if not is_valid:
        response = build_admin_unauthorized_response(path)
        clear_admin_auth_cookies(response)
        return response

    response = await call_next(request)
    if rotated_access_token:
        set_admin_auth_cookies(response, rotated_access_token, refresh_token)
    return response

@app.get("/accounts", response_model=AccountListResponse)
async def get_accounts(
    page: int = Query(1, ge=1, description="页码，从1开始"),
    page_size: int = Query(10, ge=1, le=100, description="每页数量，范围1-100"),
    email_search: Optional[str] = Query(None, description="邮箱账号模糊搜索"),
    tag_search: Optional[str] = Query(None, description="标签模糊搜索")
):
    """获取所有已加载的邮箱账户列表，支持分页和搜索"""
    return await get_all_accounts(page, page_size, email_search, tag_search)


@app.get("/accounts/{email_id}", response_model=AccountDetailResponse)
async def get_account(email_id: str):
    """获取单个账户完整信息。"""
    return await get_account_detail(email_id)


@app.put("/accounts/{email_id}", response_model=AccountResponse)
async def update_account(email_id: str, request: AccountUpdateRequest):
    """更新单个账户信息。"""
    try:
        return await update_account_detail(email_id, request)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating account {email_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to update account")


@app.get("/token-refresh/settings", response_model=TokenRefreshSettingsResponse)
async def get_rt_refresh_settings():
    """获取RT定时刷新配置。"""
    return get_token_refresh_settings()


@app.put("/token-refresh/settings", response_model=TokenRefreshSettingsResponse)
async def update_rt_refresh_settings(request: TokenRefreshSettingsUpdateRequest):
    """更新RT定时刷新配置。"""
    return set_token_refresh_settings(
        enabled=request.enabled,
        interval_value=request.interval_value,
        interval_unit=request.interval_unit
    )


@app.post("/token-refresh/refresh-all", response_model=TokenRefreshAllResponse)
async def refresh_all_rt_tokens():
    """立即刷新所有账户RT/AT。"""
    result = await run_refresh_all_accounts_with_lock(extend_refresh_expires_at=True)

    settings = get_token_refresh_settings()
    if settings.enabled:
        mark_token_refresh_run_completed(
            interval_value=settings.interval_value,
            interval_unit=settings.interval_unit,
            enabled=True
        )
    return result


@app.post("/accounts", response_model=AccountResponse)
async def register_account(credentials: AccountCredentials):
    """注册或更新邮箱账户"""
    try:
        # 验证凭证并解析认证模式
        resolved_mode = await resolve_account_auth_mode(credentials)
        credentials.auth_mode = resolved_mode

        # 保存凭证
        await save_account_credentials(credentials.email, credentials)

        # 初始化AT/RT过期时间（不阻断注册流程）
        try:
            await refresh_account_tokens_by_email(
                email_id=str(credentials.email),
                extend_refresh_expires_at=True,
                preferred_mode=resolved_mode
            )
        except Exception as refresh_error:
            logger.warning(f"Account token metadata initialization failed for {credentials.email}: {refresh_error}")

        return AccountResponse(
            email_id=credentials.email,
            message=f"Account verified and saved successfully. mode={resolved_mode}"
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error registering account: {e}")
        raise HTTPException(status_code=500, detail="Account registration failed")


@app.get("/emails/{email_id}", response_model=EmailListResponse)
async def get_emails(
    email_id: str,
    folder: str = Query("all", pattern="^(inbox|junk|all)$"),
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=500),
    refresh: bool = Query(False, description="强制刷新缓存")
):
    """获取邮件列表"""
    credentials = await get_account_credentials(email_id)
    return await list_emails(credentials, folder, page, page_size, refresh)


@app.get("/emails/{email_id}/dual-view")
async def get_dual_view_emails(
    email_id: str,
    inbox_page: int = Query(1, ge=1),
    junk_page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100)
):
    """获取双栏视图邮件（收件箱和垃圾箱）"""
    credentials = await get_account_credentials(email_id)
    
    # 并行获取收件箱和垃圾箱邮件
    inbox_response = await list_emails(credentials, "inbox", inbox_page, page_size)
    junk_response = await list_emails(credentials, "junk", junk_page, page_size)
    
    return DualViewEmailResponse(
        email_id=email_id,
        inbox_emails=inbox_response.emails,
        junk_emails=junk_response.emails,
        inbox_total=inbox_response.total_emails,
        junk_total=junk_response.total_emails
    )


@app.put("/accounts/{email_id}/tags", response_model=AccountResponse)
async def update_account_tags(email_id: str, request: UpdateTagsRequest):
    """更新账户标签"""
    try:
        # 检查账户是否存在
        credentials = await get_account_credentials(email_id)
        
        # 更新标签
        credentials.tags = request.tags
        
        # 保存更新后的凭证
        await save_account_credentials(email_id, credentials)
        
        return AccountResponse(
            email_id=email_id,
            message="Account tags updated successfully."
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating account tags: {e}")
        raise HTTPException(status_code=500, detail="Failed to update account tags")


@app.post("/accounts/{email_id}/refresh-token", response_model=TokenRefreshAccountResponse)
async def refresh_single_account_token(email_id: str):
    """刷新单个账户RT/AT。"""
    try:
        normalized_email = normalize_email(email_id)
        return await refresh_account_tokens_by_email(
            email_id=normalized_email,
            extend_refresh_expires_at=True
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error refreshing token for {email_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to refresh account token")


@app.get("/emails/{email_id}/{message_id}", response_model=EmailDetailsResponse)
async def get_email_detail(email_id: str, message_id: str):
    """获取邮件详细内容"""
    credentials = await get_account_credentials(email_id)
    return await get_email_details(credentials, message_id)

@app.delete("/accounts/{email_id}", response_model=AccountResponse)
async def delete_account(email_id: str):
    """删除邮箱账户"""
    try:
        normalized_email = normalize_email(email_id)
        with get_db_connection() as conn:
            cursor = conn.execute(
                "DELETE FROM accounts WHERE email_id = ?",
                (normalized_email,)
            )
            conn.commit()

        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Account not found")

        clear_cached_access_token(normalized_email, "imap")
        clear_cached_access_token(normalized_email, "graph")
        return AccountResponse(
            email_id=normalized_email,
            message="Account deleted successfully."
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting account from PostgreSQL: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete account")


def parse_web_credential_path(credential_path: str) -> tuple[str, str]:
    """解析 /web/{邮箱----密码} 路径参数"""
    parts = credential_path.split("----", 1)
    if len(parts) != 2:
        raise HTTPException(
            status_code=400,
            detail="Invalid web path format. Use /web/{email}----{mailbox_password}"
        )

    email_id = parts[0].strip()
    mailbox_password = parts[1].strip()
    if not email_id or not mailbox_password:
        raise HTTPException(
            status_code=400,
            detail="Invalid web path format. Email and mailbox password are required"
        )

    return email_id, mailbox_password


async def get_web_account_credentials(credential_path: str) -> AccountCredentials:
    """按 /web/{邮箱----密码} 从数据库获取账户凭证"""
    email_id, mailbox_password = parse_web_credential_path(credential_path)
    credentials = get_account_credentials_by_email_and_password(email_id, mailbox_password)
    if not credentials:
        raise HTTPException(
            status_code=404,
            detail=f"Account not found in database for {email_id}"
        )
    return credentials


def parse_web_temp_email_path(credential_path: str) -> str:
    """解析 /web/{temporary_email} 路径参数。"""
    email_id = normalize_email(credential_path)
    if not email_id or not TEMP_MAIL_EMAIL_PATTERN.match(email_id):
        raise HTTPException(
            status_code=400,
            detail="Invalid web path format. Use /web/{email}----{mailbox_password} or /web/{temporary_email}"
        )
    return email_id


async def resolve_web_mailbox_source(
    credential_path: str
) -> tuple[str, str, Optional[AccountCredentials], str]:
    """
    解析 /web 路径来源。

    Returns:
        source_type: outlook | temp
        mailbox_email: 邮箱地址
        credentials: Outlook凭证（仅outlook来源时有值）
        normalized_path_for_links: 生成链接时使用的路径字符串
    """
    normalized_path = (credential_path or "").strip()
    if not normalized_path:
        raise HTTPException(
            status_code=400,
            detail="Invalid web path format. Credential path is required"
        )

    if "----" in normalized_path:
        credentials = await get_web_account_credentials(normalized_path)
        return "outlook", str(credentials.email), credentials, normalized_path

    temp_email = parse_web_temp_email_path(normalized_path)
    return "temp", temp_email, None, temp_email


async def fetch_web_mailbox_email_response(
    source_type: str,
    mailbox_email: str,
    credentials: Optional[AccountCredentials],
    folder: str,
    page: int,
    page_size: int,
    force_refresh: bool = False
) -> EmailListResponse:
    """按 /web 来源获取邮件列表。"""
    if source_type == "temp":
        return await list_emails_temp_mail(mailbox_email, folder, page, page_size, force_refresh)

    if not credentials:
        raise HTTPException(status_code=500, detail="Web mailbox credentials resolve failed")

    return await list_emails(credentials, folder, page, page_size, force_refresh)


def build_web_mailbox_signature(source_type: str, email_response: EmailListResponse) -> str:
    """构建网页邮箱轮询签名，用于判断是否有新邮件。"""
    top_message_ids = "|".join(item.message_id for item in email_response.emails[:5])
    base = f"{source_type}|{email_response.folder_view}|{email_response.total_emails}|{top_message_ids}"
    return hashlib.sha256(base.encode("utf-8")).hexdigest()


@app.get("/web/{credential_path}", response_class=HTMLResponse)
async def web_mailbox(
    credential_path: str,
    folder: str = Query("all", pattern="^(inbox|junk|all)$"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    refresh: bool = Query(False)
):
    """
    Web快速查看邮箱。
    访问路径示例：
    - /web/user@outlook.com----mailbox_password
    - /web/temporary@mail.chatgpt.org.uk
    """
    source_type, mailbox_email, credentials, path_for_links = await resolve_web_mailbox_source(credential_path)
    email_response = await fetch_web_mailbox_email_response(
        source_type=source_type,
        mailbox_email=mailbox_email,
        credentials=credentials,
        folder=folder,
        page=page,
        page_size=page_size,
        force_refresh=refresh
    )
    source_chip = (
        "来源：GPTMail 临时邮箱API"
        if source_type == "temp"
        else f"认证模式：{normalize_auth_mode(credentials.auth_mode if credentials else 'imap').upper()}"
    )

    encoded_credential = quote(path_for_links, safe="")
    sse_url_js = json.dumps(
        f"/web/{encoded_credential}/events?folder={folder}&page_size={page_size}",
        ensure_ascii=False
    )
    tab_links = [
        ("all", "全部"),
        ("inbox", "收件箱"),
        ("junk", "垃圾箱")
    ]
    tabs_html = "".join(
        f'<a class="wm-tab{" active" if folder == tab_folder else ""}" '
        f'href="/web/{encoded_credential}?folder={tab_folder}&page=1&page_size={page_size}">{tab_label}</a>'
        for tab_folder, tab_label in tab_links
    )

    rows = []
    for item in email_response.emails:
        detail_url = f"/web/{encoded_credential}/detail/{quote(item.message_id, safe='')}"
        rows.append(
            "<tr>"
            f"<td>{escape(item.folder)}</td>"
            f"<td><a class='wm-subject-link' href='{detail_url}'>{escape(item.subject or '(无主题)')}</a></td>"
            f"<td>{escape(item.from_email or '')}</td>"
            f"<td>{escape(item.date or '')}</td>"
            "</tr>"
        )

    rows_html = "".join(rows) if rows else "<tr><td colspan='4' class='wm-empty'>暂无邮件</td></tr>"
    prev_page = page - 1 if page > 1 else 1
    next_page = page + 1

    html_content = f"""
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>{escape(mailbox_email)} 邮件预览</title>
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link href="https://fonts.googleapis.com/css2?family=Manrope:wght@400;500;600;700;800&family=Outfit:wght@600;700;800&display=swap" rel="stylesheet" />
  <link rel="stylesheet" href="/static/web-mail-view.css" />
</head>
<body class="webmail-page">
  <div class="wm-shell">
    <div class="wm-topbar">
      <h2 class="wm-title">邮箱：{escape(mailbox_email)}</h2>
      <div class="wm-topbar-actions">
        <button id="wmManualRefreshBtn" class="wm-pager-btn wm-refresh-btn" type="button">手动刷新</button>
        <span id="wmRealtimeStatus" class="wm-chip">实时监听初始化中...</span>
        <span class="wm-chip">{escape(source_chip)}</span>
      </div>
    </div>
    <div class="wm-tabs">{tabs_html}</div>
    <div class="wm-table-wrap">
      <table class="wm-table">
        <thead>
          <tr>
            <th>文件夹</th>
            <th>主题</th>
            <th>发件人</th>
            <th>时间</th>
          </tr>
        </thead>
        <tbody>
          {rows_html}
        </tbody>
      </table>
    </div>
    <div class="wm-pager">
      <a class="wm-pager-btn" href="/web/{encoded_credential}?folder={folder}&page={prev_page}&page_size={page_size}">上一页</a>
      <a class="wm-pager-btn" href="/web/{encoded_credential}?folder={folder}&page={next_page}&page_size={page_size}">下一页</a>
    </div>
  </div>
  <script>
    (() => {{
      const sseUrl = {sse_url_js};
      const manualRefreshBtn = document.getElementById("wmManualRefreshBtn");
      const realtimeStatus = document.getElementById("wmRealtimeStatus");
      let eventSource = null;
      let hasPendingNewMail = false;

      const buildRefreshUrl = () => {{
        const url = new URL(window.location.href);
        url.searchParams.set("refresh", "true");
        return url.toString();
      }};

      const refreshNow = () => {{
        window.location.replace(buildRefreshUrl());
      }};

      const setRealtimeStatus = (text) => {{
        if (realtimeStatus) {{
          realtimeStatus.textContent = text;
        }}
      }};

      if (manualRefreshBtn) {{
        manualRefreshBtn.addEventListener("click", refreshNow);
      }}

      if (typeof EventSource === "undefined") {{
        setRealtimeStatus("当前浏览器不支持实时推送");
        return;
      }}

      const closeRealtime = () => {{
        if (eventSource) {{
          eventSource.close();
          eventSource = null;
        }}
      }};

      setRealtimeStatus("实时监听中...");
      eventSource = new EventSource(sseUrl);

      eventSource.addEventListener("ready", (event) => {{
        try {{
          const payload = JSON.parse(event.data || "{{}}");
          const total = Number(payload.total_emails || 0);
          if (!hasPendingNewMail) {{
            setRealtimeStatus(`实时监听中（当前 ${{total}} 封）`);
          }}
        }} catch (_) {{
          if (!hasPendingNewMail) {{
            setRealtimeStatus("实时监听中...");
          }}
        }}
      }});

      eventSource.addEventListener("new_mail", () => {{
        hasPendingNewMail = true;
        setRealtimeStatus("检测到新邮件，点击“手动刷新”查看");
        if (manualRefreshBtn) {{
          manualRefreshBtn.classList.add("wm-refresh-pulse");
          manualRefreshBtn.textContent = "刷新查看新邮件";
        }}
      }});

      eventSource.addEventListener("error", () => {{
        if (!hasPendingNewMail) {{
          setRealtimeStatus("连接中断，正在重连...");
        }}
      }});

      window.addEventListener("beforeunload", closeRealtime);
      window.addEventListener("pagehide", closeRealtime);
    }})();
  </script>
</body>
</html>
"""
    return HTMLResponse(content=html_content)


@app.get("/web/{credential_path}/events")
async def web_mailbox_events(
    request: Request,
    credential_path: str,
    folder: str = Query("all", pattern="^(inbox|junk|all)$"),
    page_size: int = Query(20, ge=1, le=100)
):
    """Web邮箱实时事件流：每5秒轮询一次，仅在发现新邮件时推送事件。"""
    source_type, mailbox_email, credentials, _ = await resolve_web_mailbox_source(credential_path)
    probe_page_size = max(1, min(20, page_size))
    poll_interval_seconds = max(1, WEB_MAILBOX_SSE_POLL_SECONDS)

    async def event_stream() -> AsyncGenerator[str, None]:
        try:
            initial_response = await fetch_web_mailbox_email_response(
                source_type=source_type,
                mailbox_email=mailbox_email,
                credentials=credentials,
                folder=folder,
                page=1,
                page_size=probe_page_size,
                force_refresh=True
            )
        except HTTPException as e:
            payload = json.dumps({"detail": str(e.detail)}, ensure_ascii=False)
            yield f"event: error\ndata: {payload}\n\n"
            return
        except Exception as e:
            logger.error(f"Failed to initialize web mailbox SSE for {mailbox_email}: {e}")
            payload = json.dumps({"detail": "Failed to initialize realtime mailbox stream"}, ensure_ascii=False)
            yield f"event: error\ndata: {payload}\n\n"
            return

        previous_signature = build_web_mailbox_signature(source_type, initial_response)
        ready_payload = {
            "email_id": mailbox_email,
            "total_emails": initial_response.total_emails,
            "folder": folder
        }
        yield f"event: ready\ndata: {json.dumps(ready_payload, ensure_ascii=False)}\n\n"

        while True:
            if await request.is_disconnected():
                break

            await asyncio.sleep(poll_interval_seconds)

            if await request.is_disconnected():
                break

            try:
                latest_response = await fetch_web_mailbox_email_response(
                    source_type=source_type,
                    mailbox_email=mailbox_email,
                    credentials=credentials,
                    folder=folder,
                    page=1,
                    page_size=probe_page_size,
                    force_refresh=True
                )
                latest_signature = build_web_mailbox_signature(source_type, latest_response)
            except HTTPException as e:
                payload = json.dumps({"detail": str(e.detail)}, ensure_ascii=False)
                yield f"event: error\ndata: {payload}\n\n"
                continue
            except Exception as e:
                logger.error(f"Web mailbox SSE polling failed for {mailbox_email}: {e}")
                payload = json.dumps({"detail": "Realtime mailbox polling failed"}, ensure_ascii=False)
                yield f"event: error\ndata: {payload}\n\n"
                continue

            if latest_signature != previous_signature:
                latest_message_id = latest_response.emails[0].message_id if latest_response.emails else None
                latest_date = latest_response.emails[0].date if latest_response.emails else None
                payload = json.dumps(
                    {
                        "email_id": mailbox_email,
                        "folder": folder,
                        "total_emails": latest_response.total_emails,
                        "latest_message_id": latest_message_id,
                        "latest_date": latest_date
                    },
                    ensure_ascii=False
                )
                yield f"event: new_mail\ndata: {payload}\n\n"
                previous_signature = latest_signature
            else:
                yield ": ping\n\n"

        logger.info(f"Web mailbox SSE disconnected for {mailbox_email}")

    headers = {
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "X-Accel-Buffering": "no"
    }
    return StreamingResponse(event_stream(), media_type="text/event-stream", headers=headers)


@app.get("/web/{credential_path}/detail/{message_id:path}", response_class=HTMLResponse)
async def web_mailbox_detail(credential_path: str, message_id: str):
    """Web快速查看邮件详情。"""
    source_type, _, credentials, path_for_links = await resolve_web_mailbox_source(credential_path)
    if source_type == "temp":
        detail = await get_email_details_temp_mail(message_id)
    else:
        if not credentials:
            raise HTTPException(status_code=500, detail="Web mailbox credentials resolve failed")
        detail = await get_email_details(credentials, message_id)
    encoded_credential = quote(path_for_links, safe="")

    body_section = ""
    if detail.body_html:
        body_section = f"<div class='wmd-html-content'>{detail.body_html}</div>"
    else:
        body_section = f"<pre class='wmd-plain'>{escape(detail.body_plain or '')}</pre>"

    html_content = f"""
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>{escape(detail.subject or '(无主题)')}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link href="https://fonts.googleapis.com/css2?family=Manrope:wght@400;500;600;700;800&family=Outfit:wght@600;700;800&display=swap" rel="stylesheet" />
  <link rel="stylesheet" href="/static/web-mail-view.css" />
</head>
<body class="webmail-detail-page">
  <div class="wmd-shell">
    <div class="wmd-header">
      <a class="wmd-back-link" href="/web/{encoded_credential}">返回邮件列表</a>
      <h2 class="wmd-title">{escape(detail.subject or '(无主题)')}</h2>
      <p class="wmd-meta">发件人：{escape(detail.from_email or '')}</p>
      <p class="wmd-meta">收件人：{escape(detail.to_email or '')}</p>
      <p class="wmd-meta">时间：{escape(detail.date or '')}</p>
    </div>
    <div class="wmd-content">
      <div class="wmd-paper">
        {body_section}
      </div>
    </div>
  </div>
</body>
</html>
"""
    return HTMLResponse(content=html_content)


@app.get("/", response_class=HTMLResponse)
async def root():
    """根路径 - 邮箱密码登录并跳转到 /web/{邮箱----密码}"""
    html_content = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>邮箱登录</title>
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link href="https://fonts.googleapis.com/css2?family=Manrope:wght@400;500;600;700;800&family=Outfit:wght@600;700;800&display=swap" rel="stylesheet" />
  <link rel="stylesheet" href="/static/auth-pages.css" />
</head>
<body class="auth-page auth-page-web">
  <div class="auth-card">
    <div class="auth-chip"><span class="auth-dot"></span>Inbox Quick View</div>
    <h2>邮箱登录</h2>
    <p>输入邮箱和邮箱密码，登录后将跳转到邮件网页查看页。</p>
    <p class="auth-tip">临时邮箱可直接访问：/web/{临时邮箱地址}</p>
    <form class="auth-form" id="webLoginForm">
      <label for="email">邮箱地址</label>
      <input id="email" type="email" required placeholder="example@outlook.com" />
      <label for="password">邮箱密码</label>
      <input id="password" type="text" required placeholder="邮箱密码" />
      <button type="submit">登录并查看邮件</button>
    </form>
    <div class="auth-tip" id="tip">目标路径：/web/{邮箱----邮箱密码}</div>
  </div>

  <script>
    const form = document.getElementById("webLoginForm");
    const tip = document.getElementById("tip");

    form.addEventListener("submit", function (e) {
      e.preventDefault();
      const email = document.getElementById("email").value.trim();
      const password = document.getElementById("password").value.trim();
      if (!email || !password) {
        return;
      }
      const credential = `${email}----${password}`;
      tip.textContent = `目标路径：/web/${credential}`;
      window.location.href = `/web/${encodeURIComponent(credential)}`;
    });
  </script>
</body>
</html>
"""
    return HTMLResponse(content=html_content)


@app.get("/admin")
@app.get("/admin/")
async def admin_login():
    """后台管理登录页"""
    return HTMLResponse(content=render_admin_login_page())


@app.post("/admin/auth/login")
async def admin_login_submit(password: str = Form(...)):
    """管理员密码登录，签发双token"""
    if not verify_admin_password(password):
        return HTMLResponse(content=render_admin_login_page("管理员密码错误"), status_code=401)

    access_token, refresh_token = create_admin_session_tokens()
    response = RedirectResponse(url="/admin/panel", status_code=303)
    set_admin_auth_cookies(response, access_token, refresh_token)
    return response


@app.get("/admin/auth/logout")
@app.post("/admin/auth/logout")
async def admin_logout(request: Request):
    """管理员登出"""
    refresh_token = request.cookies.get(ADMIN_REFRESH_COOKIE_NAME)
    revoke_admin_session(refresh_token)
    response = RedirectResponse(url="/admin", status_code=303)
    clear_admin_auth_cookies(response)
    return response


@app.get("/admin/panel")
@app.get("/admin/panel/")
async def admin_panel():
    """后台管理系统入口（需鉴权）"""
    return FileResponse("static/index.html")

@app.delete("/cache/{email_id}")
async def clear_cache(email_id: str):
    """清除指定邮箱的缓存"""
    clear_email_cache(email_id)
    return {"message": f"Cache cleared for {email_id}"}

@app.delete("/cache")
async def clear_all_cache():
    """清除所有缓存"""
    clear_email_cache()
    return {"message": "All cache cleared"}

@app.get("/api")
async def api_status():
    """API状态检查"""
    return {
        "message": "Outlook邮件API服务正在运行（IMAP + Graph）",
        "version": "1.0.0",
        "endpoints": {
            "get_accounts": "GET /accounts",
            "register_account": "POST /accounts",
            "get_account": "GET /accounts/{email_id}",
            "update_account": "PUT /accounts/{email_id}",
            "get_token_refresh_settings": "GET /token-refresh/settings",
            "update_token_refresh_settings": "PUT /token-refresh/settings",
            "refresh_all_tokens": "POST /token-refresh/refresh-all",
            "refresh_single_account_token": "POST /accounts/{email_id}/refresh-token",
            "get_emails": "GET /emails/{email_id}?refresh=true",
            "get_dual_view_emails": "GET /emails/{email_id}/dual-view",
            "get_email_detail": "GET /emails/{email_id}/{message_id}",
            "clear_cache": "DELETE /cache/{email_id}",
            "clear_all_cache": "DELETE /cache"
        }
    }


# ============================================================================
# 启动配置
# ============================================================================

if __name__ == "__main__":
    import uvicorn

    # 启动配置
    HOST = "0.0.0.0"
    PORT = 8000

    logger.info(f"Starting Outlook Email Management System on {HOST}:{PORT}")
    logger.info("Access the web interface at: http://localhost:8000")
    logger.info("Access the API documentation at: http://localhost:8000/docs")

    uvicorn.run(
        app,
        host=HOST,
        port=PORT,
        log_level="info",
        access_log=True
    )
