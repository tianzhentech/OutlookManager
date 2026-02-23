// Global state
const API_BASE = '';
let currentAccount = null;
let openedEmailAccounts = [];
let accountLastUpdateMap = {};
let emailChildWindowAccount = null;
let isEmbedMode = new URLSearchParams(window.location.search).get('embed') === '1';
let currentEmailFolder = 'all';
let currentEmailPage = 1;
let accounts = [];

let accountsCurrentPage = 1;
let accountsPageSize = 10;
let accountsTotalPages = 0;
let accountsTotalCount = 0;
let currentEmailSearch = '';
let currentTagSearch = '';

let currentEditAccount = null;
let currentEditTags = [];
let currentAccountInfoEmail = null;

let allEmails = [];
let filteredEmails = [];
let searchTimeout = null;

let contextMenuTarget = null;

let tokenRefreshSettings = null;
let isRefreshingAllTokens = false;
let refreshingTokenAccountIds = new Set();
