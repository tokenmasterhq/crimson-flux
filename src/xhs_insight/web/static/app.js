(() => {
  "use strict";

  const API_BASE = (document.body.dataset.apiBase || "/api/v1").replace(/\/$/, "");
  const DETAIL_FIELDS = new Set(["body", "tags", "metrics", "media"]);
  const ACTIVE_STATUSES = new Set(["queued", "enumerating", "fetching_details", "exporting"]);
  const PAUSED_STATUSES = new Set([
    "paused_auth",
    "paused_rate_limit",
    "paused_interrupted",
    "cancelled",
  ]);
  const TERMINAL_STATUSES = new Set([
    "completed",
    "completed_with_warnings",
    "cancelled",
    "failed",
  ]);
  const BROWSER_LOGIN_ACTIVE = new Set([
    "starting",
    "awaiting_login",
    "verifying",
  ]);
  const BROWSER_LOGIN_LABELS = {
    starting: "正在打开",
    awaiting_login: "等待网页登录",
    verifying: "正在验证",
    succeeded: "登录成功",
    failed: "登录未完成",
    browser_closed: "登录会话已关闭",
    expired: "已超时",
    cancelled: "已取消",
    idle: "尚未开始",
  };
  const PRESET_LABELS = {
    basic: "快速版",
    full: "完整版",
    custom: "自己选择",
  };
  const TERMINATION_LABELS = {
    natural_end: "已经看到最后一页",
    reached_limit: "已经达到你设置的数量",
    source_exhausted: "没有更多结果",
    safety_cap: "达到本机设置的安全上限",
    pagination_stalled: "平台没有返回新的下一页",
    process_interrupted: "服务曾被中断",
    user_cancelled: "由你手动停止",
    no_records: "没有找到可保存的内容",
  };

  const STATUS_LABELS = {
    queued: "等待运行",
    enumerating: "正在查找内容",
    awaiting_detail_confirmation: "等你确认",
    fetching_details: "正在获取更多信息",
    exporting: "正在打包结果",
    completed: "已完成",
    completed_with_warnings: "已完成，部分信息缺失",
    paused_auth: "需要重新登录",
    paused_rate_limit: "访问过快，已暂停",
    paused_interrupted: "服务中断，已暂停",
    paused_cursor_invalid: "无法继续翻页，请重新创建",
    cancelled: "已取消",
    failed: "失败",
  };

  const state = {
    sourceType: "keyword",
    jobs: [],
    auth: null,
    health: null,
    browserLogin: null,
    limits: {
      keyword: 1000,
      user: 10000,
      pauseMinSeconds: 2,
      pauseMaxSeconds: 4,
    },
    jobsTimer: null,
    browserLoginTimer: null,
    browserLoginDeadlineMs: null,
    manualLoginAutoOpened: false,
    confirmJob: null,
    toastTimer: null,
    toastExitTimer: null,
  };

  const jobRenderSignatures = new WeakMap();
  const sourceTabsVertical = window.matchMedia("(max-width: 760px)");

  const elements = {
    serverStatus: document.querySelector("#server-status"),
    authAction: document.querySelector("#auth-action"),
    authBadge: document.querySelector("#auth-badge"),
    authLoggedOut: document.querySelector("#auth-logged-out"),
    authLoggedIn: document.querySelector("#auth-logged-in"),
    authAccount: document.querySelector("#auth-account"),
    loginForm: document.querySelector("#login-form"),
    cookieInput: document.querySelector("#cookie-input"),
    importLogin: document.querySelector("#import-login"),
    browserLogin: document.querySelector("#browser-login"),
    browserLoginCapability: document.querySelector("#browser-login-capability"),
    browserLoginVisual: document.querySelector("#browser-login-visual"),
    browserLoginPlaceholder: document.querySelector("#browser-login-placeholder"),
    browserLoginPlaceholderText: document.querySelector("#browser-login-placeholder-text"),
    browserLoginProgress: document.querySelector("#browser-login-progress"),
    browserLoginStatus: document.querySelector("#browser-login-status"),
    browserLoginMessage: document.querySelector("#browser-login-message"),
    browserLoginCountdown: document.querySelector("#browser-login-countdown"),
    cancelBrowserLogin: document.querySelector("#cancel-browser-login"),
    manualLogin: document.querySelector("#manual-login"),
    manualLoginTitle: document.querySelector("#manual-login-title"),
    manualLoginSubtitle: document.querySelector("#manual-login-subtitle"),
    manualLoginRecommendation: document.querySelector("#manual-login-recommendation"),
    logout: document.querySelector("#logout"),
    collectForm: document.querySelector("#collect-form"),
    sourceTabs: document.querySelector(".source-tabs"),
    keywordPanel: document.querySelector("#keyword-panel"),
    userPanel: document.querySelector("#user-panel"),
    keyword: document.querySelector("#keyword"),
    keywordLimit: document.querySelector("#keyword-limit"),
    keywordLimitHelp: document.querySelector("#keyword-limit-help"),
    profileUrl: document.querySelector("#profile-url"),
    userAllAck: document.querySelector("#user-all-ack"),
    customFields: document.querySelector("#custom-fields"),
    estimate: document.querySelector("#estimate"),
    formError: document.querySelector("#form-error"),
    createJob: document.querySelector("#create-job"),
    jobsList: document.querySelector("#jobs-list"),
    jobsEmpty: document.querySelector("#jobs-empty"),
    refreshJobs: document.querySelector("#refresh-jobs"),
    clearData: document.querySelector("#clear-data"),
    detailDialog: document.querySelector("#detail-confirm-dialog"),
    confirmSummary: document.querySelector("#confirm-summary"),
    confirmEstimate: document.querySelector("#confirm-estimate"),
    confirmDetails: document.querySelector("#confirm-details"),
    exportBasic: document.querySelector("#export-basic"),
    toast: document.querySelector("#toast"),
    srStatus: document.querySelector("#sr-status"),
    workflow: document.querySelector("#workflow"),
  };

  class ApiError extends Error {
    constructor(message, { code = null, status = 0 } = {}) {
      super(message);
      this.name = "ApiError";
      this.code = code;
      this.status = status;
    }
  }

  function readCookie(name) {
    const prefix = `${encodeURIComponent(name)}=`;
    const item = document.cookie
      .split(";")
      .map((value) => value.trim())
      .find((value) => value.startsWith(prefix));
    if (!item) return null;
    try {
      return decodeURIComponent(item.slice(prefix.length));
    } catch (_error) {
      return null;
    }
  }

  function unwrapPayload(payload) {
    if (payload && typeof payload === "object" && "data" in payload) return payload.data;
    return payload;
  }

  async function api(path, options = {}) {
    const method = String(options.method || "GET").toUpperCase();
    const headers = new Headers(options.headers || {});
    headers.set("Accept", "application/json");
    if (options.body !== undefined && !(options.body instanceof FormData)) {
      headers.set("Content-Type", "application/json");
    }
    if (!["GET", "HEAD", "OPTIONS"].includes(method)) {
      const csrf = readCookie("xhs_csrf");
      if (csrf) headers.set("X-XHS-CSRF", csrf);
    }

    let response;
    try {
      response = await fetch(`${API_BASE}${path}`, {
        ...options,
        method,
        headers,
        credentials: "same-origin",
        body:
          options.body !== undefined && !(options.body instanceof FormData)
            ? JSON.stringify(options.body)
            : options.body,
      });
    } catch (_error) {
      throw new ApiError("无法连接本地服务。请确认 CrimsonFlux 正在运行。", { code: "OFFLINE" });
    }

    const contentType = response.headers.get("content-type") || "";
    let payload = null;
    if (response.status !== 204) {
      payload = contentType.includes("application/json")
        ? await response.json().catch(() => null)
        : await response.text().catch(() => "");
    }
    if (!response.ok) {
      const detail = payload && typeof payload === "object" ? payload.detail : null;
      const error = payload && typeof payload === "object" ? payload.error : null;
      const candidate = error || detail || payload;
      const message =
        (candidate && typeof candidate === "object" && (candidate.message || candidate.msg)) ||
        (typeof candidate === "string" && candidate) ||
        `本地服务返回错误（HTTP ${response.status}）`;
      const code =
        (candidate && typeof candidate === "object" && candidate.code) ||
        (payload && typeof payload === "object" && payload.code) ||
        null;
      throw new ApiError(message, { code, status: response.status });
    }
    return unwrapPayload(payload);
  }

  function setPill(element, text, variant = "neutral") {
    element.className = `status-pill status-${variant}`;
    const label = element.querySelector("span:last-child");
    if (label) label.textContent = text;
  }

  function setButtonLabel(button, text) {
    const label = button.querySelector(":scope > span");
    if (label) {
      label.textContent = text;
    } else {
      button.textContent = text;
    }
  }

  function showToast(message, isError = false) {
    window.clearTimeout(state.toastTimer);
    window.clearTimeout(state.toastExitTimer);
    elements.toast.classList.remove("is-leaving");
    elements.toast.textContent = message;
    elements.toast.classList.toggle("is-error", isError);
    elements.toast.hidden = false;
    elements.srStatus.textContent = message;
    state.toastTimer = window.setTimeout(() => {
      elements.toast.classList.add("is-leaving");
      state.toastExitTimer = window.setTimeout(() => {
        elements.toast.hidden = true;
        elements.toast.classList.remove("is-leaving");
      }, 150);
    }, 4850);
  }

  function humanError(error) {
    if (error instanceof ApiError && error.code === "UPSTREAM_UNSUPPORTED") {
      return "整理功能暂时不可用，请重启服务或查看排错指南。";
    }
    if (error instanceof ApiError && error.code === "AUTH_EXPIRED") {
      return "登录已过期。请重新打开官方网页登录（或手动导入登录状态）后恢复任务。";
    }
    if (error instanceof ApiError && error.code === "RATE_LIMITED") {
      return "平台暂时限制了请求。任务已安全暂停，请稍后恢复。";
    }
    return error instanceof Error ? error.message : "发生未知错误";
  }

  function setServerAvailable(available) {
    if (available && state.health?.status === "degraded") {
      setPill(elements.serverStatus, "整理功能未就绪", "warning");
      return;
    }
    setPill(
      elements.serverStatus,
      available ? "本地服务已连接" : "本地服务未连接",
      available ? "success" : "danger",
    );
  }

  function configuredNumber(value, fallback, minimum = 0) {
    const parsed = Number(value);
    return Number.isFinite(parsed) && parsed >= minimum ? parsed : fallback;
  }

  function renderRuntimeMode() {
    elements.keywordLimit.max = String(state.limits.keyword);
    if (Number(elements.keywordLimit.value) > state.limits.keyword) {
      elements.keywordLimit.value = String(state.limits.keyword);
    }
    elements.keywordLimitHelp.textContent =
      `本次最多可设置 ${state.limits.keyword} 条；如果没有足够结果，最终数量可能会更少。`;
    updateEstimate();
    if (state.auth) renderAuth(state.auth);
  }

  async function loadHealth({ quiet = false } = {}) {
    try {
      const health = (await api("/health")) || {};
      const limits = health.limits || {};
      const pauseMin = configuredNumber(limits.pause_min_seconds, 2, 0);
      state.health = health;
      state.limits = {
        keyword: Math.max(1, Math.floor(configuredNumber(limits.keyword, 1000, 1))),
        user: Math.max(0, Math.floor(configuredNumber(limits.user, 10000, 0))),
        pauseMinSeconds: pauseMin,
        pauseMaxSeconds: Math.max(
          pauseMin,
          configuredNumber(limits.pause_max_seconds, 4, 0),
        ),
      };
      setServerAvailable(true);
      renderRuntimeMode();
      return health;
    } catch (error) {
      setServerAvailable(false);
      if (!quiet) showToast(humanError(error), true);
      return null;
    }
  }

  function isAuthenticated(auth) {
    return Boolean(
      auth &&
        (auth.authenticated === true ||
          auth.logged_in === true ||
          ["authenticated", "connected"].includes(auth.status)),
    );
  }

  function renderWorkflowState() {
    if (!elements.workflow) return;
    const connected = isAuthenticated(state.auth);
    const hasJobs = state.jobs.length > 0;
    const hasFinishedJob = state.jobs.some((job) =>
      ["completed", "completed_with_warnings"].includes(job.status),
    );
    const current = !connected ? "connect" : !hasJobs ? "scope" : "export";
    const complete = new Set();
    if (connected) complete.add("connect");
    if (hasJobs) complete.add("scope");
    if (hasFinishedJob) complete.add("export");
    elements.workflow.dataset.flowState = hasFinishedJob ? "complete" : current;
    elements.workflow.querySelectorAll("[data-workflow-step]").forEach((step) => {
      const name = step.dataset.workflowStep;
      step.classList.toggle("is-current", name === current && !complete.has(name));
      step.classList.toggle("is-complete", complete.has(name));
      if (name === current && !complete.has(name)) {
        step.setAttribute("aria-current", "step");
      } else {
        step.removeAttribute("aria-current");
      }
    });
  }

  function renderAuth(auth) {
    state.auth = auth || {};
    const connected = isAuthenticated(state.auth);
    const collector = state.health?.collector || {};
    const importSupported = collector.cookie_import_supported === true;
    const browserSupported = collector.browser_login_supported === true;
    const collectionReady = collector.collection_runtime_ok === true;
    const browserActive = BROWSER_LOGIN_ACTIVE.has(state.browserLogin?.status);
    elements.authAction.disabled =
      !connected && (!(browserSupported || importSupported) || browserActive);
    elements.logout.hidden = false;
    elements.authLoggedOut.hidden = connected;
    elements.authLoggedIn.hidden = !connected;
    setButtonLabel(
      elements.authAction,
      connected ? "账号已连接" : browserSupported ? "网页登录" : "导入登录态",
    );
    elements.cookieInput.disabled = !importSupported || browserActive;
    elements.importLogin.disabled = !importSupported || browserActive;
    elements.browserLogin.disabled = !browserSupported || browserActive;
    elements.browserLoginCapability.textContent = browserSupported
      ? `${collector.browser_name || "Chrome / Edge"} 临时窗口 · 最多等待 ${Math.ceil((collector.browser_login_timeout_seconds || 300) / 60)} 分钟 · 完成后自动关闭`
      : collector.browser_login_reason ||
        "当前环境无法打开官方网页登录窗口；可以展开下方手动导入。";
    if (!browserSupported && importSupported && !state.manualLoginAutoOpened) {
      elements.manualLogin.open = true;
      state.manualLoginAutoOpened = true;
    }
    elements.createJob.disabled = !(connected && collectionReady);
    setButtonLabel(
      elements.createJob,
      connected
        ? collectionReady
          ? "开始整理"
          : "整理功能未就绪"
        : "请先完成登录",
    );
    if (connected) {
      setPill(elements.authBadge, "已登录", "success");
      const account = state.auth.account_name || state.auth.nickname;
      const fingerprint = state.auth.account_fingerprint;
      elements.authAccount.textContent = account
        ? `当前账号：${account}`
        : fingerprint
          ? `账号标识：${String(fingerprint).slice(0, 12)}…（非账号明文）`
          : "登录态已加密保存在本机。";
    } else {
      setPill(elements.authBadge, "未登录", "warning");
    }
    renderWorkflowState();
  }

  async function loadAuth({ quiet = false } = {}) {
    try {
      const auth = await api("/auth/status");
      setServerAvailable(true);
      renderAuth(auth);
      return auth;
    } catch (error) {
      setServerAvailable(false);
      setPill(elements.authBadge, "无法检查", "danger");
      if (!quiet) showToast(humanError(error), true);
      return null;
    }
  }

  function browserLoginVariant(status) {
    if (["starting", "awaiting_login", "verifying"].includes(status)) {
      return "running";
    }
    if (status === "succeeded") return "success";
    if (status === "expired") return "warning";
    if (["failed", "browser_closed"].includes(status)) return "danger";
    return "neutral";
  }

  function browserLoginDisplayMessage(payload, fallback) {
    return payload?.message || fallback;
  }

  function renderManualLoginFallback(payload) {
    const recommended =
      payload?.status === "failed" &&
      ["BROWSER_NOT_FOUND", "BROWSER_LAUNCH_FAILED", "BROWSER_CONTROL_FAILED"].includes(
        payload?.error_code,
      );
    elements.manualLogin.classList.toggle("is-recommended", recommended);
    elements.manualLoginRecommendation.hidden = !recommended;
    elements.manualLoginTitle.textContent = recommended
      ? "建议改用手动导入"
      : "窗口打不开？手动导入登录状态";
    elements.manualLoginSubtitle.textContent = recommended
      ? "先在普通浏览器完成官方登录，再把登录状态安全保存到本机"
      : "Docker 或没有图形界面时使用";
    if (recommended) {
      elements.manualLogin.open = true;
      state.manualLoginAutoOpened = true;
    }
  }

  function resetBrowserLoginVisual({
    message = "点击后会打开临时官方窗口",
    visualState = "idle",
  } = {}) {
    elements.browserLoginPlaceholderText.textContent = message;
    elements.browserLoginVisual.dataset.state = visualState;
  }

  function browserLoginExpiry(payload) {
    const exact = payload?.expires_at;
    if (exact !== undefined && exact !== null) {
      const numeric = Number(exact);
      if (Number.isFinite(numeric) && numeric > 0) {
        return numeric > 10_000_000_000 ? numeric : numeric * 1000;
      }
      const parsed = Date.parse(String(exact));
      if (Number.isFinite(parsed)) return parsed;
    }
    const remaining = Number(payload?.remaining_seconds ?? payload?.expires_in);
    if (Number.isFinite(remaining) && remaining >= 0) {
      return Date.now() + remaining * 1000;
    }
    return null;
  }

  function updateBrowserLoginCountdown(status, payload) {
    if (!BROWSER_LOGIN_ACTIVE.has(status)) {
      elements.browserLoginCountdown.hidden = true;
      return;
    }
    const reportedExpiry = browserLoginExpiry(payload);
    if (reportedExpiry !== null) state.browserLoginDeadlineMs = reportedExpiry;
    if (state.browserLoginDeadlineMs === null) {
      const timeout = configuredNumber(
        state.health?.collector?.browser_login_timeout_seconds,
        300,
        1,
      );
      state.browserLoginDeadlineMs = Date.now() + timeout * 1000;
    }
    const remaining = Math.max(
      0,
      Math.ceil((state.browserLoginDeadlineMs - Date.now()) / 1000),
    );
    const minutes = String(Math.floor(remaining / 60)).padStart(2, "0");
    const seconds = String(remaining % 60).padStart(2, "0");
    elements.browserLoginCountdown.textContent = `剩余 ${minutes}:${seconds}`;
    elements.browserLoginCountdown.hidden = false;
  }

  function renderBrowserLogin(payload) {
    const previousStatus = state.browserLogin?.status || "idle";
    state.browserLogin = payload || { status: "idle" };
    const status = state.browserLogin.status || "idle";
    const active = BROWSER_LOGIN_ACTIVE.has(status);
    const visible = status !== "idle";
    const visual = {
      starting: ["正在打开临时官方窗口…", "loading"],
      awaiting_login: ["请在弹出的官方窗口完成登录", "ready"],
      verifying: ["检测到登录，正在验证账号…", "verifying"],
      succeeded: ["账号已连接，临时窗口已关闭", "succeeded"],
      failed: ["网页登录未完成，可以重试或使用手动方式", "error"],
      browser_closed: ["临时窗口已关闭，登录未完成", "error"],
      expired: ["等待超时，请重新打开网页登录", "expired"],
      cancelled: ["已取消网页登录", "idle"],
      idle: ["点击后会打开临时官方窗口", "idle"],
    };
    if (status !== previousStatus) {
      const [message, visualState] = visual[status] || ["正在处理网页登录…", "loading"];
      resetBrowserLoginVisual({ message, visualState });
    }
    elements.browserLoginProgress.hidden = !visible || (!active && status !== "succeeded");
    elements.cancelBrowserLogin.hidden = !active;
    setPill(
      elements.browserLoginStatus,
      BROWSER_LOGIN_LABELS[status] || "状态未知",
      browserLoginVariant(status),
    );
    elements.browserLoginMessage.textContent = browserLoginDisplayMessage(
      state.browserLogin,
      visual[status]?.[0] || "正在处理网页登录…",
    );
    updateBrowserLoginCountdown(status, state.browserLogin);
    if (status !== previousStatus) {
      elements.srStatus.textContent = elements.browserLoginMessage.textContent;
    }
    setButtonLabel(
      elements.browserLogin,
      status === "starting"
        ? "正在打开官方窗口…"
        : status === "awaiting_login"
          ? "请在官方窗口完成登录"
          : status === "verifying"
            ? "正在验证账号…"
            : ["failed", "expired", "cancelled", "browser_closed"].includes(status)
              ? "重新打开网页登录"
              : "打开官方网页登录",
    );
    renderManualLoginFallback(state.browserLogin);
    renderAuth(state.auth);
  }

  function scheduleBrowserLoginPoll() {
    window.clearTimeout(state.browserLoginTimer);
    if (!BROWSER_LOGIN_ACTIVE.has(state.browserLogin?.status)) return;
    state.browserLoginTimer = window.setTimeout(
      () => loadBrowserLoginStatus({ quiet: true }),
      1000,
    );
  }

  async function loadBrowserLoginStatus({ quiet = false } = {}) {
    const previous = state.browserLogin?.status || "idle";
    try {
      const result = await api("/auth/browser/status");
      renderBrowserLogin(result);
      const current = result?.status || "idle";
      if (current === "succeeded" && previous !== "succeeded") {
        await loadAuth({ quiet: true });
        showToast("网页登录成功，登录态已加密保存在本机。", false);
      } else if (["failed", "expired"].includes(current) && current !== previous) {
        showToast(
          browserLoginDisplayMessage(result, "网页登录未完成，请检查页面提示。"),
          true,
        );
      }
      return result;
    } catch (error) {
      if (!quiet) showToast(humanError(error), true);
      return null;
    } finally {
      scheduleBrowserLoginPoll();
    }
  }

  async function startBrowserLogin() {
    state.browserLoginDeadlineMs = null;
    resetBrowserLoginVisual({
      message: "正在打开临时官方窗口…",
      visualState: "loading",
    });
    elements.browserLogin.disabled = true;
    setButtonLabel(elements.browserLogin, "正在打开官方窗口…");
    try {
      const result = await api("/auth/browser", { method: "POST", body: {} });
      renderBrowserLogin(result);
    } catch (error) {
      showToast(humanError(error), true);
      renderBrowserLogin({
        status: "failed",
        error_code: error?.code || "BROWSER_LAUNCH_FAILED",
        message: "官方网页登录窗口未能打开，请重试或使用手动方式。",
      });
    } finally {
      scheduleBrowserLoginPoll();
    }
  }

  async function cancelBrowserLogin() {
    elements.cancelBrowserLogin.disabled = true;
    try {
      const result = await api("/auth/browser", { method: "DELETE" });
      renderBrowserLogin(result);
    } catch (error) {
      showToast(humanError(error), true);
    } finally {
      elements.cancelBrowserLogin.disabled = false;
      scheduleBrowserLoginPoll();
    }
  }

  async function importLogin(event) {
    event.preventDefault();
    let cookie = elements.cookieInput.value;
    if (!cookie || cookie.length > 16384 || /[\r\n\0]/u.test(cookie)) {
      cookie = "";
      elements.cookieInput.value = "";
      showToast("Cookie 为空、过长或包含非法控制字符。", true);
      return;
    }
    elements.importLogin.disabled = true;
    setButtonLabel(elements.importLogin, "正在验证…");
    try {
      const result = await api("/auth/import", { method: "POST", body: { cookie } });
      if (result?.authenticated !== true) {
        throw new ApiError("本地服务未确认登录态。", { code: "INVALID_RESPONSE" });
      }
      elements.cookieInput.value = "";
      await loadAuth();
      showToast("登录态已加密保存，输入框已清空。请复制一段普通文字覆盖系统剪贴板。", false);
    } catch (error) {
      showToast(humanError(error), true);
    } finally {
      cookie = "";
      elements.cookieInput.value = "";
      const supported = state.health?.collector?.cookie_import_supported === true;
      elements.importLogin.disabled = !supported;
      setButtonLabel(elements.importLogin, "验证并加密保存");
    }
  }

  async function logout() {
    if (!window.confirm("退出后，正在运行的任务可能因登录失效而暂停。确定清除本地登录态吗？")) {
      return;
    }
    elements.logout.disabled = true;
    try {
      await api("/auth/session", { method: "DELETE" });
      renderBrowserLogin({ status: "idle", message: "尚未启动网页登录。" });
      renderAuth({ authenticated: false });
      showToast("本地登录态已清除。", false);
    } catch (error) {
      showToast(humanError(error), true);
    } finally {
      elements.logout.disabled = false;
    }
  }

  async function clearAllData() {
    const confirmed = window.confirm(
      "这会永久删除全部任务、导出、登录态并轮换本地主密钥，且无法撤销。确定继续？",
    );
    if (!confirmed) return;
    elements.clearData.disabled = true;
    try {
      await api("/data", { method: "DELETE" });
      state.jobs = [];
      renderJobs();
      renderBrowserLogin({ status: "idle", message: "尚未启动网页登录。" });
      await loadAuth({ quiet: true });
      showToast("全部本地数据已清除，本地主密钥已轮换。", false);
    } catch (error) {
      showToast(humanError(error), true);
    } finally {
      elements.clearData.disabled = false;
    }
  }

  function selectedPreset() {
    return document.querySelector('input[name="preset"]:checked')?.value || "basic";
  }

  function selectedFields() {
    if (selectedPreset() !== "custom") return [];
    return Array.from(document.querySelectorAll('input[name="field_group"]:checked')).map(
      (input) => input.value,
    );
  }

  function needsDetails(preset = selectedPreset(), fields = selectedFields()) {
    return preset === "full" || (preset === "custom" && fields.some((field) => DETAIL_FIELDS.has(field)));
  }

  function durationLabel(seconds) {
    const safe = Math.max(0, Math.round(seconds));
    if (safe === 0) return "少于 1 秒";
    if (safe < 60) return `${safe} 秒`;
    const minutes = Math.ceil(safe / 60);
    if (minutes < 60) return `${minutes} 分钟`;
    const hours = Math.floor(minutes / 60);
    const rest = minutes % 60;
    return rest ? `${hours} 小时 ${rest} 分钟` : `${hours} 小时`;
  }

  function estimateRange(count, withDetails) {
    const pages = Math.max(1, Math.ceil(Number(count || 1) / 20));
    const requests = pages + (withDetails ? Number(count || 0) : 0);
    const minimum = requests * state.limits.pauseMinSeconds;
    const maximum = requests * state.limits.pauseMaxSeconds;
    return `${durationLabel(minimum)}–${durationLabel(maximum)}`;
  }

  function detailEstimateRange(count) {
    const requests = Math.max(0, Number(count) || 0);
    return (
      `${durationLabel(requests * state.limits.pauseMinSeconds)}–` +
      `${durationLabel(requests * state.limits.pauseMaxSeconds)}`
    );
  }

  function requestEstimate(count, withDetails) {
    const safeCount = Math.max(1, Number(count) || 1);
    const listRequests = Math.max(1, Math.ceil(safeCount / 20));
    const detailRequests = withDetails ? safeCount : 0;
    return { listRequests, detailRequests };
  }

  function updateEstimate() {
    const withDetails = needsDetails();
    const strong = elements.estimate.querySelector("strong");
    const small = elements.estimate.querySelector("small");
    if (state.sourceType === "user") {
      strong.textContent = withDetails
        ? "先找齐可见内容，再询问你是否继续读取正文等更多信息"
        : "会自动翻页，直到没有新的可见内容";
      small.textContent = withDetails
        ? `找到内容后会显示数量和新的时间估算；你确认前不会逐条打开。每次操作会间隔 ${state.limits.pauseMinSeconds}–${state.limits.pauseMaxSeconds} 秒。`
        : `内容越多，等待越久。程序每次操作会间隔 ${state.limits.pauseMinSeconds}–${state.limits.pauseMaxSeconds} 秒。`;
      return;
    }
    const count = Math.max(1, Number(elements.keywordLimit.value) || 1);
    const requests = requestEstimate(count, withDetails);
    strong.textContent =
      `大约需要查看 ${requests.listRequests} 页结果` +
      (withDetails ? `，再逐条读取最多 ${requests.detailRequests} 项内容` : "") +
      `；预计等待 ${estimateRange(count, withDetails)}`;
    small.textContent = withDetails
      ? "选择完整版或更多信息后，程序会逐条打开内容；没能读到的信息会在文件中注明。"
      : "快速版不逐条打开内容；网络速度和平台响应仍会影响等待时间。";
  }

  function setSourceType(type) {
    state.sourceType = type;
    document.querySelectorAll("[data-source-tab]").forEach((tab) => {
      const active = tab.dataset.sourceTab === type;
      tab.classList.toggle("is-active", active);
      tab.setAttribute("aria-selected", String(active));
      tab.tabIndex = active ? 0 : -1;
    });
    elements.keywordPanel.hidden = type !== "keyword";
    elements.userPanel.hidden = type !== "user";
    elements.keyword.required = type === "keyword";
    elements.profileUrl.required = type === "user";
    updateEstimate();
  }

  function showFormError(message) {
    elements.formError.textContent = message;
    elements.formError.hidden = !message;
  }

  function buildJobRequest() {
    const preset = selectedPreset();
    const fields = selectedFields();
    if (preset === "custom" && fields.length === 0) {
      throw new Error("请至少勾选一类要保存的信息。", { cause: "validation" });
    }
    const content = { preset, fields };
    let source;
    if (state.sourceType === "keyword") {
      const keyword = elements.keyword.value.trim().replace(/\s+/g, " ");
      const limit = Number(elements.keywordLimit.value);
      if (!keyword) throw new Error("请输入关键词。", { cause: "validation" });
      if (!Number.isInteger(limit) || limit < 1 || limit > state.limits.keyword) {
        throw new Error(`目标数量必须是 1–${state.limits.keyword} 之间的整数。`, { cause: "validation" });
      }
      source = { type: "keyword", keyword, limit };
    } else {
      const profileUrl = elements.profileUrl.value.trim();
      if (!profileUrl) throw new Error("请输入用户主页完整地址。", { cause: "validation" });
      let publicProfileUrl;
      try {
        const parsed = new URL(profileUrl);
        parsed.hash = "";
        publicProfileUrl = parsed.toString();
      } catch (_error) {
        throw new Error("用户主页地址格式不正确。", { cause: "validation" });
      }
      if (!elements.userAllAck.checked) {
        throw new Error("请先勾选主页内容范围说明。", { cause: "validation" });
      }
      source = { type: "user", profile_url: publicProfileUrl, all: true };
    }
    return {
      source,
      content,
      // Keyword details were explicitly selected with a known limit.  User details
      // are never pre-approved: enumeration must finish before the second consent.
      preapprove_details: state.sourceType === "keyword" || !needsDetails(preset, fields),
    };
  }

  async function createJob(event) {
    event.preventDefault();
    showFormError("");
    let payload;
    try {
      payload = buildJobRequest();
    } catch (error) {
      showFormError(humanError(error));
      return;
    }
    elements.createJob.disabled = true;
    setButtonLabel(elements.createJob, "正在创建…");
    try {
      const result = await api("/jobs", { method: "POST", body: payload });
      const job = result?.job || result;
      if (state.sourceType === "user") elements.profileUrl.value = "";
      showToast(`任务已创建${job?.id ? `：${String(job.id).slice(0, 8)}` : ""}。`, false);
      await loadJobs();
      document.querySelector("#jobs-title")?.scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (error) {
      showFormError(humanError(error));
    } finally {
      renderAuth(state.auth);
    }
  }

  function normalizeJobs(payload) {
    if (Array.isArray(payload)) return payload;
    if (Array.isArray(payload?.items)) return payload.items;
    if (Array.isArray(payload?.jobs)) return payload.jobs;
    return [];
  }

  function formatDate(value) {
    if (!value) return "时间未知";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return String(value);
    return new Intl.DateTimeFormat("zh-CN", {
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      hour12: false,
    }).format(date);
  }

  function jobTitle(job) {
    if (job.source_type === "keyword" || job.source?.type === "keyword") {
      return `主题：${job.source?.keyword || "未知"}`;
    }
    const url = job.source?.profile_url || "";
    let profilePath = url;
    try {
      profilePath = new URL(url).pathname;
    } catch (_error) {
      profilePath = url.split(/[?#]/, 1)[0];
    }
    const profileId = profilePath.split("/").filter(Boolean).pop();
    return `主页：${profileId || "未命名"}`;
  }

  function statusVariant(status) {
    if (status === "completed") return "success";
    if (status === "completed_with_warnings" || status?.startsWith("paused_")) return "warning";
    if (status === "failed" || status === "cancelled") return "danger";
    if (ACTIVE_STATUSES.has(status) || status === "awaiting_detail_confirmation") return "running";
    return "neutral";
  }

  function jobProgress(job) {
    const status = job.status;
    const unique = Number(job.unique_notes || 0);
    const detailDone = Number(job.detail_succeeded || 0) + Number(job.detail_failed || 0);
    if (["completed", "completed_with_warnings"].includes(status)) return 100;
    if (status === "exporting") return 96;
    if (status === "fetching_details") {
      return unique ? Math.min(94, 55 + Math.round((detailDone / unique) * 39)) : 56;
    }
    if (status === "awaiting_detail_confirmation") return 55;
    if (status === "enumerating") {
      const target = job.source?.type === "keyword" ? Number(job.source.limit || 0) : 0;
      return target ? Math.min(53, 8 + Math.round((unique / target) * 45)) : Math.min(50, 8 + unique);
    }
    if (status === "queued") return 4;
    if (status === "cancelled") return Math.min(95, unique ? 45 : 5);
    if (status === "failed") return Math.min(95, unique ? 50 : 8);
    if (status?.startsWith("paused_")) return Math.min(92, unique ? 50 : 8);
    return 2;
  }

  function jobProgressText(job) {
    const unique = Number(job.unique_notes || 0);
    const detailSucceeded = Number(job.detail_succeeded || 0);
    const detailFailed = Number(job.detail_failed || 0);
    if (job.status === "enumerating") {
      const target = job.source?.type === "keyword" ? Number(job.source.limit || 0) : null;
      return target ? `已找到 ${unique} / 目标 ${target} 条` : `已找到 ${unique} 条，正在查看下一页`;
    }
    if (job.status === "fetching_details") {
      return `更多信息已获取 ${detailSucceeded} 条，未取到 ${detailFailed} 条；共找到 ${unique} 条`;
    }
    if (job.status === "awaiting_detail_confirmation") {
      return `已找到 ${unique} 条；等你决定是否继续读取更多信息`;
    }
    if (TERMINAL_STATUSES.has(job.status) || job.status?.startsWith("paused_")) {
      const parts = [`共整理 ${unique} 条`];
      if (detailSucceeded || detailFailed) {
        parts.push(`更多信息：完整 ${detailSucceeded} / 未取到 ${detailFailed}`);
      }
      if (job.termination_reason) {
        parts.push(`结束原因：${TERMINATION_LABELS[job.termination_reason] || "运行已安全结束"}`);
      }
      return parts.join(" · ");
    }
    return "会按创建顺序自动开始";
  }

  function element(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function iconElement(name, className = "icon") {
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
    svg.setAttribute("class", className);
    svg.setAttribute("aria-hidden", "true");
    use.setAttribute("href", `#icon-${name}`);
    svg.append(use);
    return svg;
  }

  function actionButton(label, action, jobId, variant = "secondary") {
    const icons = { confirm: "download", cancel: "close", resume: "play", retry: "refresh" };
    const button = element("button", `button button-${variant} button-small`);
    button.type = "button";
    button.dataset.jobAction = action;
    button.dataset.jobId = jobId;
    button.append(iconElement(icons[action] || "arrow"), element("span", "", label));
    return button;
  }

  function exportLink(jobId, format) {
    const link = element("a", "download-link");
    link.href = `${API_BASE}/jobs/${encodeURIComponent(jobId)}/exports/${format}`;
    link.download = format === "manifest" ? "manifest.json" : `notes.${format}`;
    link.dataset.exportDownload = format;
    link.append(
      iconElement("download"),
      element(
        "span",
        "",
        format === "manifest"
          ? "任务说明"
          : format === "csv"
            ? "表格 (.csv)"
            : "原始数据 (.jsonl)",
      ),
    );
    link.title =
      format === "manifest"
        ? "包含本次整理数量、完成情况和文件校验信息"
        : format === "csv"
          ? "适合用 Excel、Numbers 或表格软件打开"
          : "适合交给其他数据工具继续处理";
    return link;
  }

  function jobSignature(job) {
    return JSON.stringify(job);
  }

  function jobControlKey(control) {
    if (control.dataset.jobAction) return `action:${control.dataset.jobAction}`;
    if (control.dataset.exportDownload) return `export:${control.dataset.exportDownload}`;
    return "";
  }

  function syncJobControl(current, next) {
    current.className = next.className;
    current.dataset.jobId = next.dataset.jobId || "";
    if (next.dataset.jobAction) current.dataset.jobAction = next.dataset.jobAction;
    if (next.dataset.exportDownload) {
      current.dataset.exportDownload = next.dataset.exportDownload;
    }
    if (current instanceof HTMLAnchorElement && next instanceof HTMLAnchorElement) {
      current.href = next.href;
      current.download = next.download;
    }
    const currentLabel = current.querySelector(":scope > span");
    const nextLabel = next.querySelector(":scope > span");
    if (currentLabel && nextLabel) currentLabel.textContent = nextLabel.textContent;
  }

  function patchJobActions(current, next) {
    const currentByKey = new Map(
      Array.from(current.children).map((control) => [jobControlKey(control), control]),
    );
    const desiredControls = Array.from(next.children);
    const desiredKeys = new Set();

    desiredControls.forEach((desired, index) => {
      const key = jobControlKey(desired);
      desiredKeys.add(key);
      const retained = currentByKey.get(key);
      const control = retained || desired;
      if (retained) syncJobControl(retained, desired);
      const atIndex = current.children[index];
      if (atIndex !== control) current.insertBefore(control, atIndex || null);
    });

    Array.from(current.children).forEach((control) => {
      if (!desiredKeys.has(jobControlKey(control))) control.remove();
    });
  }

  function renderJob(job) {
    const card = element("article", "job-card");
    card.dataset.jobId = job.id;

    const topline = element("div", "job-topline");
    const title = element("div", "job-title");
    title.append(element("strong", "", jobTitle(job)));
    title.append(element("small", "", `编号 ${String(job.id).slice(0, 8)}`));
    const pill = element("span", `status-pill status-${statusVariant(job.status)}`);
    pill.append(element("span", "status-dot"), element("span", "", STATUS_LABELS[job.status] || job.status));
    topline.append(title, pill);

    const meta = element("div", "job-meta");
    const preset = job.content?.preset || "basic";
    meta.append(
      element("span", "", `创建于 ${formatDate(job.created_at)}`),
      element("span", "", `保存内容：${PRESET_LABELS[preset] || "自定义"}`),
      element("span", "", `已查看 ${Number(job.pages_requested || 0)} 页`),
    );
    const progress = element("progress", "progress-track");
    progress.setAttribute("role", "progressbar");
    const percent = jobProgress(job);
    progress.max = 100;
    progress.value = percent;
    progress.setAttribute("aria-valuemin", "0");
    progress.setAttribute("aria-valuemax", "100");
    progress.setAttribute("aria-valuenow", String(percent));
    progress.setAttribute("aria-valuetext", jobProgressText(job));
    progress.setAttribute("aria-label", `${jobTitle(job)}进度`);
    if (job.status === "completed") progress.classList.add("is-complete");
    if (job.status === "completed_with_warnings" || job.status?.startsWith("paused_")) {
      progress.classList.add("is-warning");
    }

    card.append(topline, meta, progress, element("p", "job-detail", jobProgressText(job)));

    if (job.error_message || job.error_code) {
      const errorText = [job.error_code, job.error_message].filter(Boolean).join("：");
      card.append(element("p", "job-error", errorText));
    }

    const actions = element("div", "job-actions");
    if (job.status === "awaiting_detail_confirmation") {
      actions.append(actionButton("选择是否读取更多信息", "confirm", job.id, "primary"));
    }
    if (ACTIVE_STATUSES.has(job.status) || job.status === "awaiting_detail_confirmation") {
      actions.append(actionButton("取消", "cancel", job.id, "secondary"));
    }
    if (PAUSED_STATUSES.has(job.status)) {
      actions.append(actionButton("恢复", "resume", job.id, "secondary"));
    }
    if (job.enumeration_complete === true && Number(job.detail_failed || 0) > 0) {
      actions.append(actionButton("重试失败项", "retry", job.id, "secondary"));
    }
    const artifacts = job.artifacts && typeof job.artifacts === "object" ? job.artifacts : {};
    ["csv", "jsonl", "manifest"].forEach((format) => {
      if (artifacts[format] === true) actions.append(exportLink(job.id, format));
    });
    if (actions.childElementCount) card.append(actions);
    jobRenderSignatures.set(card, jobSignature(job));
    return card;
  }

  function patchJob(card, job) {
    const next = renderJob(job);
    const currentActions = card.querySelector(":scope > .job-actions");
    const nextActions = next.querySelector(":scope > .job-actions");

    Array.from(card.children).forEach((child) => {
      if (child !== currentActions) child.remove();
    });
    Array.from(next.children).forEach((child) => {
      if (child !== nextActions) card.insertBefore(child, currentActions || null);
    });

    if (currentActions && nextActions) {
      patchJobActions(currentActions, nextActions);
    } else if (currentActions) {
      currentActions.remove();
    } else if (nextActions) {
      card.append(nextActions);
    }

    jobRenderSignatures.set(card, jobSignature(job));
    return card;
  }

  function renderJobs() {
    const existing = new Map(
      Array.from(elements.jobsList.querySelectorAll(":scope > .job-card")).map((card) => [
        card.dataset.jobId,
        card,
      ]),
    );
    const desiredIds = new Set();

    state.jobs.forEach((job, index) => {
      const jobId = String(job.id);
      desiredIds.add(jobId);
      let card = existing.get(jobId);
      if (!card) {
        card = renderJob(job);
      } else if (jobRenderSignatures.get(card) !== jobSignature(job)) {
        patchJob(card, job);
      }
      const atIndex = elements.jobsList.children[index];
      if (atIndex !== card) elements.jobsList.insertBefore(card, atIndex || null);
    });

    Array.from(elements.jobsList.querySelectorAll(":scope > .job-card")).forEach((card) => {
      if (!desiredIds.has(card.dataset.jobId)) card.remove();
    });
    elements.jobsEmpty.hidden = state.jobs.length > 0;
    elements.jobsList.hidden = state.jobs.length === 0;
    renderWorkflowState();
  }

  function scheduleJobsRefresh() {
    window.clearTimeout(state.jobsTimer);
    if (document.hidden) return;
    const hasChangingJob = state.jobs.some(
      (job) => ACTIVE_STATUSES.has(job.status) || job.status === "awaiting_detail_confirmation",
    );
    state.jobsTimer = window.setTimeout(() => loadJobs({ quiet: true }), hasChangingJob ? 2500 : 10000);
  }

  async function loadJobs({ quiet = false } = {}) {
    elements.refreshJobs.disabled = true;
    try {
      const payload = await api("/jobs?limit=100");
      setServerAvailable(true);
      state.jobs = normalizeJobs(payload);
      renderJobs();
    } catch (error) {
      setServerAvailable(false);
      if (!quiet) showToast(humanError(error), true);
    } finally {
      elements.refreshJobs.disabled = false;
      scheduleJobsRefresh();
    }
  }

  function findJob(jobId) {
    return state.jobs.find((job) => String(job.id) === String(jobId));
  }

  function openDetailConfirmation(job) {
    state.confirmJob = job;
    const count = Number(job.unique_notes || 0);
    const preset = job.content?.preset || "full";
    elements.confirmSummary.textContent =
      `这个主页已找到 ${count} 条公开内容。你选择的是“${PRESET_LABELS[preset] || "完整版"}”。`;
    elements.confirmEstimate.textContent =
      `接下来最多逐条读取 ${count} 项内容；` +
      `每次间隔 ${state.limits.pauseMinSeconds}–${state.limits.pauseMaxSeconds} 秒，` +
      `预计还需 ${detailEstimateRange(count)}`;
    if (typeof elements.detailDialog.showModal === "function") {
      elements.detailDialog.showModal();
    } else if (window.confirm(`${elements.confirmSummary.textContent}\n${elements.confirmEstimate.textContent}`)) {
      confirmDetails();
    }
  }

  async function submitDetailDecision(content, successMessage) {
    const job = state.confirmJob;
    if (!job) return;
    elements.confirmDetails.disabled = true;
    elements.exportBasic.disabled = true;
    try {
      await api(`/jobs/${encodeURIComponent(job.id)}/confirm-details`, {
        method: "POST",
        body: { content },
      });
      elements.detailDialog.close();
      showToast(successMessage, false);
      state.confirmJob = null;
      await loadJobs();
    } catch (error) {
      showToast(humanError(error), true);
    } finally {
      elements.confirmDetails.disabled = false;
      elements.exportBasic.disabled = false;
    }
  }

  async function confirmDetails(event) {
    event?.preventDefault();
    const job = state.confirmJob;
    if (!job) return;
    await submitDetailDecision(job.content, "已确认，将继续获取更多信息。");
  }

  async function exportBasic(event) {
    event?.preventDefault();
    await submitDetailDecision(
      { preset: "basic", fields: [] },
      "已改为快速导出，不会逐条打开内容。",
    );
  }

  async function runJobAction(action, jobId, button) {
    const job = findJob(jobId);
    if (!job) return;
    if (action === "confirm") {
      openDetailConfirmation(job);
      return;
    }
    if (action === "cancel" && !window.confirm("确定取消这个任务吗？已整理的数据不会被删除。")) {
      return;
    }
    button.disabled = true;
    const endpoint = `/jobs/${encodeURIComponent(jobId)}/${action === "retry" ? "retry-details" : action}`;
    try {
      await api(endpoint, { method: "POST", body: {} });
      const labels = { cancel: "已请求取消任务。", resume: "任务已恢复并重新排队。", retry: "失败项已重新排队。" };
      showToast(labels[action] || "任务已更新。", false);
      await loadJobs();
    } catch (error) {
      showToast(humanError(error), true);
      button.disabled = false;
    }
  }

  function bindEvents() {
    function updateSourceTabsOrientation() {
      elements.sourceTabs?.setAttribute(
        "aria-orientation",
        sourceTabsVertical.matches ? "vertical" : "horizontal",
      );
    }

    updateSourceTabsOrientation();
    sourceTabsVertical.addEventListener("change", updateSourceTabsOrientation);
    document.querySelectorAll("[data-source-tab]").forEach((tab) => {
      tab.addEventListener("click", () => setSourceType(tab.dataset.sourceTab));
      tab.addEventListener("keydown", (event) => {
        const navigationKeys = sourceTabsVertical.matches
          ? ["ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown"]
          : ["ArrowLeft", "ArrowRight"];
        if (!navigationKeys.includes(event.key)) return;
        event.preventDefault();
        const next = tab.dataset.sourceTab === "keyword" ? "user" : "keyword";
        setSourceType(next);
        document.querySelector(`[data-source-tab="${next}"]`)?.focus();
      });
    });

    document.querySelectorAll('input[name="preset"]').forEach((input) => {
      input.addEventListener("change", () => {
        elements.customFields.hidden = selectedPreset() !== "custom";
        updateEstimate();
      });
    });
    document.querySelectorAll('input[name="field_group"]').forEach((input) => {
      input.addEventListener("change", updateEstimate);
    });
    elements.keywordLimit.addEventListener("input", updateEstimate);
    elements.collectForm.addEventListener("submit", createJob);
    elements.loginForm.addEventListener("submit", importLogin);
    elements.browserLogin.addEventListener("click", startBrowserLogin);
    elements.cancelBrowserLogin.addEventListener("click", cancelBrowserLogin);
    elements.authAction.addEventListener("click", () => {
      if (isAuthenticated(state.auth)) return;
      document.querySelector("#auth-title")?.scrollIntoView({ behavior: "smooth" });
      if (state.health?.collector?.browser_login_supported === true) {
        startBrowserLogin();
      } else {
        elements.manualLogin.open = true;
        elements.cookieInput.focus({ preventScroll: true });
      }
    });
    elements.logout.addEventListener("click", logout);
    elements.refreshJobs.addEventListener("click", () => loadJobs());
    elements.clearData.addEventListener("click", clearAllData);
    elements.confirmDetails.addEventListener("click", confirmDetails);
    elements.exportBasic.addEventListener("click", exportBasic);
    elements.detailDialog.addEventListener("close", () => {
      state.confirmJob = null;
    });
    elements.jobsList.addEventListener("click", (event) => {
      const button = event.target.closest("[data-job-action]");
      if (button) runJobAction(button.dataset.jobAction, button.dataset.jobId, button);
    });
    document.addEventListener("visibilitychange", () => {
      if (document.hidden) {
        window.clearTimeout(state.jobsTimer);
      } else {
        loadJobs({ quiet: true });
        loadBrowserLoginStatus({ quiet: true });
      }
    });
    window.addEventListener("beforeunload", () => {
      window.clearTimeout(state.jobsTimer);
      window.clearTimeout(state.browserLoginTimer);
      elements.cookieInput.value = "";
    });
  }

  async function initialise() {
    bindEvents();
    setSourceType("keyword");
    await loadHealth({ quiet: true });
    await Promise.all([
      loadAuth({ quiet: true }),
      loadJobs({ quiet: true }),
      loadBrowserLoginStatus({ quiet: true }),
    ]);
  }

  initialise();
})();
