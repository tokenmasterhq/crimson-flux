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
    "awaiting_scan",
    "awaiting_phone_confirmation",
    "verifying",
  ]);
  const BROWSER_LOGIN_LABELS = {
    starting: "正在生成",
    awaiting_scan: "等待扫码",
    awaiting_phone_confirmation: "等待手机确认",
    verifying: "正在验证",
    succeeded: "登录成功",
    failed: "登录未完成",
    browser_closed: "登录会话已关闭",
    expired: "已超时",
    cancelled: "已取消",
    idle: "尚未开始",
  };
  const PLATFORM_CHALLENGE_REQUIRED = "PLATFORM_CHALLENGE_REQUIRED";
  const PLATFORM_CHALLENGE_MESSAGE =
    "手机确认已完成，但平台要求额外网页验证；当前安全模式无法在页内自动完成。";

  const STATUS_LABELS = {
    queued: "等待运行",
    enumerating: "正在列出笔记",
    awaiting_detail_confirmation: "等待详情确认",
    fetching_details: "正在补全详情",
    exporting: "正在生成文件",
    completed: "已完成",
    completed_with_warnings: "已完成，有缺失",
    paused_auth: "登录失效，已暂停",
    paused_rate_limit: "触发限流，已暂停",
    paused_interrupted: "服务中断，已暂停",
    paused_cursor_invalid: "翻页位置失效，请新建任务",
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
    browserQrGeneration: 0,
    browserQrLoading: false,
    browserQrLoaded: false,
    browserQrError: false,
    browserQrObjectUrl: null,
    browserQrRevision: null,
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
    browserLoginQr: document.querySelector("#browser-login-qr"),
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
      return "当前内容处理组件不可用，请检查健康状态中的阻断项。";
    }
    if (error instanceof ApiError && error.code === "AUTH_EXPIRED") {
      return "登录已过期。请重新扫码登录（或手动导入 Cookie）后恢复任务。";
    }
    if (error instanceof ApiError && error.code === "RATE_LIMITED") {
      return "平台暂时限制了请求。任务已安全暂停，请稍后恢复。";
    }
    return error instanceof Error ? error.message : "发生未知错误";
  }

  function setServerAvailable(available) {
    if (available && state.health?.status === "degraded") {
      setPill(elements.serverStatus, "处理组件未就绪", "warning");
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
      `服务配置上限为 ${state.limits.keyword} 条；实际结果可能因去重、无更多结果或风控而更少。`;
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
    const challengeRequired = isPlatformChallengeRequired(state.browserLogin);
    const qrRetryAllowed =
      state.browserLogin?.status === "awaiting_scan" && state.browserQrError;
    elements.authAction.disabled =
      !connected && (!(browserSupported || importSupported) || browserActive);
    elements.logout.hidden = false;
    elements.authLoggedOut.hidden = connected;
    elements.authLoggedIn.hidden = !connected;
    setButtonLabel(
      elements.authAction,
      connected ? "账号已连接" : browserSupported ? "扫码登录" : "导入登录态",
    );
    elements.cookieInput.disabled = !importSupported || browserActive;
    elements.importLogin.disabled = !importSupported || browserActive;
    elements.browserLogin.disabled =
      !browserSupported || (browserActive && !qrRetryAllowed);
    elements.browserLoginCapability.textContent = challengeRequired
      ? "重新扫码可能仍会遇到相同验证，建议使用下方 Cookie 导入。"
      : browserSupported
        ? `二维码有效期约 ${collector.browser_login_timeout_seconds || 180} 秒 · 扫码后请按手机提示完成确认或验证`
        : collector.browser_login_reason || "当前环境不支持扫码；可以展开下方手动导入。";
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
          : "处理组件未就绪"
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
    if (
      ["starting", "awaiting_scan", "awaiting_phone_confirmation", "verifying"].includes(
        status,
      )
    ) {
      return "running";
    }
    if (status === "succeeded") return "success";
    if (status === "expired") return "warning";
    if (["failed", "browser_closed"].includes(status)) return "danger";
    return "neutral";
  }

  function isPlatformChallengeRequired(payload) {
    return (
      payload?.status === "failed" &&
      payload?.error_code === PLATFORM_CHALLENGE_REQUIRED
    );
  }

  function browserLoginDisplayMessage(payload, fallback) {
    if (isPlatformChallengeRequired(payload)) return PLATFORM_CHALLENGE_MESSAGE;
    return payload?.message || fallback;
  }

  function renderManualLoginFallback(payload) {
    const recommended = isPlatformChallengeRequired(payload);
    elements.manualLogin.classList.toggle("is-recommended", recommended);
    elements.manualLoginRecommendation.hidden = !recommended;
    elements.manualLoginTitle.textContent = recommended
      ? "建议改用 Cookie 导入"
      : "扫码不可用？手动导入 Cookie";
    elements.manualLoginSubtitle.textContent = recommended
      ? "先在官方网页完成额外验证，再把网页登录态安全保存到本机"
      : "Docker 与无图形界面环境使用此方式";
    if (recommended) {
      elements.manualLogin.open = true;
      state.manualLoginAutoOpened = true;
    }
  }

  function releaseBrowserQrObjectUrl() {
    if (state.browserQrObjectUrl) {
      URL.revokeObjectURL(state.browserQrObjectUrl);
      state.browserQrObjectUrl = null;
    }
    elements.browserLoginQr.removeAttribute("src");
  }

  function resetBrowserQr({ message = "点击获取登录二维码", visualState = "idle" } = {}) {
    state.browserQrGeneration += 1;
    state.browserQrLoading = false;
    state.browserQrLoaded = false;
    state.browserQrError = false;
    state.browserQrRevision = null;
    releaseBrowserQrObjectUrl();
    elements.browserLoginQr.hidden = true;
    elements.browserLoginPlaceholder.hidden = false;
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
        180,
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

  async function loadBrowserQrImage({ quiet = false } = {}) {
    if (state.browserQrLoading || state.browserQrLoaded) return;
    const generation = state.browserQrGeneration;
    let candidateObjectUrl = null;
    state.browserQrLoading = true;
    state.browserQrError = false;
    elements.browserLoginVisual.dataset.state = "loading";
    elements.browserLoginPlaceholder.hidden = false;
    elements.browserLoginPlaceholderText.textContent = "正在加载二维码…";
    setButtonLabel(elements.browserLogin, "正在加载二维码…");
    renderAuth(state.auth);
    try {
      const response = await fetch(`${API_BASE}/auth/browser/qr`, {
        method: "GET",
        headers: { Accept: "image/png" },
        credentials: "same-origin",
        cache: "no-store",
      });
      const contentType = response.headers.get("content-type") || "";
      const responseRevision = response.headers.get("x-xhs-qr-revision");
      if (!response.ok || !contentType.toLowerCase().startsWith("image/png")) {
        throw new ApiError("二维码暂时无法加载，请重试。", {
          code: "QR_IMAGE_UNAVAILABLE",
          status: response.status,
        });
      }
      const blob = await response.blob();
      if (blob.size === 0 || blob.size > 1024 * 1024) {
        throw new ApiError("二维码图片格式异常，请重新获取。", {
          code: "QR_IMAGE_INVALID",
        });
      }
      candidateObjectUrl = URL.createObjectURL(blob);
      await new Promise((resolve, reject) => {
        elements.browserLoginQr.onload = resolve;
        elements.browserLoginQr.onerror = () => reject(new Error("invalid QR image"));
        elements.browserLoginQr.src = candidateObjectUrl;
      });
      if (generation !== state.browserQrGeneration) {
        URL.revokeObjectURL(candidateObjectUrl);
        candidateObjectUrl = null;
        return;
      }
      if (state.browserQrObjectUrl) URL.revokeObjectURL(state.browserQrObjectUrl);
      state.browserQrObjectUrl = candidateObjectUrl;
      candidateObjectUrl = null;
      state.browserQrLoaded = true;
      state.browserQrRevision =
        responseRevision || state.browserLogin?.qr_revision || null;
      elements.browserLoginQr.hidden = false;
      elements.browserLoginPlaceholder.hidden = true;
      elements.browserLoginVisual.dataset.state = "ready";
      setButtonLabel(elements.browserLogin, "等待扫码确认");
      elements.srStatus.textContent = "登录二维码已显示，请使用平台官方 App 扫描。";
    } catch (error) {
      if (candidateObjectUrl) URL.revokeObjectURL(candidateObjectUrl);
      if (generation !== state.browserQrGeneration) return;
      state.browserQrError = true;
      elements.browserLoginQr.hidden = true;
      elements.browserLoginPlaceholder.hidden = false;
      elements.browserLoginPlaceholderText.textContent = "二维码加载失败";
      elements.browserLoginVisual.dataset.state = "error";
      setButtonLabel(elements.browserLogin, "重新加载二维码");
      if (!quiet) showToast(humanError(error), true);
    } finally {
      if (generation === state.browserQrGeneration) {
        state.browserQrLoading = false;
        renderAuth(state.auth);
      }
    }
  }

  function renderBrowserLogin(payload) {
    const previousStatus = state.browserLogin?.status || "idle";
    const nextQrRevision = payload?.qr_revision || null;
    state.browserLogin = payload || { status: "idle" };
    const status = state.browserLogin.status || "idle";
    const active = BROWSER_LOGIN_ACTIVE.has(status);
    const visible = status !== "idle";
    const challengeRequired = isPlatformChallengeRequired(state.browserLogin);
    const terminalMessage = {
      awaiting_phone_confirmation:
        "已扫码，请按手机提示完成确认；如要求短信验证，请在手机端完成。",
      failed: "登录未完成，请重新获取二维码",
      browser_closed: "登录会话已关闭，请重新获取二维码",
      expired: "二维码已过期，请重新获取",
      cancelled: "扫码登录已取消",
      succeeded: "登录成功",
      idle: "点击获取登录二维码",
    };
    if (
      [
        "awaiting_phone_confirmation",
        "verifying",
        "succeeded",
        "failed",
        "expired",
        "cancelled",
        "browser_closed",
        "idle",
      ].includes(status) &&
      status !== previousStatus
    ) {
      resetBrowserQr({
        message: challengeRequired
          ? "需要额外网页验证"
          : terminalMessage[status] || "正在验证登录…",
        visualState: challengeRequired ? "challenge" : status,
      });
    } else if (status === "starting" && previousStatus !== "starting") {
      resetBrowserQr({ message: "正在生成登录二维码…", visualState: "loading" });
    } else if (
      status === "awaiting_scan" &&
      state.browserQrLoaded &&
      nextQrRevision &&
      state.browserQrRevision !== nextQrRevision
    ) {
      resetBrowserQr({ message: "二维码已刷新，正在加载新二维码…", visualState: "loading" });
    }
    const terminalWithoutProgress =
      ["cancelled", "expired", "browser_closed", "failed"].includes(status) &&
      !challengeRequired;
    elements.browserLoginProgress.hidden = !visible || terminalWithoutProgress;
    elements.cancelBrowserLogin.hidden = !active;
    setPill(
      elements.browserLoginStatus,
      BROWSER_LOGIN_LABELS[status] || "状态未知",
      browserLoginVariant(status),
    );
    elements.browserLoginMessage.textContent = browserLoginDisplayMessage(
      state.browserLogin,
      status === "awaiting_scan"
        ? "请使用平台官方 App 扫描二维码，并在手机上确认。"
        : terminalMessage[status] || "正在准备登录二维码…",
    );
    updateBrowserLoginCountdown(status, state.browserLogin);
    if (status !== previousStatus) {
      elements.srStatus.textContent = elements.browserLoginMessage.textContent;
    }
    setButtonLabel(
      elements.browserLogin,
      status === "awaiting_scan" && state.browserQrError
        ? "重新加载二维码"
        : status === "starting"
          ? "正在生成二维码…"
          : status === "awaiting_scan"
            ? state.browserQrLoaded
              ? "等待扫码确认"
              : "正在加载二维码…"
            : status === "awaiting_phone_confirmation"
              ? "等待手机确认"
              : status === "verifying"
                ? "正在验证…"
                : challengeRequired
                  ? "仍要尝试扫码"
                  : ["failed", "expired", "cancelled", "browser_closed"].includes(status)
                    ? "重新获取二维码"
                    : "获取登录二维码",
    );
    if (
      status === "awaiting_scan" &&
      !state.browserQrLoaded &&
      !state.browserQrLoading &&
      !state.browserQrError
    ) {
      void loadBrowserQrImage({ quiet: true });
    }
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
        showToast("扫码登录成功，登录态已加密保存在本机。", false);
      } else if (["failed", "expired"].includes(current) && current !== previous) {
        showToast(
          browserLoginDisplayMessage(result, "扫码登录未完成，请检查页面提示。"),
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
    if (state.browserLogin?.status === "awaiting_scan" && state.browserQrError) {
      await loadBrowserQrImage();
      return;
    }
    state.browserLoginDeadlineMs = null;
    resetBrowserQr({ message: "正在生成登录二维码…", visualState: "loading" });
    elements.browserLogin.disabled = true;
    setButtonLabel(elements.browserLogin, "正在生成二维码…");
    try {
      const result = await api("/auth/browser", { method: "POST", body: {} });
      renderBrowserLogin(result);
    } catch (error) {
      state.browserQrError = true;
      showToast(humanError(error), true);
      renderBrowserLogin({ status: "failed", message: "二维码获取失败，请重试。" });
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
      renderBrowserLogin({ status: "idle", message: "尚未启动扫码登录。" });
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
      renderBrowserLogin({ status: "idle", message: "尚未启动扫码登录。" });
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
        ? "耗时取决于公开内容数量；列出后会再次确认详情补全"
        : "耗时取决于该用户当前可见的公开笔记数量";
      small.textContent = withDetails
        ? `届时会显示数量和新估算；确认前不请求详情。当前请求间隔 ${state.limits.pauseMinSeconds}–${state.limits.pauseMaxSeconds} 秒。`
        : `会持续翻页到无更多结果；当前请求间隔 ${state.limits.pauseMinSeconds}–${state.limits.pauseMaxSeconds} 秒。`;
      return;
    }
    const count = Math.max(1, Number(elements.keywordLimit.value) || 1);
    const requests = requestEstimate(count, withDetails);
    strong.textContent =
      `预计列表请求约 ${requests.listRequests} 次，最多详情请求 ${requests.detailRequests} 次；` +
      `按当前间隔耗时约 ${estimateRange(count, withDetails)}`;
    small.textContent = withDetails
      ? "完整/自定义详情需要逐条请求，数量越大耗时越长，失败项会在导出文件中标注。"
      : "基础字段主要来自列表页；网络、风控和平台响应仍会造成波动。";
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
      throw new Error("自定义模式至少选择一个字段组。", { cause: "validation" });
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
        throw new Error("请先确认你理解“全部公开笔记”的范围。", { cause: "validation" });
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
      return `关键词：${job.source?.keyword || "未知"}`;
    }
    const url = job.source?.profile_url || "";
    let profilePath = url;
    try {
      profilePath = new URL(url).pathname;
    } catch (_error) {
      profilePath = url.split(/[?#]/, 1)[0];
    }
    const profileId = profilePath.split("/").filter(Boolean).pop();
    return `用户：${profileId || "公开主页"}`;
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
      return target ? `已列出 ${unique} / 目标 ${target} 条` : `已列出 ${unique} 条，正在查找下一页`;
    }
    if (job.status === "fetching_details") {
      return `详情成功 ${detailSucceeded}，失败 ${detailFailed}，共发现 ${unique} 条`;
    }
    if (job.status === "awaiting_detail_confirmation") {
      return `已列出 ${unique} 条；确认前不会逐条请求详情`;
    }
    if (TERMINAL_STATUSES.has(job.status) || job.status?.startsWith("paused_")) {
      const parts = [`共 ${unique} 条`];
      if (detailSucceeded || detailFailed) parts.push(`详情成功 ${detailSucceeded} / 失败 ${detailFailed}`);
      if (job.termination_reason) parts.push(`结束原因：${job.termination_reason}`);
      return parts.join(" · ");
    }
    return "任务会按创建顺序运行";
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
      element("span", "", format === "manifest" ? "manifest" : format.toUpperCase()),
    );
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
    title.append(element("small", "", `任务 ${job.id}`));
    const pill = element("span", `status-pill status-${statusVariant(job.status)}`);
    pill.append(element("span", "status-dot"), element("span", "", STATUS_LABELS[job.status] || job.status));
    topline.append(title, pill);

    const meta = element("div", "job-meta");
    const preset = job.content?.preset || "basic";
    meta.append(
      element("span", "", `创建于 ${formatDate(job.created_at)}`),
      element("span", "", `字段：${preset}`),
      element("span", "", `已请求 ${Number(job.pages_requested || 0)} 页`),
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
      actions.append(actionButton("确认补全详情", "confirm", job.id, "primary"));
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
    elements.confirmSummary.textContent = `该用户当前已发现 ${count} 条公开笔记。你选择了“${job.content?.preset || "full"}”字段方案。`;
    elements.confirmEstimate.textContent =
      `最多发起 ${count} 次详情请求；按当前 ${state.limits.pauseMinSeconds}–` +
      `${state.limits.pauseMaxSeconds} 秒间隔，详情阶段预计需 ${detailEstimateRange(count)}`;
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
    await submitDetailDecision(job.content, "已确认，任务将继续补全详情。");
  }

  async function exportBasic(event) {
    event?.preventDefault();
    await submitDetailDecision(
      { preset: "basic", fields: [] },
      "已改为仅导出基础字段，不会逐条请求详情。",
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
      releaseBrowserQrObjectUrl();
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
