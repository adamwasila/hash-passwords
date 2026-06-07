const siteInput = document.getElementById("site");
const passwordInput = document.getElementById("password");
const hashedInput = document.getElementById("hashed");
const hashIdenticon = document.getElementById("hash-identicon");
const toggleVisibilityButton = document.getElementById("toggle-visibility");
const copyHashButton = document.getElementById("copy-hash");
const passwordTimeoutBar = document.getElementById("password-timeout-bar");
const algoSha256Button = document.getElementById("algo-sha256");
const domainExtractor = new SPH_DomainExtractor();
const SESSION_PASSWORD_KEY = "popupPassword";
const SESSION_PASSWORD_EXPIRES_AT_KEY = "popupPasswordExpiresAt";
const PERSISTENT_STRONG_HASH_KEY = "useStrongHash";
const PASSWORD_TIMEOUT_MS = 60_000;

let passwordTimeoutIntervalId = null;
let passwordExpiresAt = null;
let activeTabHost = "";
let useStrongHash = true;

function applyHashConstraints(hash, size, nonalphanumeric) {
  var startingSize = size - 4;
  var result = hash.substring(0, startingSize);
  var extras = hash.substring(startingSize).split('');

  function nextExtra() { return extras.length ? extras.shift().charCodeAt(0) : 0; }
  function nextExtraChar() { return String.fromCharCode(nextExtra()); }
  function rotate(arr, amount) { while (amount--) arr.push(arr.shift()); }
  function between(min, interval, offset) { return min + offset % interval; }
  function nextBetween(base, interval) {
    return String.fromCharCode(between(base.charCodeAt(0), interval, nextExtra()));
  }
  function contains(regex) { return result.match(regex); }

  result += (contains(/[A-Z]/) ? nextExtraChar() : nextBetween('A', 26));
  result += (contains(/[a-z]/) ? nextExtraChar() : nextBetween('a', 26));
  result += (contains(/[0-9]/) ? nextExtraChar() : nextBetween('0', 10));
  result += (contains(/\W/) && nonalphanumeric ? nextExtraChar() : '+');
  while (contains(/\W/) && !nonalphanumeric) {
    result = result.replace(/\W/, nextBetween('A', 26));
  }

  result = result.split('');
  rotate(result, nextExtra());
  return result.join('');
}

async function generateStrongPwdHash(site, password) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: enc.encode(site), iterations: 100000, hash: "SHA-256" },
    keyMaterial,
    256
  );
  const hash = btoa(String.fromCharCode(...new Uint8Array(bits)));
  const size = password.length + SPH_kPasswordPrefix.length;
  const nonalphanumeric = /\W/.test(password);
  return applyHashConstraints(hash, size, nonalphanumeric);
}

const OPEN_EYE_ICON_REF = "#icon-eye-open";
const CROSSED_EYE_ICON_REF = "#icon-eye-crossed";

function getExtensionApi() {
  return typeof browser !== "undefined" ? browser : chrome;
}

async function restorePasswordFromSession() {
  const api = getExtensionApi();
  const storageSession = api.storage?.session;

  if (!storageSession) {
    return;
  }

  try {
    const storedData = await storageSession.get(SESSION_PASSWORD_KEY);
    const storedPassword = storedData?.[SESSION_PASSWORD_KEY];

    if (typeof storedPassword === "string") {
      passwordInput.value = storedPassword;
    }
  } catch {
    // Ignore storage errors and keep default empty password field.
  }
}

async function restoreAlgorithmPreference() {
  const api = getExtensionApi();
  const storageLocal = api.storage?.local;

  if (!storageLocal) {
    return;
  }

  try {
    const storedData = await storageLocal.get(PERSISTENT_STRONG_HASH_KEY);
    const storedValue = storedData?.[PERSISTENT_STRONG_HASH_KEY];

    if (typeof storedValue === "boolean") {
      useStrongHash = storedValue;
    }
  } catch {
    // Ignore storage errors and keep default algorithm preference.
  }
}

async function persistAlgorithmPreference() {
  const api = getExtensionApi();
  const storageLocal = api.storage?.local;

  if (!storageLocal) {
    return;
  }

  try {
    await storageLocal.set({ [PERSISTENT_STRONG_HASH_KEY]: useStrongHash });
  } catch {
    // Ignore storage errors to avoid blocking hash generation.
  }
}

async function persistPasswordToSession(passwordValue) {
  const api = getExtensionApi();
  const storageSession = api.storage?.session;

  if (!storageSession) {
    return;
  }

  try {
    await storageSession.set({ [SESSION_PASSWORD_KEY]: passwordValue });
  } catch {
    // Ignore storage errors to avoid blocking hash generation.
  }
}

async function restorePasswordTimeoutFromSession() {
  const api = getExtensionApi();
  const storageSession = api.storage?.session;

  if (!storageSession) {
    return;
  }

  try {
    const storedData = await storageSession.get(SESSION_PASSWORD_EXPIRES_AT_KEY);
    const storedExpiresAt = storedData?.[SESSION_PASSWORD_EXPIRES_AT_KEY];

    if (typeof storedExpiresAt === "number" && Number.isFinite(storedExpiresAt)) {
      passwordExpiresAt = storedExpiresAt;
    }
  } catch {
    // Ignore storage errors and keep in-memory timer state.
  }
}

async function persistPasswordTimeoutToSession(expiresAt) {
  const api = getExtensionApi();
  const storageSession = api.storage?.session;

  if (!storageSession) {
    return;
  }

  try {
    await storageSession.set({ [SESSION_PASSWORD_EXPIRES_AT_KEY]: expiresAt });
  } catch {
    // Ignore storage errors to avoid blocking hash generation.
  }
}

async function clearPasswordFromSession() {
  const api = getExtensionApi();
  const storageSession = api.storage?.session;

  if (!storageSession) {
    return;
  }

  try {
    await storageSession.remove([SESSION_PASSWORD_KEY, SESSION_PASSWORD_EXPIRES_AT_KEY]);
  } catch {
    // Ignore storage errors to avoid blocking the popup flow.
  }
}

async function getActiveTabUrl() {
  const api = getExtensionApi();

  const [activeTab] = await api.tabs.query({ active: true, currentWindow: true });
  return activeTab?.url ?? "";
}

function extractHostFromUrl(urlValue) {
  if (!urlValue) {
    return "";
  }

  try {
    const parsedUrl = new URL(urlValue);
    return parsedUrl.hostname.toLowerCase();
  } catch {
    return "";
  }
}

function normalizeSiteValue(value) {
  const trimmedValue = value.trim();

  if (!trimmedValue) {
    return "";
  }

  try {
    return domainExtractor.extractDomain(trimmedValue);
  } catch {
    return trimmedValue;
  }
}

async function deriveIdenticonSeed(hashValue) {
  const enc = new TextEncoder();
  const input = enc.encode(`identicon-v1:${hashValue}`);

  try {
    const digest = await crypto.subtle.digest("SHA-256", input);
    return new Uint8Array(digest);
  } catch {
    // Fallback keeps deterministic behavior when subtle crypto is unavailable.
    const fallback = new Uint8Array(32);

    for (let i = 0; i < fallback.length; i += 1) {
      const char = hashValue.charCodeAt(i % hashValue.length) || 0;
      fallback[i] = (char + i * 31) % 256;
    }

    return fallback;
  }
}

async function updateHashIdenticon(hashValue) {
  if (!hashIdenticon) {
    return;
  }

  const context = hashIdenticon.getContext("2d");

  if (!context) {
    return;
  }

  const canvasSize = hashIdenticon.width;
  const gridSize = 5;
  const padding = 2;
  const cellSize = Math.floor((canvasSize - padding * 2) / gridSize);
  const paintSize = cellSize * gridSize;
  const offset = Math.floor((canvasSize - paintSize) / 2);
  const style = getComputedStyle(hashIdenticon);
  const backgroundColor = style.backgroundColor || "#ffffff";

  context.clearRect(0, 0, hashIdenticon.width, hashIdenticon.height);
  context.fillStyle = backgroundColor;
  context.fillRect(0, 0, hashIdenticon.width, hashIdenticon.height);

  if (!hashValue) {
    return;
  }

  const seed = await deriveIdenticonSeed(hashValue);
  const hueSeed = (seed[0] << 8) | seed[1];

  const color = `hsl(${hueSeed % 360} 68% 44%)`;
  context.fillStyle = color;

  let index = 0;

  for (let row = 0; row < gridSize; row += 1) {
    for (let col = 0; col < Math.ceil(gridSize / 2); col += 1) {
      const byteIndex = 2 + Math.floor(index / 8);
      const bitIndex = index % 8;
      const value = (seed[byteIndex % seed.length] >> bitIndex) & 1;

      if (value === 1) {
        const x = offset + col * cellSize;
        const y = offset + row * cellSize;
        const mirroredX = offset + (gridSize - 1 - col) * cellSize;

        context.fillRect(x, y, cellSize, cellSize);

        if (mirroredX !== x) {
          context.fillRect(mirroredX, y, cellSize, cellSize);
        }
      }

      index += 1;
    }
  }
}

function updatePasswordTimeoutBar(remainingMs) {
  if (!passwordTimeoutBar) {
    return;
  }

  if (!passwordInput.value) {
    passwordTimeoutBar.style.width = "0%";
    return;
  }

  const clampedRemainingMs = Math.max(0, Math.min(PASSWORD_TIMEOUT_MS, remainingMs));
  const percent = (clampedRemainingMs / PASSWORD_TIMEOUT_MS) * 100;

  passwordTimeoutBar.style.width = `${percent}%`;
}

async function clearPasswordByTimeout() {
  stopPasswordTimeoutCountdown();
  passwordExpiresAt = null;
  passwordInput.value = "";
  await clearPasswordFromSession();
  updatePasswordTimeoutBar(0);
  await generateHash();
}

async function clearPasswordByHostChange() {
  stopPasswordTimeoutCountdown();
  passwordExpiresAt = null;
  passwordInput.value = "";
  await clearPasswordFromSession();
  updatePasswordTimeoutBar(0);
}

function stopPasswordTimeoutCountdown() {
  if (passwordTimeoutIntervalId !== null) {
    clearInterval(passwordTimeoutIntervalId);
    passwordTimeoutIntervalId = null;
  }
}

function startPasswordTimeoutCountdown(options = {}) {
  const { resetDeadline = true } = options;

  stopPasswordTimeoutCountdown();

  if (!passwordInput.value) {
    passwordExpiresAt = null;
    updatePasswordTimeoutBar(0);
    return;
  }

  if (resetDeadline || passwordExpiresAt === null || passwordExpiresAt <= Date.now()) {
    passwordExpiresAt = Date.now() + PASSWORD_TIMEOUT_MS;
  }

  void persistPasswordTimeoutToSession(passwordExpiresAt);
  updatePasswordTimeoutBar(passwordExpiresAt - Date.now());

  passwordTimeoutIntervalId = setInterval(() => {
    const remainingMs = passwordExpiresAt - Date.now();

    if (remainingMs <= 0) {
      void clearPasswordByTimeout();
      return;
    }

    updatePasswordTimeoutBar(remainingMs);
  }, 100);
}

function onVisibilityChange() {
  if (document.hidden || !passwordInput.value) {
    return;
  }

  if (passwordExpiresAt === null || passwordExpiresAt <= Date.now()) {
    void clearPasswordByTimeout();
    return;
  }

  updatePasswordTimeoutBar(passwordExpiresAt - Date.now());

  if (passwordTimeoutIntervalId === null) {
    startPasswordTimeoutCountdown({ resetDeadline: false });
  }
}

async function syncWithActiveTab(options = {}) {
  const { clearPasswordOnHostChange = true } = options;

  try {
    const activeTabUrl = await getActiveTabUrl();
    const nextHost = extractHostFromUrl(activeTabUrl);
    const normalizedSite = normalizeSiteValue(activeTabUrl);

    if (normalizedSite) {
      siteInput.value = normalizedSite;
    }

    const hostChanged = activeTabHost !== "" && activeTabHost !== nextHost;

    if (clearPasswordOnHostChange && hostChanged && passwordInput.value) {
      await clearPasswordByHostChange();
    }

    activeTabHost = nextHost;
    await generateHash();
  } catch {
    // Keep current values when active tab details cannot be read.
  }
}

function initializeActiveTabListeners() {
  const api = getExtensionApi();

  api.tabs?.onActivated?.addListener(() => {
    void syncWithActiveTab();
  });

  api.tabs?.onUpdated?.addListener((_tabId, changeInfo, tab) => {
    if (!tab?.active) {
      return;
    }

    if (typeof changeInfo.url !== "string" && changeInfo.status !== "complete") {
      return;
    }

    void syncWithActiveTab();
  });
}

async function generateHash() {
  if (!passwordInput.value) {
    hashedInput.value = "";
    await updateHashIdenticon("");
    return;
  }

  const normalizedSite = normalizeSiteValue(siteInput.value);

  const hashValue = useStrongHash
    ? await generateStrongPwdHash(normalizedSite, passwordInput.value)
    : generatePwdHash(normalizedSite, passwordInput.value);

  hashedInput.value = hashValue;
  await updateHashIdenticon(hashValue);
}

async function copyHash() {
  if (!hashedInput.value) {
    await generateHash();
  }

  await navigator.clipboard.writeText(hashedInput.value);
}

function setHashVisibility(revealed) {
  hashedInput.type = revealed ? "text" : "password";
  const iconUse = toggleVisibilityButton.querySelector("use");

  if (iconUse) {
    iconUse.setAttribute("href", revealed ? OPEN_EYE_ICON_REF : CROSSED_EYE_ICON_REF);
  }

  const label = revealed ? "Hide hash" : "Show hash";
  toggleVisibilityButton.setAttribute("aria-label", label);
  toggleVisibilityButton.setAttribute("title", label);
}

function updateAlgorithmToggleButton() {
  if (!algoSha256Button) {
    return;
  }

  algoSha256Button.classList.toggle("is-active", useStrongHash);
  algoSha256Button.setAttribute("aria-pressed", String(useStrongHash));

  const tooltip = useStrongHash
    ? "SHA256 enabled: PBKDF2-SHA256 is active. Click to return to original MD5 behavior compatible with PwdHash."
    : "SHA256 disabled: original MD5 behavior compatible with PwdHash is active. Press to switch to PBKDF2-SHA256.";

  algoSha256Button.setAttribute("title", tooltip);
}

copyHashButton.addEventListener("click", () => {
  void copyHash();
});

toggleVisibilityButton.addEventListener("click", () => {
  setHashVisibility(hashedInput.type === "password");
});

algoSha256Button?.addEventListener("click", () => {
  useStrongHash = !useStrongHash;
  updateAlgorithmToggleButton();
  void persistAlgorithmPreference();
  void generateHash();
});

siteInput.addEventListener("input", () => {
  void generateHash();
});

passwordInput.addEventListener("input", () => {
  void persistPasswordToSession(passwordInput.value);
  if (passwordInput.value) {
    startPasswordTimeoutCountdown();
  } else {
    stopPasswordTimeoutCountdown();
    passwordExpiresAt = null;
    updatePasswordTimeoutBar(0);
    void clearPasswordFromSession();
  }
  void generateHash();
});

document.addEventListener("visibilitychange", onVisibilityChange);

siteInput.addEventListener("paste", (event) => {
  event.preventDefault();

  const pastedText = event.clipboardData?.getData("text") ?? "";
  siteInput.value = normalizeSiteValue(pastedText);

  void generateHash();
});

async function initializePopup() {
  await restoreAlgorithmPreference();
  updateAlgorithmToggleButton();
  await restorePasswordFromSession();
  await restorePasswordTimeoutFromSession();

  if (passwordInput.value) {
    if (passwordExpiresAt !== null && passwordExpiresAt <= Date.now()) {
      await clearPasswordByTimeout();
    } else {
      startPasswordTimeoutCountdown({ resetDeadline: passwordExpiresAt === null });
    }
  } else {
    updatePasswordTimeoutBar(0);
  }
  await syncWithActiveTab({ clearPasswordOnHostChange: false });
  initializeActiveTabListeners();
  setHashVisibility(false);
}

void initializePopup();
