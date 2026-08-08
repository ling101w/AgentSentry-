(function initializeThemeController() {
  const STORAGE_KEY = "agentsentry-console-theme";
  const DEFAULT_THEME = "midnight";
  const ALTERNATE_THEME = "graphite";

  function readTheme() {
    try {
      return window.localStorage.getItem(STORAGE_KEY) === ALTERNATE_THEME
        ? ALTERNATE_THEME
        : DEFAULT_THEME;
    } catch {
      return DEFAULT_THEME;
    }
  }

  function writeTheme(theme) {
    try {
      window.localStorage.setItem(STORAGE_KEY, theme);
    } catch {
      // Private browsing can disable storage; the active page still updates.
    }
  }

  function syncButtons(theme) {
    const alternate = theme === ALTERNATE_THEME;
    document.querySelectorAll("[data-theme-toggle]").forEach((button) => {
      button.setAttribute("aria-pressed", String(alternate));
      button.setAttribute("aria-label", alternate ? "切换到夜航主题" : "切换到石墨主题");
      button.setAttribute("title", alternate ? "切换到夜航主题" : "切换到石墨主题");
      button.innerHTML = `<i data-lucide="${alternate ? "moon" : "palette"}"></i>`;
    });
    if (window.lucide?.createIcons) window.lucide.createIcons();
  }

  function applyTheme(theme, { persist = true } = {}) {
    const nextTheme = theme === ALTERNATE_THEME ? ALTERNATE_THEME : DEFAULT_THEME;
    document.documentElement.dataset.theme = nextTheme;
    if (persist) writeTheme(nextTheme);
    syncButtons(nextTheme);
  }

  function toggleTheme() {
    applyTheme(document.documentElement.dataset.theme === ALTERNATE_THEME ? DEFAULT_THEME : ALTERNATE_THEME);
  }

  // Apply the stored palette before the application shell paints to avoid a flash.
  document.documentElement.dataset.theme = readTheme();

  function bind() {
    syncButtons(document.documentElement.dataset.theme || DEFAULT_THEME);
    document.querySelectorAll("[data-theme-toggle]").forEach((button) => {
      button.addEventListener("click", toggleTheme);
    });
  }

  window.AgentSentryTheme = { apply: applyTheme, toggle: toggleTheme };
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", bind, { once: true });
  } else {
    bind();
  }
})();
