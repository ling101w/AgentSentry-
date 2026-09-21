(function initializeThemeController() {
  const STORAGE_KEY = "agentsentry-console-theme";
  const DEFAULT_THEME = "safeline";
  const THEMES = ["safeline", "midnight", "graphite"];
  const THEME_META = {
    safeline: { label: "晴空", icon: "sun", themeColor: "#f7f8fa" },
    midnight: { label: "夜航", icon: "moon", themeColor: "#030b13" },
    graphite: { label: "石墨", icon: "palette", themeColor: "#111319" },
  };

  function readTheme() {
    try {
      const stored = window.localStorage.getItem(STORAGE_KEY);
      if (stored === "azure") return "safeline";
      return THEMES.includes(stored) ? stored : DEFAULT_THEME;
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
    const currentIndex = Math.max(0, THEMES.indexOf(theme));
    const nextTheme = THEMES[(currentIndex + 1) % THEMES.length];
    document.querySelectorAll("[data-theme-toggle]").forEach((button) => {
      button.dataset.themeCurrent = theme;
      button.setAttribute("aria-label", `当前${THEME_META[theme].label}主题，切换到${THEME_META[nextTheme].label}主题`);
      button.setAttribute("title", `当前：${THEME_META[theme].label}主题；切换到${THEME_META[nextTheme].label}主题`);
      const spriteIcon = { sun: "i-sun", moon: "i-moon", palette: "i-palette" }[THEME_META[theme].icon] || "i-sun";
      button.innerHTML = window.lucide?.createIcons
        ? `<i data-lucide="${THEME_META[theme].icon}"></i>`
        : `<svg aria-hidden="true"><use href="#${spriteIcon}"></use></svg>`;
    });
    const meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.setAttribute("content", THEME_META[theme].themeColor);
    if (window.lucide?.createIcons) window.lucide.createIcons();
  }

  function applyTheme(theme, { persist = true } = {}) {
    const nextTheme = THEMES.includes(theme) ? theme : DEFAULT_THEME;
    document.documentElement.dataset.theme = nextTheme;
    if (persist) writeTheme(nextTheme);
    syncButtons(nextTheme);
  }

  function toggleTheme() {
    const currentIndex = Math.max(0, THEMES.indexOf(document.documentElement.dataset.theme));
    applyTheme(THEMES[(currentIndex + 1) % THEMES.length]);
  }

  // Apply the stored palette before the application shell paints to avoid a flash.
  document.documentElement.dataset.theme = readTheme();

  function bind() {
    syncButtons(document.documentElement.dataset.theme || DEFAULT_THEME);
    document.querySelectorAll("[data-theme-toggle]").forEach((button) => {
      button.addEventListener("click", toggleTheme);
    });
  }

  window.AgentSentryTheme = { apply: applyTheme, toggle: toggleTheme, themes: [...THEMES] };
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", bind, { once: true });
  } else {
    bind();
  }
})();
