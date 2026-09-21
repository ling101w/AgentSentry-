(() => {
  const cases = window.XUANJIAN_DEMO_CASES || [];
  const $ = (id) => document.getElementById(id);

  const state = {
    caseId: cases[0]?.id || "injection",
    step: 0,
    playing: false,
    timer: 0,
  };

  const playBtn = $("playBtn");
  const resetBtn = $("resetBtn");
  const progress = $("progress");
  const nav = $("caseNav");

  nav.innerHTML = cases.map((item) => (
    `<button type="button" data-case="${item.id}">${escapeHtml(item.category)}<span class="tag">${escapeHtml(item.familyLabel)}</span></button>`
  )).join("");

  nav.addEventListener("click", (event) => {
    const button = event.target.closest("[data-case]");
    if (!button) return;
    selectCase(button.dataset.case);
  });
  playBtn.addEventListener("click", togglePlay);
  resetBtn.addEventListener("click", () => selectCase(state.caseId, 0));
  progress.addEventListener("input", () => {
    stop();
    reveal(Number(progress.value));
  });
  $("timeline").addEventListener("click", (event) => {
    const card = event.target.closest("[data-step]");
    if (!card) return;
    stop();
    reveal(Number(card.dataset.step));
  });

  const params = new URLSearchParams(location.search);
  selectCase(params.get("case") || state.caseId, 0);

  function currentCase() {
    return cases.find((item) => item.id === state.caseId) || cases[0];
  }

  function selectCase(id, step = 0) {
    stop();
    state.caseId = cases.some((item) => item.id === id) ? id : cases[0].id;
    const item = currentCase();
    nav.querySelectorAll("[data-case]").forEach((button) => {
      button.classList.toggle("active", button.dataset.case === item.id);
    });
    $("caseBanner").innerHTML = `
      <div>
        <span class="kicker">${escapeHtml(item.source)} · ${escapeHtml(item.caseId)}</span>
        <h2>${escapeHtml(item.title)}</h2>
        <p>${escapeHtml(item.description)}</p>
      </div>
      <div class="meta">
        <span class="chip">${escapeHtml(item.category)}</span>
        <span class="chip deny">期望拦截</span>
        <span class="chip">${escapeHtml(item.recordId)}</span>
      </div>`;
    $("timeline").innerHTML = item.steps.map((stepItem, index) => `
      <button class="card ${stepItem.tone}" data-step="${index}" type="button" role="listitem">
        <div class="who"><strong>${escapeHtml(stepItem.who)}</strong><span>${escapeHtml(stepItem.title)}</span></div>
        <p>${escapeHtml(stepItem.text)}</p>
      </button>`).join("");
    progress.max = String(Math.max(item.steps.length - 1, 0));
    reveal(step);
    if (location.protocol !== "file:") {
      history.replaceState(null, "", `${location.pathname}?case=${encodeURIComponent(item.id)}`);
    }
  }

  function reveal(step) {
    const item = currentCase();
    state.step = Math.max(0, Math.min(step, item.steps.length - 1));
    progress.value = String(state.step);
    $("progressLabel").textContent = `${state.step + 1} / ${item.steps.length}`;
    [...$("timeline").children].forEach((card, index) => {
      card.classList.toggle("visible", index <= state.step);
      card.classList.toggle("current", index === state.step);
    });
    const current = $("timeline").querySelector(".current");
    if (current) current.scrollIntoView({ block: "nearest", behavior: "smooth" });
    renderAnalysis(item.steps[state.step]);
  }

  function renderAnalysis(step) {
    const analysis = step.analysis || {};
    $("analysisTitle").textContent = step.analysisTitle || step.title;
    $("analysisPill").className = `pill ${analysis.decision === "deny" ? "deny" : analysis.decision === "allow" ? "allow" : analysis.decision === "taint" || analysis.decision === "observe" ? "ask" : "info"}`;
    $("analysisPill").textContent = analysis.pill || step.tone;
    const facts = (analysis.facts || []).map(([k, v]) => `<span>${escapeHtml(k)}</span><code>${escapeHtml(v)}</code>`).join("");
    const rules = (analysis.rules || []).map((rule) => `<li><code>${escapeHtml(rule)}</code></li>`).join("");
    const notes = (analysis.notes || []).map((note) => `<li>${escapeHtml(note)}</li>`).join("");
    $("analysis").innerHTML = `
      <div class="rule ${analysis.decision === "allow" ? "allow" : analysis.decision === "deny" ? "" : "ask"}">
        <strong>${escapeHtml(analysis.pill || "治理结果")}</strong>
        <p>${escapeHtml(analysis.summary || "")}</p>
      </div>
      ${facts ? `<div class="kv">${facts}</div>` : ""}
      ${rules ? `<h3>命中规则</h3><ul>${rules}</ul>` : ""}
      ${notes ? `<h3>说明</h3><ul>${notes}</ul>` : ""}
    `;
  }

  function togglePlay() {
    if (state.playing) {
      stop();
      return;
    }
    const item = currentCase();
    if (state.step >= item.steps.length - 1) reveal(0);
    state.playing = true;
    playBtn.textContent = "暂停";
    tick();
  }

  function tick() {
    if (!state.playing) return;
    const item = currentCase();
    if (state.step >= item.steps.length - 1) {
      stop();
      return;
    }
    const current = item.steps[state.step];
    const delay = current.tone === "deny" ? 1700 : 1100;
    state.timer = window.setTimeout(() => {
      reveal(state.step + 1);
      tick();
    }, delay);
  }

  function stop() {
    state.playing = false;
    playBtn.textContent = "播放";
    window.clearTimeout(state.timer);
  }

  function escapeHtml(value) {
    return String(value ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;");
  }
})();
