const VERDICT_META = Object.freeze({
  deny: Object.freeze({
    key: "deny",
    code: "DENY",
    label: "阻断",
    tone: "danger",
    icon: "shield-x",
    summary: "请求未越过执行边界",
  }),
  review: Object.freeze({
    key: "review",
    code: "REVIEW",
    label: "待确认",
    tone: "warning",
    icon: "clock-alert",
    summary: "执行已暂停，等待人工裁决",
  }),
  allow: Object.freeze({
    key: "allow",
    code: "ALLOW",
    label: "放行",
    tone: "safe",
    icon: "shield-check",
    summary: "行为符合当前任务边界",
  }),
  observe: Object.freeze({
    key: "observe",
    code: "OBSERVE",
    label: "已记录",
    tone: "neutral",
    icon: "eye",
    summary: "行为已进入审计链路",
  }),
});

export function normalizeVerdict(value) {
  const text = String(value || "").trim().toLowerCase();
  if (["block", "blocked", "deny", "denied", "reject", "rejected", "block_mode"].includes(text)) return "deny";
  if (["ask", "review", "pending", "require_approval", "approval", "approval_mode"].includes(text)) return "review";
  if (["allow", "allowed", "pass", "passed", "success"].includes(text)) return "allow";
  return "observe";
}

export function verdictMeta(value) {
  return VERDICT_META[normalizeVerdict(value)] || VERDICT_META.observe;
}

export function verdictCode(value) {
  return verdictMeta(value).code;
}

export function verdictLabel(value) {
  return verdictMeta(value).label;
}

export function verdictTone(value) {
  return verdictMeta(value).tone;
}
