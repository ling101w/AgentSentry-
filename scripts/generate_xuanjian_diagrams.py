from __future__ import annotations

import html
import math
from pathlib import Path

import cairosvg


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "reports" / "assets" / "diagrams"
W, H = 1920, 1080


def esc(text: object) -> str:
    return html.escape(str(text), quote=True)


def wrap(text: str, width: int = 18) -> list[str]:
    lines: list[str] = []
    for raw in str(text).split("\n"):
        current = ""
        for ch in raw:
            current += ch
            score = sum(1.65 if ord(c) > 127 else 1.0 for c in current)
            if score >= width:
                lines.append(current)
                current = ""
        if current:
            lines.append(current)
    return lines or [""]


def text_block(x: int, y: int, text: str, size: int = 32, color: str = "#eaf7ff", weight: int = 700,
               width: int = 22, line_h: int | None = None, anchor: str = "start", cls: str = "") -> str:
    line_h = line_h or int(size * 1.38)
    lines = wrap(text, width)
    out = [f'<text x="{x}" y="{y}" fill="{color}" font-size="{size}" font-weight="{weight}" '
           f'text-anchor="{anchor}" class="{cls}">']
    for i, line in enumerate(lines):
        dy = 0 if i == 0 else line_h
        out.append(f'<tspan x="{x}" dy="{dy}">{esc(line)}</tspan>')
    out.append("</text>")
    return "\n".join(out)


def box(x: int, y: int, w: int, h: int, title: str, body: str = "", accent: str = "#46d9ff",
        fill: str = "#0b2230", title_size: int = 34, body_size: int = 24, width: int = 20,
        radius: int = 22) -> str:
    return f"""
    <g>
      <rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{radius}" fill="{fill}" stroke="{accent}" stroke-width="2.4" filter="url(#softShadow)"/>
      <rect x="{x}" y="{y}" width="8" height="{h}" rx="4" fill="{accent}" opacity="0.95"/>
      {text_block(x + 28, y + 48, title, title_size, "#ffffff", 900, width)}
      {text_block(x + 28, y + 96, body, body_size, "#b9d6e6", 500, width + 4, int(body_size * 1.45))}
    </g>
    """


def pill(x: int, y: int, text: str, color: str = "#46d9ff", w: int = 210, h: int = 46) -> str:
    return f"""
    <g>
      <rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{h // 2}" fill="{color}" opacity="0.18" stroke="{color}" stroke-width="1.6"/>
      {text_block(x + w // 2, y + 31, text, 21, "#eaf7ff", 800, 18, anchor="middle")}
    </g>
    """


def arrow(x1: int, y1: int, x2: int, y2: int, color: str = "#46d9ff", width: int = 4,
          dash: bool = False, label: str = "") -> str:
    midx = (x1 + x2) // 2
    midy = (y1 + y2) // 2
    dash_attr = 'stroke-dasharray="12 10"' if dash else ""
    label_svg = text_block(midx, midy - 12, label, 20, color, 800, 18, anchor="middle") if label else ""
    return f"""
    <g>
      <line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{color}" stroke-width="{width}" stroke-linecap="round" {dash_attr} marker-end="url(#{'arrowRed' if color == '#ff6074' else 'arrow'})"/>
      {label_svg}
    </g>
    """


def base(title: str, subtitle: str = "") -> str:
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">
    <defs>
      <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
        <stop offset="0" stop-color="#06131d"/><stop offset="0.52" stop-color="#092231"/><stop offset="1" stop-color="#0d1a2b"/>
      </linearGradient>
      <radialGradient id="halo" cx="50%" cy="45%" r="62%">
        <stop offset="0" stop-color="#1dd9ff" stop-opacity="0.24"/><stop offset="1" stop-color="#1dd9ff" stop-opacity="0"/>
      </radialGradient>
      <filter id="softShadow" x="-20%" y="-20%" width="140%" height="150%">
        <feDropShadow dx="0" dy="16" stdDeviation="18" flood-color="#000000" flood-opacity="0.34"/>
      </filter>
      <marker id="arrow" markerWidth="12" markerHeight="12" refX="10" refY="6" orient="auto">
        <path d="M2,2 L10,6 L2,10 Z" fill="#46d9ff"/>
      </marker>
      <marker id="arrowRed" markerWidth="12" markerHeight="12" refX="10" refY="6" orient="auto">
        <path d="M2,2 L10,6 L2,10 Z" fill="#ff6074"/>
      </marker>
      <style>
        text {{ font-family: "Noto Sans CJK SC", "Noto Sans SC", "Microsoft YaHei", sans-serif; letter-spacing: 0; }}
        .mono {{ font-family: "Noto Sans Mono CJK SC", "Noto Sans Mono", monospace; }}
      </style>
    </defs>
    <rect width="{W}" height="{H}" fill="url(#bg)"/>
    <rect width="{W}" height="{H}" fill="url(#halo)"/>
    <g opacity="0.10">
      {''.join(f'<line x1="{i}" y1="0" x2="{i}" y2="{H}" stroke="#8ee8ff"/>' for i in range(80, W, 80))}
      {''.join(f'<line x1="0" y1="{i}" x2="{W}" y2="{i}" stroke="#8ee8ff"/>' for i in range(80, H, 80))}
    </g>
    {text_block(92, 86, title, 48, "#ffffff", 950, 42)}
    {text_block(94, 132, subtitle, 25, "#9bcfe4", 550, 70) if subtitle else ""}
    """


def end() -> str:
    return "</svg>\n"


def diagram_four_domains() -> str:
    cx, cy = 960, 560
    svg = base("玄鉴：四域一环总体架构", "面向 OpenClaw 工具调用链的实时行为监督与风险拦截系统")
    svg += f"""
    <circle cx="{cx}" cy="{cy}" r="360" fill="none" stroke="#2ee6ff" stroke-width="4" opacity="0.34"/>
    <circle cx="{cx}" cy="{cy}" r="286" fill="none" stroke="#35f29b" stroke-width="5" stroke-dasharray="18 16" opacity="0.65"/>
    <text x="{cx}" y="{cy - 320}" fill="#35f29b" font-size="28" font-weight="900" text-anchor="middle">证据回流闭环 Evidence Feedback</text>
    <rect x="{cx - 210}" y="{cy - 110}" width="420" height="220" rx="30" fill="#102a3a" stroke="#ffffff" stroke-width="2.2" filter="url(#softShadow)"/>
    {text_block(cx, cy - 30, "OpenClaw Agent Runtime", 36, "#ffffff", 950, 28, anchor="middle")}
    {text_block(cx, cy + 18, "想法与动作分离：所有工具调用先过玄鉴治理", 24, "#b9d6e6", 550, 24, anchor="middle")}
    {pill(cx - 310, cy + 145, "ALLOW 放行", "#35f29b", 190)}
    {pill(cx - 96, cy + 145, "ASK 审批", "#f8b84e", 170)}
    {pill(cx + 100, cy + 145, "DENY 阻断", "#ff6074", 180)}
    """
    domains = [
        (140, 220, 390, 230, "上下文溯源域", "外部网页、邮件、PDF、图像、工具返回统一打来源标签；隐藏文本只允许被总结，不能驱动高危动作。", "#46d9ff"),
        (1390, 220, 390, 230, "状态完整性域", "MEMORY.md、openclaw.json、Skill、启动项等持久化状态进入护照、哈希、隔离与回滚检查。", "#a77cff"),
        (140, 670, 390, 230, "意图授权域", "由用户请求生成 TaskSpec，结合 ABAC 检查工具、目标、收件人和路径是否仍在授权范围。", "#f8b84e"),
        (1390, 670, 390, 230, "工具边界域", "文件读写、邮件、API、Shell 执行先做策略裁决；高危面联动 eBPF 运行时观测。", "#ff6074"),
    ]
    for item in domains:
        svg += box(*item)
    svg += arrow(532, 325, 750, 470)
    svg += arrow(1388, 325, 1170, 470)
    svg += arrow(532, 785, 750, 650)
    svg += arrow(1388, 785, 1170, 650)
    techs = [
        (650, 225, "签名信任标签"),
        (885, 225, "动态污点传播"),
        (1120, 225, "风险特征图谱"),
        (640, 860, "TaskSpec"),
        (810, 860, "ABAC"),
        (975, 860, "LLM-Judge"),
        (1190, 860, "eBPF 审计"),
    ]
    for x, y, t in techs:
        svg += pill(x, y, t, "#46d9ff", 150 if len(t) < 7 else 200)
    svg += text_block(92, 1018, "图 1  四域一环：四个治理域分别覆盖上下文、状态、意图和工具边界；证据回流把工具结果、污点和运行时观测写回后续决策。", 23, "#9bcfe4", 600, 120)
    return svg + end()


def diagram_runtime_flow() -> str:
    svg = base("OpenClaw 嵌入与旁路监督流程", "玄鉴在消息、记忆、工具调用和运行时四个关键位置形成内联拦截与旁路审计")
    y = 250
    steps = [
        (80, y, "用户/环境输入", "中文指令、网页、邮件、PDF、图像、历史回放", "#46d9ff"),
        (360, y, "上下文入口", "净化、来源标记、隐藏内容识别、Trust Label", "#46d9ff"),
        (640, y, "TaskSpec", "抽取用户授权任务、允许工具、目标和输出策略", "#f8b84e"),
        (920, y, "工具调用前", "规则、风险向量、ABAC、污点流向检查", "#f8b84e"),
        (1200, y, "风险分级", "仅高风险语义场景调用 LLM-Judge", "#a77cff"),
        (1480, y, "执行控制", "放行 / 审批 / 阻断；高危面做 eBPF 预检与审计", "#ff6074"),
    ]
    for x, yy, title, body, color in steps:
        svg += box(x, yy, 240, 210, title, body, color, width=10, title_size=28, body_size=20)
    for i in range(len(steps) - 1):
        svg += arrow(steps[i][0] + 240, y + 105, steps[i + 1][0], y + 105)
    svg += box(168, 650, 320, 180, "内联插件", "OpenClaw 消息入口与工具调用前钩子：落地前强制裁决。", "#35f29b", width=15)
    svg += box(590, 650, 320, 180, "旁路观测", "dashboard、records、eBPF 日志持续记录真实事件。", "#46d9ff", width=15)
    svg += box(1012, 650, 320, 180, "证据回写", "工具结果被重新打标，污染、信任和基线进入下一轮判断。", "#f8b84e", width=15)
    svg += box(1434, 650, 320, 180, "监督端展示", "实时告警、拓扑、时间线、审批记录和 benchmark 留痕。", "#a77cff", width=15)
    svg += arrow(328, 460, 328, 650, "#35f29b", label="嵌入")
    svg += arrow(1600, 460, 1600, 650, "#46d9ff", label="旁路")
    svg += arrow(1172, 650, 1015, 468, "#f8b84e", dash=True, label="反馈")
    svg += text_block(92, 1018, "图 2  内联负责拦截，旁路负责观测；二者共享同一份审计记录和策略状态，保证演示数据来自真实工具调用。", 23, "#9bcfe4", 600, 120)
    return svg + end()


def diagram_taint_abac() -> str:
    svg = base("污点传播与 ABAC 授权判定", "外部内容可以被读取和总结，但不可信数据不能流向敏感读取、外发、执行或持久化工具")
    svg += box(100, 250, 360, 210, "有毒外部内容", "邮件白字、网页零尺寸 span、PDF 透明层、图片元数据隐藏指令。", "#ff6074", width=17)
    svg += box(560, 250, 350, 230, "只读摄取", "邮件读取、网页读取、PDF 解析、图片分析默认允许完成业务分析。", "#35f29b", width=15)
    svg += box(1010, 250, 350, 230, "污点标签", "来源=外部网页/邮件\n完整性=已污染\n密级=公开或机密\n禁止流向=外发、执行、持久化", "#46d9ff", width=15)
    svg += box(1460, 250, 350, 230, "高危工具", "敏感文件读取\n外部邮件发送\n非白名单 API\nShell 执行", "#ff6074", width=15)
    svg += arrow(460, 355, 560, 355)
    svg += arrow(910, 355, 1010, 355)
    svg += arrow(1360, 355, 1460, 355, "#ff6074", label="流向检查")
    svg += box(265, 650, 420, 190, "TaskSpec", "来自用户原始任务：例如“只总结邮件，不执行邮件内额外指令”。", "#f8b84e", width=18)
    svg += box(750, 650, 420, 190, "ABAC 判定", "主体=Agent；客体=工具、路径、收件人；环境=会话污点、来源信任、当前任务。", "#a77cff", width=18)
    svg += box(1235, 650, 420, 190, "结果", "低风险读取：ALLOW\n敏感读取/外发/执行：DENY\n边界不清：ASK", "#35f29b", width=20)
    svg += arrow(475, 650, 760, 520, "#f8b84e", dash=True)
    svg += arrow(1130, 650, 1295, 520, "#a77cff", dash=True)
    svg += arrow(1170, 745, 1235, 745)
    svg += text_block(92, 1018, "图 3  玄鉴不是“一看到外部内容就阻断”，而是允许摄取、保留污点，并在高危 sink 前进行 ABAC 流向门禁。", 23, "#9bcfe4", 600, 120)
    return svg + end()


def diagram_llm_ebpf() -> str:
    svg = base("上下文增强 LLM-Judge 与 eBPF 运行时联动", "Judge 负责复杂语义判断，eBPF 负责执行后的系统行为观测；两者都不替代硬策略边界")
    svg += box(90, 240, 470, 510, "LLM-Judge 上下文包", "用户授权任务\nTaskSpec 工具与目标边界\n最近工具轨迹\n污点来源与 Trust Label\nABAC/规则命中\n候选工具参数\n可能后果", "#a77cff", width=19, title_size=34, body_size=28)
    svg += box(725, 260, 470, 250, "DeepSeek 语义裁决", "输出风险等级、置信度、建议动作、证据和风险分类。重点判断隐蔽外发、持久化污染、目标漂移、工具劫持。", "#46d9ff", width=18)
    svg += box(725, 590, 470, 210, "策略融合", "确定性规则 + 污点/ABAC + LLM 语义证据，共同形成放行、审批或阻断。", "#f8b84e", width=18)
    svg += box(1360, 240, 470, 250, "eBPF 观测器", "内核层记录进程执行、文件打开、网络连接等事件，验证工具是否触碰敏感路径、外联或执行命令。", "#35f29b", width=18)
    svg += box(1360, 590, 470, 210, "证据回流", "执行结果、系统事件、污染流和审批记录写入 records，进入下一轮策略状态。", "#35f29b", width=18)
    svg += arrow(560, 470, 725, 385)
    svg += arrow(960, 510, 960, 590, "#f8b84e")
    svg += arrow(1195, 695, 1360, 695, "#35f29b")
    svg += arrow(1595, 490, 1595, 590, "#35f29b")
    svg += arrow(1360, 365, 1195, 365, "#35f29b", dash=True, label="运行时证据")
    svg += pill(628, 860, "非全量：risk-tiered 调度", "#a77cff", 320)
    svg += pill(988, 860, "高危面：内联阻断优先", "#ff6074", 320)
    svg += text_block(92, 1018, "图 4  LLM-Judge 处理复杂语义和上下文关系；eBPF 提供系统层证据。最终执行权仍由玄鉴策略内核掌握。", 23, "#9bcfe4", 600, 120)
    return svg + end()


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    diagrams = {
        "xuanjian-01-four-domains-loop": diagram_four_domains(),
        "xuanjian-02-openclaw-runtime-flow": diagram_runtime_flow(),
        "xuanjian-03-taint-abac-flow": diagram_taint_abac(),
        "xuanjian-04-llmjudge-ebpf-loop": diagram_llm_ebpf(),
    }
    for name, svg in diagrams.items():
        svg_path = OUT / f"{name}.svg"
        png_path = OUT / f"{name}.png"
        svg_path.write_text(svg, encoding="utf-8")
        cairosvg.svg2png(bytestring=svg.encode("utf-8"), write_to=str(png_path), output_width=W, output_height=H)
        print(png_path.relative_to(ROOT))


if __name__ == "__main__":
    main()
