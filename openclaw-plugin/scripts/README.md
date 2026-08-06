# openclaw-plugin/scripts

OpenClaw 插件构建和烟测脚本。

- `build.mjs`：构建 TypeScript 插件到 `dist/`。
- `policy-smoke.mjs`：核心策略烟测。
- `security-smoke.mjs`：已修安全漏洞的回归测试。
- `property-fuzz.mjs`：URL、路径、工具规范化、capability、taint、session 和 semantic cache 的可复现属性测试。

常用命令：

```bash
npm --prefix openclaw-plugin run build
npm --prefix openclaw-plugin run test:policy
npm --prefix openclaw-plugin run test:property
```
