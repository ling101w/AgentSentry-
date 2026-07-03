# openclaw-plugin/scripts

OpenClaw 插件构建和烟测脚本。

- `build.mjs`：构建 TypeScript 插件到 `dist/`。
- `policy-smoke.mjs`：核心策略烟测。

常用命令：

```bash
npm --prefix openclaw-plugin run build
npm --prefix openclaw-plugin run test:policy
```
