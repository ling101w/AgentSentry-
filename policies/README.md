# policies

策略配置目录。

- `default.yaml`：离线原型使用的默认安全策略，包含工具范围、允许目标、敏感路径和外部 sink 约束。
- OpenClaw 插件的运行时策略主要在 `openclaw-plugin/config.ts` 和运行时配置中维护。

修改策略后应运行：

```bash
pytest -q
npm --prefix openclaw-plugin run test:policy
```
