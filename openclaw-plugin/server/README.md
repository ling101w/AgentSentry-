# openclaw-plugin/server

8765 插件内置 HTTP 服务。

`dashboard.ts` 提供：

- 静态页面服务。
- 运行记录、统计、告警和安全大屏 API。
- `/api/lab/command` 业务测试接口。
- `/api/lab/benchmarks` 公开 benchmark 样例浏览接口。
- 运行模式切换和导出接口。

这里不直接实现策略算法，策略逻辑由 `openclaw-plugin/core/` 提供。
