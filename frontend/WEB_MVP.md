# VulnShield Web MVP

这个 MVP 把 `frontend/` 静态原型升级为本地 Web 控制台：

- 托管前端页面
- 读取 `result/scan_summary.json` 与 `result/*.report.json`
- 通过后端 API 启动 `python main.py` 扫描任务
- 在前端展示真实统计、漏洞、报告、任务日志

## 启动

```powershell
python web_mvp.py --host 127.0.0.1 --port 8765
```

打开：

```text
http://127.0.0.1:8765/
```

## 常用 API

- `GET /api/health`
- `GET /api/summary`
- `GET /api/reports`
- `GET /api/reports/{report_id}`
- `GET /api/findings`
- `GET /api/scans`
- `GET /api/scans/{scan_id}`
- `POST /api/scans`
- `GET /api/code-context?file=api.c&line=12`

## 启动扫描示例

```powershell
$body = @{
  mode = "scan"
  root = "dataset/multi_c_project"
  parallel = 1
  max_files = 1
  c_workspace_cpg = $false
} | ConvertTo-Json

Invoke-WebRequest `
  -Method POST `
  -ContentType "application/json" `
  -Body $body `
  http://127.0.0.1:8765/api/scans
```

## 说明

扫描仍然依赖现有 CLI 能力和环境配置，包括 Joern 与 LLM。MVP 后端使用 Python 标准库实现，没有新增 Python 依赖。

为避免多个扫描同时覆盖 `result/scan_summary.json`，当前适合本地单人调试和演示。生产化时建议改为每次扫描写入独立 `result/runs/{job_id}/`。
