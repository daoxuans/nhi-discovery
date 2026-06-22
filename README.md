# NHI Discovery — 双引擎 AI 资产发现后端

被动发现（Probe，nDPI+nDPIsrvd C 管线）+ 主动发现（Scan，nmap+aiohttp）+ 双源融合。

## 部署

**环境**：Ubuntu 22.04/24.04，Python 3.12，nmap，root（nmap -sS 需要）。

**C 管线前置**：nDPId 抓 ens64 → nDPIsrvd → `/tmp/ndpid-distributor.sock`（已在 192.168.1.111 运行，nobody 用户）。

**后端部署**：

```bash
cd /opt/nhi-discovery/backend
source venv/bin/activate  # 已装 fastapi/uvicorn/pydantic/aiohttp/apscheduler/mmh3
# 启动（默认不开 ScanScheduler，手动触发扫描）
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000

# 启用自动扫描调度（full scan 00:00-06:00/30min，增量 */5min）
SCAN_SCHEDULER_ENABLED=1 python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## 配置

环境变量（`app/config.py`）：

| 变量 | 默认 | 说明 |
|------|------|------|
| `DB_PATH` | `/opt/nhi-discovery/backend/data/ndpid.db` | SQLite 路径 |
| `DISTRIBUTOR_SOCKET` | `/tmp/ndpid-distributor.sock` | nDPIsrvd socket |
| `NDPISRVD_PY` | `/opt/nDPId/dependencies/nDPIsrvd.py` | nDPIsrvd.py 路径 |
| `SCAN_SCHEDULER_ENABLED` | `0` | 启用自动扫描调度 |
| `SCAN_GLOBAL_PPS` | `500` | nmap 全局包速率 |
| `SCAN_PER_TARGET_QPS` | `10` | 单目标连接速率 |
| `SCAN_CONCURRENCY` | `64` | 并发探测数 |
| `RETENTION_FLOWS_DAYS` | `90` | flows 保留天数 |
| `RETENTION_AI_EVENTS_DAYS` | `180` | ai_events 保留天数 |

## API

| 端点 | 说明 |
|------|------|
| `GET /api/v1/health` | 健康检查 + 各表行数 |
| `GET /api/v1/flows` | 流量历史（分页） |
| `GET /api/v1/flows/stats` | 协议/分类/检测率聚合 |
| `GET /api/v1/ai/events` | AI 事件流水（Probe） |
| `GET /api/v1/ai/events/stats?time_range=1h` | AI 统计聚合 |
| `GET /api/v1/ai/endpoints` | AI 端点资产（Probe） |
| `GET /api/v1/ai/endpoint/{ip}` | 单 IP AI 画像 |
| `POST /api/v1/scan/trigger` | 手动触发扫描 `{"cidr":"192.168.1.0/24"}` |
| `GET /api/v1/scan/task/{id}` | 扫描任务状态 |
| `GET /api/v1/scan/findings` | 扫描发现明细 |
| `GET /api/v1/scan/services` | Scan 侧 AI 服务资产 |
| `GET /api/v1/scan/cve?service=Ollama` | CVE 查询 |
| `GET /api/v1/scan/targets` | 扫描目标配置 |
| `GET /api/v1/assets/fused?source=both` | **双源融合资产视图** |

## 架构

```
app/
├── core/          # 融合层（共享）
│   ├── db.py            # 9 表 schema + 查询方法
│   ├── asset_model.py   # 生命周期状态机
│   ├── fusion.py        # 置信度矩阵 + 权威源裁决
│   └── retention.py     # 每日 02:00 清理
├── probe/         # 被动发现
│   ├── event_consumer.py # nDPIsrvd socket + JSON filter
│   ├── db_writer.py      # flows 批量写入
│   ├── ai_writer.py      # ai_events + ai_endpoints 持久化
│   ├── ai_service.py     # 135 规则服务发现（纯函数）
│   └── ai_agent.py       # 60 规则 Agent 推断（纯函数）
├── scan/          # 主动发现
│   ├── scan_runner.py    # 5 Prober 编排
│   ├── scheduler.py      # APScheduler 定时
│   ├── result_correlator.py # 双源融合
│   ├── target_manager.py / rate_limiter.py
│   ├── cve_updater.py    # CVE 种子 + NVD
│   └── workers/          # port/api/web/container/version Prober
└── routers/       # REST API
    ├── stats.py / ai.py / scan.py / assets.py
```

## 双源融合

融合键：`Scan.ai_services.ip ←→ Probe.ai_endpoints.ip (role=service)`

| Scan | Probe | 融合置信度 |
|------|-------|----------|
| 命中(端口+API) | 有流量 | **0.95** 双源一致 |
| 命中(端口+API) | 无流量 | 0.75 静默服务 |
| 未命中 | 有流量 | 0.60 Probe 单源 |
| 命中 A | 流量指向 B | 0.30 冲突 |

权威源：版本/CVE/端口归 Scan，Agent/频率归 Probe。

## 生命周期

`active → dormant → decommissioned`
- active→dormant：连续 3 轮 Scan 未发现 + Probe 7 天无流量
- dormant→decommissioned：dormant 持续 30 天
- 复活：任一源重新发现 → active

## 回滚

```bash
# 新后端出问题，恢复旧后端（C 管线无需重启）
cd /opt/ndpid-web-console.bak/backend && venv/bin/uvicorn app.main:app
```
