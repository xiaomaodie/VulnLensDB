# VulnLensDB

数据库系统课程项目。系统用 MySQL 8 整合 PyPI、Maven 和 Go 的 OSV 公告、NVD CVE 样本与 deps.dev 发行记录和依赖图。网页提供软件包搜索、逐版本漏洞查询、公告检索、依赖清单检查与统计。

## 打开和运行

继续使用仓库已有的 GitHub Codespace。已有环境同步更新后，在云端终端运行：

```bash
git pull --ff-only
python -m pip install -r requirements.txt
bash .devcontainer/start.sh
```

在 **端口** 面板打开启动脚本提示的端口。默认是 5000，当前答辩演示使用同一环境的 5001。已有旧进程占用端口时，先停止旧应用进程，再启动新版。数据库连通检查位于 `/health/db`。使用完毕后可在 GitHub Codespaces 停止环境以节省额度。

## 答辩演示

1. 首页搜 **pillow**，选择 PyPI 的 Pillow。打开「只看有命中的版本」，点 **12.3.0** 查看公告、严重程度及已记录的修复版本。
2. 从「公告目录」搜 `CVE-2021-44228`，查看 OSV 版本区间与 NVD 的产品配置，沿来源链接复核。
3. 在「依赖检查」上传 UTF-8 的 `requirements.txt` 或固定版本的直接依赖 `pom.xml`，检查后导出 CSV。
4. 在「统计查询」打开 Q6 下游依赖影响面和 Q9 Scorecard 分层，展开实际 SQL。

## 数据和验收

固定快照保存在 `data/library/`，包含 19,447 条去重公告、6,700 个软件包及 39,545 段区间。NVD 包含 66 条 CVE，依赖图取自 20 个根版本。版本列表来自 deps.dev 或 OSV 版本证据，具体来源显示在页面。结果覆盖本批数据。

`python -m backend.library_db` 加载固定快照。相同快照会跳过重复导入。`python -m tools.collect_library` 可重新采集。`python -m pytest -q` 在云端运行测试。`python -m tools.verify_library` 重跑全量真实关联索引实验。`python -m tools.benchmark build/benchmark.json` 重跑独立的百万行合成实验。

## 提交材料

- [课程报告 Word](submission/VulnLensDB-report.docx) · [PDF](submission/VulnLensDB-report.pdf)
- [答辩演示 PowerPoint](submission/VulnLensDB-defense.pptx) · [PDF](submission/VulnLensDB-defense.pdf)
- [全量真实数据的索引实验](submission/library-evidence.json) · [百万行合成实验](submission/benchmark.json)
- [扩展版实现说明](docs/implementation.md)

报告保留了姓名、学号、组号和个人贡献栏。请在交课程平台前据实填写。
