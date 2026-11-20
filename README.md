# VulnLensDB

开源依赖漏洞多源整合数据库课程演示。MySQL 8 存储 PyPI 公告及版本区间，Flask 提供中文目录、公告详情、依赖清单检查与统计。演示使用仓库中固定的三源快照，启动时无需重新访问外部数据接口。

## 在已有 Codespace 运行

在仓库根目录执行以下命令。新建环境会自动安装依赖、导入数据并启动服务。已有环境从旧版升级时，可在拉取代码后停止并重新打开该 Codespace，使旧版 Flask 退出。

```bash
git pull --ff-only
bash .devcontainer/start.sh
python -m pytest -q
```

打开 **端口 → 5000** 进入首页。健康检查位于 `/health/db`。使用完毕后在 GitHub Codespaces 页面停止环境，以节省计算额度。

## 五分钟演示

1. 首页按 `PYSEC-2022-190` 搜索，打开 Django 公告。观察同一公告的三段区间、别名及三个来源。
2. 在“依赖检查”中对比 `django==3.2.9` 和 `django==3.2.13`，前者命中，后者等于修复端点。再输入 `flask==3.0`，观察“包未收录”。
3. 在“统计查询”切换 CVE 对齐、风险排名、修复时间线和证据覆盖。SQL 在 `backend/views.py`。
4. 在云端终端运行 `python -m pytest -q` 验证页面和查询结果。

## 数据与复现

`data/snapshot.json` 保留采集时间、OSV 修改时间、NVD 评分提供方、修复版本和 deps.dev 链接。刷新命令为 `python tools/collect.py`，成功后运行 `python -m backend.catalog`。导入器在一次事务中替换此课程专用的七张表。查询仅覆盖快照中的公告；未命中不能证明依赖安全。

[修订方案、表关系与查询对照](docs/方案G-修订版.md)

## 提交材料

- [课程报告（Word）](submission/VulnLensDB-report.docx) · [PDF 阅读版](submission/VulnLensDB-report.pdf)
- [答辩演示（PowerPoint）](submission/VulnLensDB-defense.pptx) · [PDF 阅读版](submission/VulnLensDB-defense.pdf)
- [MySQL 实验记录](submission/benchmark.json)，含完整执行计划及每次查询耗时。合成数据仅用于性能实验，业务页面使用三源真实快照。

在 **Actions → Build course materials → Run workflow** 可重新生成材料。报告、幻灯片和原始结果来自同一次运行。提交课程平台前请在 Word 中填写姓名、学号及个人贡献。
