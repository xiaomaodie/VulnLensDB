# VulnLensDB 云端开发起步环境

开源依赖漏洞多源整合数据库课程作业。当前仅包含 Codespaces 开发环境和 Flask 连通检查接口；业务表、数据采集、Q1–Q9 和前端尚未实现。

## 在浏览器中启动

1. 将本目录内的文件提交到 GitHub 仓库根目录，包括隐藏的 `.devcontainer` 目录。
2. 打开仓库，选择 **Code → Codespaces → Create codespace on main**（分支名以实际为准）。
3. 等待环境创建、MySQL 健康检查和 Python 依赖安装完成。
4. 环境会自动启动 Flask 后端。在 **Ports** 中打开 5000 端口，在浏览器地址后加 `/health`，应返回 `status: ok`；访问 `/health/db` 应返回 MySQL 版本。
5. 若需要手动启动，在 Codespaces 终端执行：

```bash
bash .devcontainer/start.sh
```

当前 Flask 内置服务用于开发演示；长期托管时需改用生产 WSGI 服务。启动日志位于 `/tmp/vulnlens-api.log`。

MySQL 运行在同一云端环境的独立容器中，主机名为 `db`。不需要使用本机 MySQL，也不需要向公网开放 3306。Node.js 在创建环境时自动安装，后续用于前端。

## 自动检查

提交代码后，仓库 **Actions → Check cloud environment** 会启动独立的 MySQL 8.0 服务、安装 Python 依赖并运行真实数据库连通测试。该检查通过表示起步后端能连接 MySQL，不代表作业业务功能已经完成。

也可在 Codespaces 终端运行 `python -m pytest -q`。未提供数据库密码时该集成测试会跳过。

## 数据保留和成本

- 这是开发和临时演示环境，停止 Codespace 后接口无法访问。关闭浏览器不等于停止环境，请在 GitHub 的 Codespaces 页面主动停止。
- 数据库使用 Docker 命名卷；删除 Codespace 或卷会丢失数据库，不应把它当作唯一备份。重要数据请导出并下载到本机。
- Codespaces 有计算和存储配额，使用前检查账户的 Billing 页面。这里不自动开通付费资源。
- Compose 中的密码仅供隔离的开发环境使用；长期公开部署时应使用平台 Secrets 设置独立密码。
- 原始数据、数据库备份和 `.env` 不提交 GitHub；已有课程材料也无需上传。

## 下一步

1. 对照课程模板完成 E-R 图、数据字典和建表 SQL。
2. 用 PyPI 小批真实数据跑通 OSV → 清洗 → MySQL → 包版本查询。
3. 接入 deps.dev 和 NVD，完成别名对齐、版本判定和来源追溯。
4. 完成 Q1–Q9、前端、索引优化实验和课程报告。
