# 精神状态 CPI 测评

前端托管在 GitHub Pages，密码额度和结果由 Supabase Edge Function + Postgres 管理。

## 首次部署需要的账号操作

1. 在 Supabase 创建一个项目，并在 Authentication → Users 中创建管理员用户（邮箱需要与 `CPI_ADMIN_EMAIL` 一致）。
2. 在 GitHub 创建一个空仓库，把本项目推送到仓库的 `main` 分支。
3. 在仓库 Settings → Secrets and variables → Actions 添加以下 Repository secrets：
   - `SUPABASE_URL`
   - `SUPABASE_ANON_KEY`
   - `SUPABASE_SERVICE_ROLE_KEY`
   - `SUPABASE_ACCESS_TOKEN`
   - `SUPABASE_PROJECT_REF`
   - `SUPABASE_DB_URL`（Supabase 项目的 Postgres connection string）
   - `CPI_ADMIN_EMAIL`（已提供：`zy313657@gmail.com`）
   - `CPI_SITE_ORIGIN`（网站的 origin，例如 `https://你的GitHub用户名.github.io`，不要附加仓库路径）
4. Actions 会自动推送数据库迁移、部署 Edge Function 和 GitHub Pages。首次启用 Pages 时，在仓库 Settings → Pages 中选择 GitHub Actions。
5. 在 Supabase Authentication → URL Configuration 中把 GitHub Pages 网站地址加入 Site URL / Redirect URLs。

## 部署后

- 测评页：GitHub Pages 项目地址
- 管理后台：项目地址后加 `/admin.html`
- 示例密码：`CPI-START-2026`，额度 3 次
- 管理后台使用步骤 1 创建的 Supabase Auth 邮箱和密码登录。

## 本地预览

本地 Python 服务仍可通过 `python3 server.py` 启动。若本地也要直连 Supabase，把 `supabase-config.js.example` 复制为 `supabase-config.js` 并填入项目 URL 和 anon key；该文件已加入 `.gitignore`。

**安全提示：** Supabase anon key 是公开客户端 key，可随静态前端发布；绝不要把 service role key、数据库密码或 Supabase access token 放进前端文件。它们只通过 GitHub Actions secrets 配置。
