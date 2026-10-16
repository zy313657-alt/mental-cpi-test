#!/bin/bash
set -e
cd "$(dirname "$0")"
if ! curl -fsS --max-time 1 http://127.0.0.1:8000/api/admin/session >/dev/null 2>&1; then
  python3 server.py
else
  open http://127.0.0.1:8000/
  echo "CPI 测评服务已在运行。"
  echo "测评页：http://127.0.0.1:8000/"
  echo "管理后台：http://127.0.0.1:8000/admin"
  read -r -p "按回车键关闭此窗口..."
fi
