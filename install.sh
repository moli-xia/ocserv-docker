#!/bin/bash

set -euo pipefail

REPO_URL="https://github.com/moli-xia/ocserv-docker"
RAW_BASE_URL="https://raw.githubusercontent.com/moli-xia/ocserv-docker/main"
BOOTSTRAP_DIR="${OCSERV_BOOTSTRAP_DIR:-/opt/ocserv-docker-bootstrap}"

print_message() {
    echo "[INFO] $1"
}

print_warning() {
    echo "[WARN] $1"
}

print_error() {
    echo "[ERROR] $1" >&2
}

require_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        print_error "请使用 root 用户运行此脚本。"
        exit 1
    fi
}

download_with_curl() {
    local source_url="$1"
    local target_file="$2"

    curl -fsSL "$source_url" -o "$target_file"
}

download_with_wget() {
    local source_url="$1"
    local target_file="$2"

    wget -qO "$target_file" "$source_url"
}

download_deploy_script() {
    local target_file="$1"
    local source_url="${RAW_BASE_URL}/ocserv_deploy.sh"

    if command -v curl >/dev/null 2>&1; then
        download_with_curl "$source_url" "$target_file"
        return 0
    fi

    if command -v wget >/dev/null 2>&1; then
        download_with_wget "$source_url" "$target_file"
        return 0
    fi

    print_error "未检测到 curl 或 wget，无法自动下载主部署脚本。"
    exit 1
}

main() {
    require_root

    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    local deploy_script=""
    if [[ -f "${script_dir}/ocserv_deploy.sh" ]]; then
        deploy_script="${script_dir}/ocserv_deploy.sh"
        print_message "检测到本地 ocserv_deploy.sh，直接使用仓库内脚本。"
    else
        mkdir -p "$BOOTSTRAP_DIR"
        deploy_script="${BOOTSTRAP_DIR}/ocserv_deploy.sh"
        print_message "正在从 ${REPO_URL} 下载最新部署脚本..."
        download_deploy_script "$deploy_script"
    fi

    chmod +x "$deploy_script"

    print_message "即将启动 OCserv 部署脚本: ${deploy_script}"
    if [[ "$#" -gt 0 ]]; then
        print_message "透传参数: $*"
    else
        print_warning "未传入参数，将进入交互式菜单。"
    fi

    exec bash "$deploy_script" "$@"
}

main "$@"
