#!/bin/bash

# ocserv Docker 部署脚本 - 支持与nginx/OpenResty共存
# 支持快速部署和自定义部署
# 支持Let's Encrypt证书自动申请和续期

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 全局变量
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OCSERV_CONFIG_DIR="/opt/ocserv"
DEFAULT_CONTAINER_NAME="ocserv"
DEFAULT_USERNAME="NoRoute"
DEFAULT_PASSWORD="654321"
DEFAULT_OCSERV_CONTAINER_PORT="443"
REPO_URL="https://github.com/moli-xia/ocserv-docker"

# 防火墙和端口管理函数
manage_firewall() {
    print_message "配置防火墙和端口..."

    open_port_with_bt_panel 80 tcp http-80 || true
    open_port_with_bt_panel 443 tcp https-443 || true
    open_port_with_bt_panel 443 udp https-443-udp || true
    
    # 检测防火墙类型并开启端口
    if command -v ufw >/dev/null 2>&1; then
        print_message "检测到UFW防火墙，开启端口80和443..."
        ufw allow 80/tcp >/dev/null 2>&1
        ufw allow 443/tcp >/dev/null 2>&1
        ufw allow 443/udp >/dev/null 2>&1
        print_message "UFW防火墙端口已开启"
    elif command -v firewall-cmd >/dev/null 2>&1; then
        print_message "检测到firewalld防火墙，开启端口80和443..."
        firewall-cmd --permanent --add-port=80/tcp >/dev/null 2>&1
        firewall-cmd --permanent --add-port=443/tcp >/dev/null 2>&1
        firewall-cmd --permanent --add-port=443/udp >/dev/null 2>&1
        firewall-cmd --reload >/dev/null 2>&1
        print_message "firewalld防火墙端口已开启"
    elif command -v iptables >/dev/null 2>&1; then
        print_message "检测到iptables防火墙，开启端口80和443..."
        iptables -I INPUT -p tcp --dport 80 -j ACCEPT >/dev/null 2>&1
        iptables -I INPUT -p tcp --dport 443 -j ACCEPT >/dev/null 2>&1
        iptables -I INPUT -p udp --dport 443 -j ACCEPT >/dev/null 2>&1
        # 尝试保存iptables规则
        if command -v iptables-save >/dev/null 2>&1; then
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        fi
        print_message "iptables防火墙端口已开启"
    else
        print_warning "未检测到已知的防火墙，请手动确保端口80和443已开启"
    fi
    
    # 检查云服务商安全组提示
    print_warning "如果您使用的是云服务器（如阿里云、腾讯云、AWS等），请确保在安全组中开启了80和443端口！"
}

# 端口共存相关函数
check_port_availability() {
    local port="$1"
    if netstat -tlnp 2>/dev/null | grep -q ":$port "; then
        return 1  # 端口被占用
    else
        return 0  # 端口可用
    fi
}

find_available_port() {
    local start_port="$1"
    local port="$start_port"
    
    while ! check_port_availability "$port"; do
        port=$((port + 1))
        if [ $port -gt 65535 ]; then
            return 1  # 没有可用端口
        fi
    done
    echo "$port"
}

resolve_vpn_host_port() {
    local preferred_port="${1:-443}"
    local fallback_start="$preferred_port"

    if [[ "$preferred_port" == "443" ]]; then
        fallback_start="8443"
    fi

    if check_port_availability "$preferred_port"; then
        echo "$preferred_port"
        return 0
    fi

    local available_port
    available_port=$(find_available_port "$fallback_start") || return 1

    print_warning "检测到宿主机端口 $preferred_port 已被占用，已自动切换到端口 $available_port。宿主机 nginx 可继续监听 443。" >&2
    echo "$available_port"
}

setup_port_coexistence() {
    local domain="$1"
    local container_name="$2"

    print_message "设置端口共存模式..." >&2

    local ocserv_port
    ocserv_port=$(resolve_vpn_host_port 443)
    if [ $? -ne 0 ]; then
        print_error "无法找到可用端口" >&2
        return 1
    fi

    if [ "$ocserv_port" = "443" ]; then
        print_message "443端口可用，ocserv 将直接使用 443" >&2
    else
        print_message "宿主机 443 由 nginx 使用，ocserv 将改为使用 $ocserv_port" >&2
    fi

    echo "$ocserv_port"
}

open_vpn_port_in_firewall() {
    local port="$1"

    if [[ -z "$port" ]]; then
        return 1
    fi

    open_port_with_bt_panel "$port" "tcp" "ocserv-tcp-${port}" || true
    open_port_with_bt_panel "$port" "udp" "ocserv-udp-${port}" || true

    if command -v ufw >/dev/null 2>&1; then
        ufw allow "${port}/tcp" >/dev/null 2>&1 || true
        ufw allow "${port}/udp" >/dev/null 2>&1 || true
    elif command -v firewall-cmd >/dev/null 2>&1; then
        firewall-cmd --permanent --add-port="${port}/tcp" >/dev/null 2>&1 || true
        firewall-cmd --permanent --add-port="${port}/udp" >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null 2>&1 || true
    elif command -v iptables >/dev/null 2>&1; then
        iptables -C INPUT -p tcp --dport "$port" -j ACCEPT >/dev/null 2>&1 || iptables -I INPUT -p tcp --dport "$port" -j ACCEPT >/dev/null 2>&1 || true
        iptables -C INPUT -p udp --dport "$port" -j ACCEPT >/dev/null 2>&1 || iptables -I INPUT -p udp --dport "$port" -j ACCEPT >/dev/null 2>&1 || true
        if command -v iptables-save >/dev/null 2>&1; then
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        fi
    else
        print_warning "未检测到已知防火墙，请手动放行端口 ${port}/tcp 和 ${port}/udp"
        return 0
    fi

    print_message "已放行 ocserv 使用端口: $port/tcp, $port/udp"
}

is_bt_panel_installed() {
    command -v bt >/dev/null 2>&1 && [[ -d "/www/server/panel" ]]
}

open_port_with_bt_panel() {
    local port="$1"
    local protocol="$2"
    local remark="${3:-ocserv}"

    if ! is_bt_panel_installed; then
        return 1
    fi

    bt 2 "$port" "$protocol" "$remark" >/dev/null 2>&1 || return 1
    bt 1 >/dev/null 2>&1 || true
    return 0
}

get_bt_panel_port() {
    local port_file="/www/server/panel/data/port.pl"

    if [[ -f "$port_file" ]]; then
        tr -dc '0-9' < "$port_file"
        return 0
    fi

    echo "8888"
}

get_container_host_port() {
    local container_name="$1"
    local container_port="${2:-$DEFAULT_OCSERV_CONTAINER_PORT}"
    local port_mapping

    port_mapping=$(docker port "$container_name" "${container_port}/tcp" 2>/dev/null | head -1)
    if [[ -n "$port_mapping" ]]; then
        echo "${port_mapping##*:}"
    fi
}

deploy_with_port_coexistence() {
    local domain="$1"
    local container_name="$2"
    # 兼容旧调用参数，当前仅用于输出提示
    : "${domain:=}"
    : "${container_name:=}"
    local config_dir="$3"
    local username="$4"
    local password="$5"
    
    print_message "使用端口共存模式部署ocserv..."
    
    # 设置端口共存
    local ocserv_port
    ocserv_port=$(setup_port_coexistence "$domain" "$container_name")
    if [ $? -ne 0 ]; then
        print_error "端口共存设置失败"
        return 1
    fi
    
    # 生成配置文件
    generate_ocserv_config "$domain" "$config_dir" "$username"
    
    # 创建密码文件
    generate_password_hash "$username" "$password" "$config_dir"
    
    # 申请SSL证书
    if check_certbot || install_certbot; then
        print_message "开始申请Let's Encrypt SSL证书..."
        request_ssl_certificate_for_config "$config_dir" "$domain"
    else
        generate_self_signed_cert "$domain" "$config_dir"
    fi
    
    # 启动容器（容器内始终监听443，宿主机按可用端口映射）
    docker run -d --name "$container_name" --privileged \
        -p "$ocserv_port:${DEFAULT_OCSERV_CONTAINER_PORT}" \
        -p "$ocserv_port:${DEFAULT_OCSERV_CONTAINER_PORT}/udp" \
        -v "$config_dir:/etc/ocserv" \
        tommylau/ocserv:latest
    
    if [ $? -eq 0 ]; then
        print_message "ocserv部署成功！"
        if [ "$ocserv_port" != "443" ]; then
            print_message "访问地址: $domain:$ocserv_port"
            print_message "宿主机 nginx 继续使用 443，ocserv 使用独立端口 $ocserv_port"
        else
            print_message "访问地址: $domain:443"
        fi
        print_message "用户名: $username"
        print_message "密码: $password"
        return 0
    else
        print_error "ocserv部署失败"
        return 1
    fi
}

# 检查端口占用情况
check_port_status() {
    print_message "检查端口占用情况..."
    
    echo -e "${BLUE}端口状态：${NC}"
    echo -e "${YELLOW}80端口 (HTTP):${NC}"
    if check_port_availability 80; then
        echo -e "  ${GREEN}✓ 可用${NC}"
    else
        local process=$(netstat -tlnp 2>/dev/null | grep ":80 " | awk '{print $7}')
        echo -e "  ${RED}✗ 被占用 ($process)${NC}"
    fi
    
    echo -e "${YELLOW}443端口 (HTTPS):${NC}"
    if check_port_availability 443; then
        echo -e "  ${GREEN}✓ 可用${NC}"
    else
        local process=$(netstat -tlnp 2>/dev/null | grep ":443 " | awk '{print $7}')
        echo -e "  ${RED}✗ 被占用 ($process)${NC}"
    fi
    
    echo -e "${YELLOW}8443端口 (备用):${NC}"
    if check_port_availability 8443; then
        echo -e "  ${GREEN}✓ 可用${NC}"
    else
        local process=$(netstat -tlnp 2>/dev/null | grep ":8443 " | awk '{print $7}')
        echo -e "  ${RED}✗ 被占用 ($process)${NC}"
    fi
}

# 确保宝塔面板服务正常运行
ensure_bt_panel_running() {
    if ! is_bt_panel_installed; then
        return 0
    fi

    print_message "检查宝塔面板服务状态..."

    # 检查宝塔面板是否运行
    if ! bt status | grep -q "already running"; then
        print_warning "宝塔面板服务未运行，正在启动..."
        bt start >/dev/null 2>&1
        sleep 5
        
        # 再次检查
        if bt status | grep -q "already running"; then
            print_message "宝塔面板服务已成功启动"
        else
            print_error "宝塔面板服务启动失败"
            return 1
        fi
    else
        print_message "宝塔面板服务运行正常"
    fi
    
    # 检查宝塔面板端口
    local panel_port
    panel_port=$(get_bt_panel_port)
    if [[ -n "$panel_port" ]] && ! netstat -tlnp 2>/dev/null | grep -q ":$panel_port "; then
        print_warning "宝塔面板端口 $panel_port 未监听，尝试重启..."
        bt restart >/dev/null 2>&1
        sleep 5

        if netstat -tlnp 2>/dev/null | grep -q ":$panel_port "; then
            print_message "宝塔面板端口已恢复监听: $panel_port"
        else
            print_error "宝塔面板端口恢复失败"
            return 1
        fi
    fi
    
    return 0
}

# 在证书申请后确保服务恢复
post_certificate_cleanup() {
    print_message "证书申请完成，确保服务正常运行..."

    # 确保宝塔面板运行
    ensure_bt_panel_running || true

    # 确保nginx运行
    if command -v systemctl >/dev/null 2>&1; then
        if ! systemctl is-active nginx >/dev/null 2>&1; then
            print_warning "nginx服务未运行，正在启动..."
            systemctl start nginx >/dev/null 2>&1 || true
            sleep 3
        else
            nginx -s reload >/dev/null 2>&1 || true
        fi
    elif command -v nginx >/dev/null 2>&1; then
        nginx >/dev/null 2>&1 || nginx -s reload >/dev/null 2>&1 || true
    fi

    # 显示服务状态
    print_message "当前服务状态："
    if is_bt_panel_installed; then
        echo "  宝塔面板: $(bt status | grep -o 'already running\|not running' | head -1)"
        echo "  宝塔端口: $(get_bt_panel_port)"
    fi
    if command -v systemctl >/dev/null 2>&1; then
        echo "  nginx: $(systemctl is-active nginx 2>/dev/null || echo 'not running')"
    else
        echo "  nginx: $(ps -ef | grep '[n]ginx' >/dev/null && echo 'running' || echo 'not running')"
    fi
    echo "  ocserv: $(docker ps | grep ocserv >/dev/null && echo 'running' || echo 'not running')"
}

# 清理nginx代理配置
cleanup_nginx_proxy() {
    local config_file="/www/server/nginx/conf/vhost/ocserv-proxy.conf"
    if [ -f "$config_file" ]; then
        rm -f "$config_file"
        if nginx -t >/dev/null 2>&1; then
            nginx -s reload
            print_message "已清理旧版nginx代理配置"
        fi
    else
        print_message "未发现旧版nginx代理配置"
    fi
}

# 停止并删除ocserv服务
stop_and_remove_ocserv() {
    print_message "停止并删除ocserv服务..."
    
    # 查找所有ocserv容器
    local containers
    containers=$(docker ps -a --filter "name=ocserv" --format "{{.Names}}")
    
    if [[ -z "$containers" ]]; then
        print_warning "未找到ocserv容器"
        return 0
    fi
    
    echo "找到以下ocserv容器："
    echo "$containers"
    echo ""
    
    read -p "确认删除所有ocserv容器、镜像和配置文件？(y/N): " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        # 停止并删除容器
        for container in $containers; do
            print_message "停止容器: $container"
            docker stop "$container" >/dev/null 2>&1 || true
            
            print_message "删除容器: $container"
            docker rm "$container" >/dev/null 2>&1 || true
        done
        
        # 自动删除Docker镜像
        print_message "正在删除ocserv Docker镜像..."
            # 查找ocserv相关镜像
            local images
            # 查找多种可能的ocserv镜像名称
            images=$(docker images --format "{{.Repository}}:{{.Tag}}" | grep -E "(ocserv|openconnect|cisco)" || true)
            
            # 如果没找到，尝试查找所有镜像中可能相关的
            if [[ -z "$images" ]]; then
                # 查找可能用于构建ocserv的基础镜像
                images=$(docker images --format "{{.Repository}}:{{.Tag}}" | grep -E "(ubuntu|debian|alpine|centos).*ocserv" || true)
            fi
            
            if [[ -n "$images" ]]; then
                echo "找到以下可能的ocserv相关镜像："
                echo "$images"
                echo ""
                
                for image in $images; do
                    print_message "删除镜像: $image"
                    docker rmi "$image" >/dev/null 2>&1 || true
                done
                
                print_message "相关镜像已删除"
            else
                # 显示所有镜像供用户参考
                local all_images
                all_images=$(docker images --format "{{.Repository}}:{{.Tag}}" | head -10)
                if [[ -n "$all_images" ]]; then
                    print_warning "未找到明确的ocserv相关镜像"
                    echo "当前系统中的镜像（前10个）："
                    echo "$all_images"
                    echo ""
                    read -p "请手动输入要删除的镜像名称（留空跳过）: " manual_image
                    if [[ -n "$manual_image" ]]; then
                        print_message "删除镜像: $manual_image"
                        docker rmi "$manual_image" >/dev/null 2>&1 || print_error "删除镜像失败"
                    fi
                else
                    print_message "系统中没有Docker镜像"
                fi
            fi
        
        # 自动清理配置文件
        print_message "正在删除配置文件..."
            if [[ -d "$OCSERV_CONFIG_DIR" ]]; then
                rm -rf "$OCSERV_CONFIG_DIR"
                print_message "已删除配置目录: $OCSERV_CONFIG_DIR"
            fi
            
            # 删除其他可能的配置目录
            for config_dir in "$OCSERV_CONFIG_DIR"-*; do
                if [[ -d "$config_dir" ]]; then
                    rm -rf "$config_dir"
                    print_message "已删除配置目录: $config_dir"
                fi
            done
        
        # 清理nginx代理配置
        cleanup_nginx_proxy
        
        print_message "ocserv服务已完全清理"
    else
        print_message "操作已取消"
    fi
}

# 打印带颜色的消息
print_message() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}+----------------------------------------------------------+${NC}"
    echo -e "${BLUE}|               ocserv Docker 一键部署脚本                 |${NC}"
    echo -e "${BLUE}|          Repo: https://github.com/moli-xia/ocserv-docker |${NC}"
    echo -e "${BLUE}+----------------------------------------------------------+${NC}"
}

print_menu() {
    clear
    print_header
    echo -e "${CYAN}    支持与 nginx/OpenResty/宝塔面板 并行运行${NC}"
    echo ""
    echo -e "${BLUE}部署选项：${NC}"
    echo -e "${YELLOW}1.${NC} 快速自动部署 (预设账号: $DEFAULT_USERNAME/$DEFAULT_PASSWORD)"
    echo -e "${YELLOW}2.${NC} 自定义部署 (用户自定义配置)"
    echo -e "${YELLOW}3.${NC} 管理SSL证书"
    echo -e "${YELLOW}4.${NC} 服务状态管理"
    echo -e "${YELLOW}5.${NC} 端口状态检查"
    echo -e "${YELLOW}6.${NC} 清理旧版nginx代理配置"
    echo -e "${YELLOW}7.${NC} 停止并删除ocserv服务"
    echo -e "${YELLOW}0.${NC} 退出"
    echo ""
}

# 检查Docker是否安装
check_docker() {
    if ! command -v docker &> /dev/null; then
        print_error "Docker 未安装，请先安装 Docker"
        exit 1
    fi
    
    if ! docker info &> /dev/null; then
        print_error "Docker 服务未运行，请启动 Docker 服务"
        exit 1
    fi
    
    print_message "Docker 检查通过"
}

# 检查OpenSSL是否安装
check_openssl() {
    if ! command -v openssl &> /dev/null; then
        print_error "OpenSSL 未安装，请先安装 OpenSSL"
        print_message "Ubuntu/Debian: apt-get install openssl"
        print_message "CentOS/RHEL: yum install openssl"
        exit 1
    fi
    
    print_message "OpenSSL 检查通过"
}

# 检查OpenSSL兼容性
check_openssl_compatibility() {
    local openssl_version=$(openssl version | awk -F' ' '{print $2}')
    local major_version=$(echo "$openssl_version" | awk -F'.' '{print $1}')
    local minor_version=$(echo "$openssl_version" | awk -F'.' '{print $2}')

    if [ "$major_version" -lt 1 ] || ([ "$major_version" -eq 1 ] && [ "$minor_version" -lt 1 ]); then
        print_warning "OpenSSL 版本较低 ($openssl_version)，可能存在兼容性问题。建议升级到 1.1.1 或更高版本。"
        print_message "Ubuntu/Debian: apt-get install openssl"
        print_message "CentOS/RHEL: yum install openssl"
        print_message "Fedora: dnf install openssl"
        print_message "请根据提示升级 OpenSSL 版本。"
    fi
}

# 生成密码哈希（不依赖Alpine镜像）
generate_password_hash() {
    local password="$1"
    # 使用Python生成密码哈希
    python3 -c "
import crypt
import sys
password = sys.argv[1]
salt = crypt.mksalt(crypt.METHOD_SHA512)
hashed = crypt.crypt(password, salt)
print(hashed)
" "$password" 2>/dev/null || echo "$1\$$(openssl rand -base64 6 | tr -d '=+/')$(openssl rand -base64 6 | tr -d '=+/')"
}

# 快速自动部署
quick_deploy() {
    print_message "开始快速自动部署..."

    # 预设配置
    USERNAME="NoRoute"
    PASSWORD="654321"
    PORT=$(resolve_vpn_host_port 443)
    if [ $? -ne 0 ] || [[ -z "$PORT" ]]; then
        print_error "无法分配可用端口"
        return 1
    fi
    CONTAINER_NAME="ocserv"
    CONTAINER_PORT="$DEFAULT_OCSERV_CONTAINER_PORT"
    
    print_message "使用预设配置："
    echo "  用户名: $USERNAME"
    echo "  密码: $PASSWORD"
    echo "  宿主机端口: $PORT"
    echo "  容器端口: $CONTAINER_PORT"
    echo "  容器名: $CONTAINER_NAME"
    
    # 停止并删除已存在的容器
    if docker ps -a | grep -q $CONTAINER_NAME; then
        print_warning "发现已存在的容器，正在停止并删除..."
        docker stop $CONTAINER_NAME 2>/dev/null || true
        docker rm $CONTAINER_NAME 2>/dev/null || true
    fi
    
    # 创建/opt/ocserv目录
    mkdir -p "$OCSERV_CONFIG_DIR"
    if [ $? -ne 0 ]; then
        print_error "无法创建配置目录 $OCSERV_CONFIG_DIR"
        return 1
    fi
    print_message "配置目录已创建: $OCSERV_CONFIG_DIR"
    
    # 创建ocserv配置文件
    cat > "$OCSERV_CONFIG_DIR/ocserv.conf" << EOF
auth = "plain[passwd=/etc/ocserv/ocpasswd]"
tcp-port = $CONTAINER_PORT
udp-port = $CONTAINER_PORT
run-as-user = nobody
run-as-group = daemon
socket-file = /var/run/ocserv-socket
server-cert = /etc/ocserv/server-cert.pem
server-key = /etc/ocserv/server-key.pem
ca-cert = /etc/ocserv/ca-cert.pem
isolate-workers = true
max-clients = 16
max-same-clients = 2
server-stats-reset-time = 604800
keepalive = 32400
dpd = 90
mobile-dpd = 1800
switch-to-tcp-timeout = 25
try-mtu-discovery = true
cert-user-oid = 0.9.2342.19200300.100.1.1
tls-priorities = "NORMAL:%SERVER_PRECEDENCE:%COMPAT:-VERS-SSL3.0"
auth-timeout = 240
min-reauth-time = 300
max-ban-score = 50
ban-reset-time = 300
cookie-timeout = 300
deny-roaming = false
rekey-time = 172800
rekey-method = ssl
use-occtl = true
pid-file = /var/run/ocserv.pid
device = vpns
predictable-ips = true
default-domain = example.com
ipv4-network = 10.66.0.0
ipv4-netmask = 255.255.255.0
dns = 8.8.8.8
dns = 8.8.4.4
route = default
cisco-client-compat = true
dtls-legacy = true
EOF
    
    # 生成密码哈希并创建用户密码文件
    print_message "生成用户密码文件..."
    PASSWORD_HASH=$(generate_password_hash "$PASSWORD")
    echo "$USERNAME:*:$PASSWORD_HASH" > "$OCSERV_CONFIG_DIR/ocpasswd"
    
    # 拉取镜像
    print_message "拉取 ocserv 镜像..."
    docker pull tommylau/ocserv:latest

    open_vpn_port_in_firewall "$PORT"

    # 启动容器
    print_message "启动 ocserv 容器..."
    docker run -d \
        --name $CONTAINER_NAME \
        --restart unless-stopped \
        -p $PORT:$CONTAINER_PORT \
        -p $PORT:$CONTAINER_PORT/udp \
        -v "$OCSERV_CONFIG_DIR:/etc/ocserv" \
        --cap-add=NET_ADMIN \
        --cap-add=NET_BROADCAST \
        --cap-add=NET_RAW \
        --cap-add=NET_BIND_SERVICE \
        --cap-add=SYS_CHROOT \
        --cap-add=SYS_ADMIN \
        --security-opt seccomp=unconfined \
        tommylau/ocserv:latest
    
    # 等待服务启动
    sleep 10
    
    # 检查容器状态
    if docker ps | grep -q $CONTAINER_NAME; then
        print_message "ocserv 部署成功！"
        
        # 获取服务器IP或域名
        local server_address
        server_address=$(curl -s ifconfig.me 2>/dev/null || echo "请手动获取服务器IP")
        
        # 询问用户是否申请SSL证书
        ask_for_ssl_certificate "$server_address" "$OCSERV_CONFIG_DIR"
        
        # 检查是否有SSL证书申请成功的域名
        if [[ -f "$OCSERV_CONFIG_DIR/domain.txt" ]]; then
            server_address=$(cat "$OCSERV_CONFIG_DIR/domain.txt")
            print_message "使用SSL证书域名作为服务器地址: $server_address"
        fi
        
        # 显示连接信息
        show_connection_info "$USERNAME" "$PASSWORD" "$server_address" "$PORT"
        
    else
        print_error "ocserv 部署失败，请检查日志"
        docker logs $CONTAINER_NAME
        exit 1
    fi
}

# 用户自定义部署
custom_deploy() {
    print_message "开始用户自定义部署..."
    
    # 获取用户输入
    echo ""
    read -p "请输入用户名: " USERNAME
    read -s -p "请输入密码: " PASSWORD
    echo ""
    read -p "请输入宿主机端口 (默认443，若443被nginx占用将自动改用8443+): " PORT
    PORT=${PORT:-443}
    read -p "请输入容器名 (默认ocserv): " CONTAINER_NAME
    CONTAINER_NAME=${CONTAINER_NAME:-ocserv}
    
    # 验证输入
    if [[ -z "$USERNAME" || -z "$PASSWORD" ]]; then
        print_error "用户名和密码不能为空"
        exit 1
    fi
    
    if ! [[ "$PORT" =~ ^[0-9]+$ ]] || [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
        print_error "端口号必须是1-65535之间的数字"
        exit 1
    fi

    PORT=$(resolve_vpn_host_port "$PORT")
    if [ $? -ne 0 ] || [[ -z "$PORT" ]]; then
        print_error "无法分配可用端口"
        return 1
    fi

    CONTAINER_PORT="$DEFAULT_OCSERV_CONTAINER_PORT"
    
    print_message "使用自定义配置："
    echo "  用户名: $USERNAME"
    echo "  密码: $PASSWORD"
    echo "  宿主机端口: $PORT"
    echo "  容器端口: $CONTAINER_PORT"
    echo "  容器名: $CONTAINER_NAME"
    
    # 停止并删除已存在的容器
    if docker ps -a | grep -q $CONTAINER_NAME; then
        print_warning "发现已存在的容器，正在停止并删除..."
        docker stop $CONTAINER_NAME 2>/dev/null || true
        docker rm $CONTAINER_NAME 2>/dev/null || true
    fi
    
    # 创建配置文件目录
    if [[ "$CONTAINER_NAME" == "ocserv" ]]; then
        CONFIG_DIR="$OCSERV_CONFIG_DIR"
    else
        CONFIG_DIR="$OCSERV_CONFIG_DIR-$CONTAINER_NAME"
    fi
    mkdir -p "$CONFIG_DIR"
    if [ $? -ne 0 ]; then
        print_error "无法创建配置目录 $CONFIG_DIR"
        return 1
    fi
    print_message "配置目录已创建: $CONFIG_DIR"
    
    # 创建ocserv配置文件
    cat > $CONFIG_DIR/ocserv.conf << EOF
auth = "plain[passwd=/etc/ocserv/ocpasswd]"
tcp-port = $CONTAINER_PORT
udp-port = $CONTAINER_PORT
run-as-user = nobody
run-as-group = daemon
socket-file = /var/run/ocserv-socket
server-cert = /etc/ocserv/server-cert.pem
server-key = /etc/ocserv/server-key.pem
ca-cert = /etc/ocserv/ca-cert.pem
isolate-workers = true
max-clients = 16
max-same-clients = 2
server-stats-reset-time = 604800
keepalive = 32400
dpd = 90
mobile-dpd = 1800
switch-to-tcp-timeout = 25
try-mtu-discovery = true
cert-user-oid = 0.9.2342.19200300.100.1.1
tls-priorities = "NORMAL:%SERVER_PRECEDENCE:%COMPAT:-VERS-SSL3.0"
auth-timeout = 240
min-reauth-time = 300
max-ban-score = 50
ban-reset-time = 300
cookie-timeout = 300
deny-roaming = false
rekey-time = 172800
rekey-method = ssl
use-occtl = true
pid-file = /var/run/ocserv.pid
device = vpns
predictable-ips = true
default-domain = example.com
ipv4-network = 10.66.0.0
ipv4-netmask = 255.255.255.0
dns = 8.8.8.8
dns = 8.8.4.4
route = default
cisco-client-compat = true
dtls-legacy = true
EOF
    
    # 生成密码哈希并创建用户密码文件
    print_message "生成用户密码文件..."
    PASSWORD_HASH=$(generate_password_hash "$PASSWORD")
    echo "$USERNAME:*:$PASSWORD_HASH" > $CONFIG_DIR/ocpasswd
    
    # 拉取镜像
    print_message "拉取 ocserv 镜像..."
    docker pull tommylau/ocserv:latest

    open_vpn_port_in_firewall "$PORT"

    # 启动容器
    print_message "启动 ocserv 容器..."
    docker run -d \
        --name $CONTAINER_NAME \
        --restart unless-stopped \
        -p $PORT:$CONTAINER_PORT \
        -p $PORT:$CONTAINER_PORT/udp \
        -v "$CONFIG_DIR:/etc/ocserv" \
        --cap-add=NET_ADMIN \
        --cap-add=NET_BROADCAST \
        --cap-add=NET_RAW \
        --cap-add=NET_BIND_SERVICE \
        --cap-add=SYS_CHROOT \
        --cap-add=SYS_ADMIN \
        --security-opt seccomp=unconfined \
        tommylau/ocserv:latest
    
    # 等待服务启动
    sleep 10
    
    # 检查容器状态
    if docker ps | grep -q $CONTAINER_NAME; then
        print_message "ocserv 自定义部署成功！"
        
        # 获取服务器IP或域名
        local server_address
        server_address=$(curl -s ifconfig.me 2>/dev/null || echo "请手动获取服务器IP")
        
        # 询问用户是否申请SSL证书
        ask_for_ssl_certificate "$server_address" "$CONFIG_DIR"
        
        # 检查是否有SSL证书申请成功的域名
        if [[ -f "$CONFIG_DIR/domain.txt" ]]; then
            server_address=$(cat "$CONFIG_DIR/domain.txt")
            print_message "使用SSL证书域名作为服务器地址: $server_address"
        fi
        
        # 显示连接信息
        show_connection_info "$USERNAME" "$PASSWORD" "$server_address" "$PORT"
        
    else
        print_error "ocserv 自定义部署失败，请检查日志"
        docker logs $CONTAINER_NAME
        exit 1
    fi
}

# 修复密码问题
fix_password() {
    print_message "修复 ocserv 用户密码..."
    
    # 检查容器是否运行
    if ! docker ps | grep -q ocserv; then
        print_error "未找到运行中的 ocserv 容器"
        exit 1
    fi
    
    # 获取容器名
    CONTAINER_NAME=$(docker ps --format "table {{.Names}}" | grep ocserv | head -1)
    
    if [[ -z "$CONTAINER_NAME" ]]; then
        print_error "无法获取 ocserv 容器名"
        exit 1
    fi
    
    echo "找到容器: $CONTAINER_NAME"
    
    # 设置用户名和密码
    USERNAME="NoRoute"
    PASSWORD="654321"
    
    echo "设置用户: $USERNAME"
    echo "设置密码: $PASSWORD"
    
    # 生成密码哈希
    print_message "生成密码哈希..."
    PASSWORD_HASH=$(generate_password_hash "$PASSWORD")
    
    # 创建新的密码文件
    print_message "创建新的密码文件..."
    echo "$USERNAME:*:$PASSWORD_HASH" > ./temp_ocpasswd
    
    # 复制到容器
    docker cp ./temp_ocpasswd $CONTAINER_NAME:/etc/ocserv/ocpasswd
    rm -f ./temp_ocpasswd
    
    # 设置正确的权限
    docker exec $CONTAINER_NAME chown root:root /etc/ocserv/ocpasswd
    docker exec $CONTAINER_NAME chmod 600 /etc/ocserv/ocpasswd
    
    # 验证密码文件
    echo ""
    echo "验证密码文件内容:"
    docker exec $CONTAINER_NAME cat /etc/ocserv/ocpasswd
    
    # 重启容器以应用新配置
    echo ""
    echo "重启容器以应用新配置..."
    docker restart $CONTAINER_NAME
    
    # 等待服务启动
    echo "等待服务启动..."
    sleep 10
    
    # 检查服务状态
    if docker ps | grep -q $CONTAINER_NAME; then
        echo ""
        echo "✅ 密码修复完成！"
        echo ""
        echo "现在可以使用以下信息连接:"
        echo "  用户名: $USERNAME"
        echo "  密码: $PASSWORD"
        echo "  端口: 443"
        echo "  协议: AnyConnect"
        echo ""
        echo "请重新尝试连接！"
    else
        echo "❌ 容器启动失败，请检查日志"
        docker logs $CONTAINER_NAME
    fi
}

# 检测系统类型
detect_system() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        echo "$NAME"
    elif command -v lsb_release >/dev/null 2>&1; then
        lsb_release -si
    elif [[ -f /etc/redhat-release ]]; then
        cat /etc/redhat-release
    else
        uname -s
    fi
}

# 检查并安装 Certbot
install_certbot() {
    local system
    system=$(detect_system)
    print_message "检测到系统: $system"

    if check_certbot; then
        print_message "Certbot 已安装"
        return 0
    fi

    print_message "正在安装 Certbot..."

    case "$system" in
        *Ubuntu*|*Debian*)
            apt-get update >/dev/null 2>&1 || true
            apt-get install -y certbot >/dev/null 2>&1
            ;;
        *CentOS*|*Red\ Hat*|*Rocky*|*AlmaLinux*)
            if command -v dnf >/dev/null 2>&1; then
                dnf install -y epel-release >/dev/null 2>&1 || true
                dnf install -y certbot >/dev/null 2>&1
            else
                yum install -y epel-release >/dev/null 2>&1 || true
                yum install -y certbot >/dev/null 2>&1
            fi
            ;;
        *)
            if command -v snap >/dev/null 2>&1; then
                snap install certbot --classic >/dev/null 2>&1
            elif command -v pip3 >/dev/null 2>&1; then
                pip3 install certbot >/dev/null 2>&1
            else
                print_error "无法自动安装 Certbot，请手动安装后重试"
                return 1
            fi
            ;;
    esac

    check_certbot
}

# 检查 Certbot 是否可用
check_certbot() {
    if command -v certbot >/dev/null 2>&1; then
        certbot --version >/dev/null 2>&1
        return $?
    elif [[ -f "/snap/bin/certbot" ]]; then
        return 0
    fi

    return 1
}

manage_firewall_for_ssl() {
    print_message "为 SSL 证书申请配置防火墙和端口..."

    open_port_with_bt_panel 80 tcp cert-http-80 || true
    open_port_with_bt_panel 443 tcp cert-https-443 || true

    if command -v ufw >/dev/null 2>&1; then
        ufw allow 80/tcp >/dev/null 2>&1 || true
        ufw allow 443/tcp >/dev/null 2>&1 || true
    elif command -v firewall-cmd >/dev/null 2>&1; then
        firewall-cmd --permanent --add-port=80/tcp >/dev/null 2>&1 || true
        firewall-cmd --permanent --add-port=443/tcp >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null 2>&1 || true
    elif command -v iptables >/dev/null 2>&1; then
        iptables -C INPUT -p tcp --dport 80 -j ACCEPT >/dev/null 2>&1 || iptables -I INPUT -p tcp --dport 80 -j ACCEPT >/dev/null 2>&1 || true
        iptables -C INPUT -p tcp --dport 443 -j ACCEPT >/dev/null 2>&1 || iptables -I INPUT -p tcp --dport 443 -j ACCEPT >/dev/null 2>&1 || true
        if command -v iptables-save >/dev/null 2>&1; then
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        fi
    else
        print_warning "未检测到已知防火墙，请手动确保 80 和 443 已开启"
    fi
}

get_domain_input() {
    local domain=""

    echo ""
    print_message "请输入您的域名（例如: example.com）"
    print_message "注意：域名必须已解析到当前服务器"

    while true; do
        read -p "域名: " domain
        domain=$(echo "$domain" | grep -o '[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z0-9][a-zA-Z0-9.-]*' | tail -1)

        if [[ -z "$domain" ]]; then
            print_error "域名不能为空，请重新输入"
            continue
        fi

        if [[ "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$ ]] && [[ "$domain" == *.* ]]; then
            echo "$domain"
            return 0
        fi

        print_error "域名格式不正确，请重新输入"
    done
}

check_port_usage() {
    local port="$1"

    if command -v netstat >/dev/null 2>&1; then
        netstat -tlnp 2>/dev/null | grep -q ":$port "
        return $?
    elif command -v ss >/dev/null 2>&1; then
        ss -tlnp 2>/dev/null | grep -q ":$port "
        return $?
    fi

    return 1
}

get_port_process() {
    local port="$1"

    if command -v netstat >/dev/null 2>&1; then
        netstat -tlnp 2>/dev/null | grep ":$port " | awk '{print $7}' | head -1
    elif command -v ss >/dev/null 2>&1; then
        ss -tlnp 2>/dev/null | grep ":$port " | awk '{print $6}' | head -1
    fi
}

stop_port_service() {
    local port="$1"
    local process_info="$2"

    if [[ -z "$process_info" ]]; then
        return 0
    fi

    if echo "$process_info" | grep -q "nginx"; then
        print_warning "检测到 nginx 占用 ${port} 端口，尝试停止 nginx..."

        if command -v systemctl >/dev/null 2>&1; then
            systemctl stop nginx >/dev/null 2>&1 || true
            sleep 3
            if ! systemctl is-active nginx >/dev/null 2>&1; then
                return 0
            fi
        fi

        if command -v nginx >/dev/null 2>&1; then
            nginx -s stop >/dev/null 2>&1 || true
            sleep 3
        fi

        if ! check_port_usage "$port"; then
            return 0
        fi
    fi

    local pid
    pid=$(echo "$process_info" | sed 's/.*\([0-9][0-9]*\).*/\1/' | tail -1)
    if [[ -n "$pid" ]] && [[ "$pid" =~ ^[0-9]+$ ]]; then
        kill "$pid" >/dev/null 2>&1 || true
        sleep 2
        kill -9 "$pid" >/dev/null 2>&1 || true
    fi

    return 0
}

restart_nginx_service() {
    if command -v systemctl >/dev/null 2>&1; then
        systemctl enable nginx >/dev/null 2>&1 || true
        systemctl start nginx >/dev/null 2>&1 || true
        sleep 3
        if systemctl is-active nginx >/dev/null 2>&1; then
            print_message "nginx 服务已恢复"
            return 0
        fi
    fi

    if command -v nginx >/dev/null 2>&1; then
        nginx >/dev/null 2>&1 || true
    fi
}

apply_ssl_certificate() {
    local domain="$1"
    local config_dir="$2"
    local nginx_was_stopped=false
    local clean_domain
    clean_domain=$(echo "$domain" | grep -o '[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z0-9][a-zA-Z0-9.-]*' | tail -1)

    manage_firewall_for_ssl

    if ! check_certbot; then
        if ! install_certbot; then
            print_error "Certbot 安装失败，无法申请 SSL 证书"
            post_certificate_cleanup
            return 1
        fi
    fi

    mkdir -p "$config_dir"

    if check_port_usage 80; then
        local process_info
        process_info=$(get_port_process 80)
        if echo "$process_info" | grep -q "nginx"; then
            nginx_was_stopped=true
        fi
        stop_port_service 80 "$process_info"
    fi

    local certbot_cmd="certbot"
    if [[ -f "/snap/bin/certbot" ]]; then
        certbot_cmd="/snap/bin/certbot"
    fi

    local certbot_output
    certbot_output=$($certbot_cmd certonly --standalone --non-interactive --agree-tos --email "admin@$clean_domain" --domains "$clean_domain" --preferred-challenges http 2>&1)
    local certbot_exit_code=$?

    if [[ "$certbot_exit_code" -ne 0 ]]; then
        print_error "SSL 证书申请失败"
        echo "$certbot_output" | head -10
        if [[ "$nginx_was_stopped" == "true" ]]; then
            restart_nginx_service
        fi
        post_certificate_cleanup
        return 1
    fi

    cp "/etc/letsencrypt/live/$clean_domain/fullchain.pem" "$config_dir/server-cert.pem"
    cp "/etc/letsencrypt/live/$clean_domain/privkey.pem" "$config_dir/server-key.pem"
    cp "/etc/letsencrypt/live/$clean_domain/chain.pem" "$config_dir/ca-cert.pem"
    chmod 600 "$config_dir/server-key.pem"
    chmod 644 "$config_dir/server-cert.pem" "$config_dir/ca-cert.pem"

    if [[ "$nginx_was_stopped" == "true" ]]; then
        restart_nginx_service
    fi

    echo "$clean_domain" > "$config_dir/domain.txt"
    print_message "SSL 证书申请成功"
    post_certificate_cleanup
    return 0
}

setup_auto_renewal() {
    local domain="$1"
    local config_dir="$2"
    local clean_domain
    clean_domain=$(echo "$domain" | grep -o '[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z0-9][a-zA-Z0-9.-]*' | tail -1)

    cat > /etc/cron.daily/ocserv-renew << EOF
#!/bin/bash
CERTBOT_CMD="/snap/bin/certbot"
if [[ ! -f "\$CERTBOT_CMD" ]]; then
    CERTBOT_CMD="certbot"
fi

\$CERTBOT_CMD renew --quiet

if [ \$? -eq 0 ]; then
    cp /etc/letsencrypt/live/$clean_domain/fullchain.pem $config_dir/server-cert.pem
    cp /etc/letsencrypt/live/$clean_domain/privkey.pem $config_dir/server-key.pem
    cp /etc/letsencrypt/live/$clean_domain/chain.pem $config_dir/ca-cert.pem
    chmod 600 $config_dir/server-key.pem
    chmod 644 $config_dir/server-cert.pem $config_dir/ca-cert.pem
    docker restart \$(docker ps --format "{{.Names}}" | grep ocserv | head -1) >/dev/null 2>&1
fi
EOF

    chmod +x /etc/cron.daily/ocserv-renew
    print_message "已设置 SSL 证书自动续签"
}

get_running_ocserv_container_name() {
    docker ps --format "{{.Names}}" | grep ocserv | head -1
}

resolve_config_dir_for_container() {
    local container_name="$1"

    if [[ -z "$container_name" || "$container_name" == "ocserv" ]]; then
        echo "$OCSERV_CONFIG_DIR"
    else
        echo "${OCSERV_CONFIG_DIR}-${container_name}"
    fi
}

request_ssl_certificate_for_config() {
    local config_dir="$1"
    local domain="${2:-}"

    if [[ -z "$domain" ]]; then
        domain=$(get_domain_input)
    fi

    if [[ -z "$domain" ]]; then
        print_error "域名获取失败"
        return 1
    fi

    if apply_ssl_certificate "$domain" "$config_dir"; then
        setup_auto_renewal "$domain" "$config_dir"
        return 0
    fi

    return 1
}

# 管理 SSL 证书
manage_ssl_cert() {
    print_message "SSL 证书管理..."

    local container_name
    local config_dir
    container_name=$(get_running_ocserv_container_name)
    config_dir=$(resolve_config_dir_for_container "$container_name")

    mkdir -p "$config_dir"
    request_ssl_certificate_for_config "$config_dir"
}

# 查看服务状态
show_service_status() {
    print_message "ocserv 服务状态..."
    
    # 检查容器状态
    if docker ps | grep -q ocserv; then
        echo ""
        echo "✅ 服务运行中："
        docker ps --filter "name=ocserv" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

        # 显示连接信息
        echo ""
        echo "连接信息："
        CONTAINER_NAME=$(docker ps --format "table {{.Names}}" | grep ocserv | head -1)
        if [[ -n "$CONTAINER_NAME" ]]; then
            local host_port
            host_port=$(get_container_host_port "$CONTAINER_NAME" "$DEFAULT_OCSERV_CONTAINER_PORT")
            echo "端口监听状态："
            if [[ -n "$host_port" ]]; then
                netstat -tlnp 2>/dev/null | grep ":$host_port " || echo "宿主机端口 $host_port 未监听"
            else
                echo "未检测到宿主机端口映射"
            fi
            echo ""
            echo "容器名: $CONTAINER_NAME"
            echo "配置文件: $OCSERV_CONFIG_DIR"
            echo "宿主机端口: ${host_port:-未检测到}"
            echo "容器端口: $DEFAULT_OCSERV_CONTAINER_PORT"
            echo "协议: AnyConnect"
        fi
    else
        echo ""
        echo "❌ 服务未运行"
        echo "使用 'docker ps -a | grep ocserv' 查看所有容器状态"
    fi
}

# 询问用户是否申请SSL证书
ask_for_ssl_certificate() {
    local server_ip="$1"
    local config_dir="$2"
    
    echo ""
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}           SSL证书配置${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo ""
    echo -e "${YELLOW}当前配置：${NC}"
    echo "  服务器IP: $server_ip"
    echo "  配置目录: $config_dir"
    echo ""
    echo -e "${BLUE}SSL证书选项：${NC}"
    echo -e "${YELLOW}1.${NC} 申请Let's Encrypt免费SSL证书 (推荐)"
    echo -e "${YELLOW}2.${NC} 跳过SSL证书配置"
    echo ""
    
    while true; do
        read -p "请选择SSL证书配置 (1-2): " ssl_choice
        case $ssl_choice in
            1)
                print_message "开始申请Let's Encrypt SSL证书..."
                request_ssl_certificate_for_config "$config_dir"
                return $?
                ;;
            2)
                print_message "跳过SSL证书配置，使用默认配置"
                return 1
                ;;
            *)
                print_error "无效选择，请输入 1 或 2"
                ;;
        esac
    done
}

# 显示连接信息
show_connection_info() {
    local username="$1"
    local password="$2"
    local domain="$3"
    local port="$4"
    
    echo ""
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}           ocserv 连接信息${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo ""
    echo -e "${GREEN}✓ 部署完成！${NC}"
    echo ""
    echo -e "${YELLOW}连接信息：${NC}"
    # 根据是否有SSL证书决定显示格式
    if [[ "$port" == "443" ]]; then
        echo "  服务器地址: $domain"
    else
        echo "  服务器地址: $domain:$port"
    fi
    echo "  用户名: $username"
    echo "  密码: $password"
    echo ""
}

# 显示帮助信息
show_help() {
    echo "用法: $0 [选项]"
    echo ""
    echo "选项:"
    echo "  -q, --quick     快速自动部署 (使用预设账号: NoRoute/654321)"
    echo "  -c, --custom    用户自定义部署"
    echo "  -h, --help      显示此帮助信息"
    echo ""
    echo "示例:"
    echo "  $0 -q           # 快速部署"
    echo "  $0 -c           # 自定义部署"
    echo "  $0 --help       # 显示帮助"
    echo ""
    echo "交互式模式:"
    echo "  直接运行 $0 进入交互式菜单"
}

# 交互式主菜单
interactive_menu() {
    while true; do
        print_menu
        
        read -p "请输入选择 (0-7): " choice
        
        case $choice in
            1)
                quick_deploy
                ;;
            2)
                custom_deploy
                ;;
            3)
                manage_ssl_cert
                ;;
            4)
                show_service_status
                ;;
            5)
                check_port_status
                ;;
            6)
                cleanup_nginx_proxy
                ;;
            7)
                stop_and_remove_ocserv
                ;;
            0)
                print_message "感谢使用！"
                exit 0
                ;;
            *)
                print_error "无效选择，请输入 0-7"
                ;;
        esac
        
        echo ""
        read -p "按回车键继续..."
        clear
    done
}

# 主函数
main() {
    # 检查依赖
    check_docker
    check_openssl
    check_openssl_compatibility
    check_certbot
    
    # 配置防火墙和端口
    manage_firewall
    
    # 如果没有参数，进入交互式模式
    if [[ $# -eq 0 ]]; then
        interactive_menu
        return
    fi
    
    # 解析命令行参数
    case "${1:-}" in
        -q|--quick)
            quick_deploy
            ;;
        -c|--custom)
            custom_deploy
            ;;
        -h|--help)
            show_help
            ;;
        *)
            print_error "未知选项: $1"
            show_help
            exit 1
            ;;
    esac
}

# 运行主函数
main "$@"
