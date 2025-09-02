#!/bin/bash

# ocserv 一键部署脚本 - 完整版
# 整合了ocserv部署和SSL证书申请功能
# 支持快速部署和自定义部署
# 支持Let's Encrypt证书自动申请和续期
# 自动配置防火墙和端口

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 全局变量
SCRIPT_DIR="/opt/ocserv"
DEFAULT_CONTAINER_NAME="ocserv"
DEFAULT_USERNAME="NoRoute"
DEFAULT_PASSWORD="654321"  # 修改预设密码为654321

# 初始化工作目录
init_work_directory() {
    print_message "初始化工作目录..."
    
    # 创建/opt/ocserv目录
    if [[ ! -d "/opt/ocserv" ]]; then
        mkdir -p /opt/ocserv
        print_message "已创建工作目录: /opt/ocserv"
    else
        print_message "工作目录已存在: /opt/ocserv"
    fi
    
    # 切换到工作目录
    cd /opt/ocserv
    
    # 复制当前脚本到工作目录（如果不在工作目录运行）
    if [[ "$(pwd)" != "/opt/ocserv" ]] && [[ -f "$0" ]]; then
        cp "$0" /opt/ocserv/
        chmod +x /opt/ocserv/$(basename "$0")
        print_message "脚本已复制到工作目录"
    fi
}

# 自动配置防火墙
configure_firewall() {
    print_message "配置防火墙，开启必要端口..."
    
    # 检测防火墙类型并配置
    if command -v ufw >/dev/null 2>&1; then
        # Ubuntu/Debian 使用 ufw
        print_message "检测到 ufw 防火墙，正在配置..."
        ufw allow 80/tcp >/dev/null 2>&1
        ufw allow 443/tcp >/dev/null 2>&1
        ufw allow 443/udp >/dev/null 2>&1
        print_message "ufw 防火墙规则已添加"
        
    elif command -v firewall-cmd >/dev/null 2>&1; then
        # CentOS/RHEL 使用 firewalld
        print_message "检测到 firewalld 防火墙，正在配置..."
        firewall-cmd --permanent --add-port=80/tcp >/dev/null 2>&1
        firewall-cmd --permanent --add-port=443/tcp >/dev/null 2>&1
        firewall-cmd --permanent --add-port=443/udp >/dev/null 2>&1
        firewall-cmd --reload >/dev/null 2>&1
        print_message "firewalld 防火墙规则已添加"
        
    elif command -v iptables >/dev/null 2>&1; then
        # 使用 iptables
        print_message "检测到 iptables 防火墙，正在配置..."
        iptables -I INPUT -p tcp --dport 80 -j ACCEPT >/dev/null 2>&1
        iptables -I INPUT -p tcp --dport 443 -j ACCEPT >/dev/null 2>&1
        iptables -I INPUT -p udp --dport 443 -j ACCEPT >/dev/null 2>&1
        
        # 尝试保存iptables规则
        if command -v iptables-save >/dev/null 2>&1; then
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        fi
        print_message "iptables 防火墙规则已添加"
        
    else
        print_warning "未检测到常见防火墙，请手动开启以下端口："
        echo "  - 80/tcp (HTTP)"
        echo "  - 443/tcp (HTTPS)"
        echo "  - 443/udp (HTTPS)"
    fi
    
    # 检查SELinux状态并处理
    if command -v getenforce >/dev/null 2>&1; then
        local selinux_status=$(getenforce 2>/dev/null)
        if [[ "$selinux_status" == "Enforcing" ]]; then
            print_warning "检测到SELinux处于强制模式，可能影响SSL证书申请"
            print_message "临时设置SELinux为宽松模式..."
            setenforce 0 2>/dev/null || true
        fi
    fi
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
        local images
        images=$(docker images --format "{{.Repository}}:{{.Tag}}" | grep -E "(ocserv|tommylau)" || true)
        
        if [[ -n "$images" ]]; then
            echo "找到以下ocserv相关镜像："
            echo "$images"
            echo ""
            
            for image in $images; do
                print_message "删除镜像: $image"
                docker rmi "$image" >/dev/null 2>&1 || true
            done
            
            print_message "相关镜像已删除"
        else
            print_message "未找到ocserv相关镜像"
        fi
        
        # 自动清理配置文件
        print_message "正在删除配置文件..."
        if [[ -d "/opt/ocserv/ocserv-config" ]]; then
            rm -rf "/opt/ocserv/ocserv-config"
            print_message "已删除配置目录: /opt/ocserv/ocserv-config"
        fi
        
        # 删除其他可能的配置目录
        for config_dir in /opt/ocserv/ocserv-config-*; do
            if [[ -d "$config_dir" ]]; then
                rm -rf "$config_dir"
                print_message "已删除配置目录: $config_dir"
            fi
        done
        
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
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}    ocserv 一键部署脚本${NC}"
    echo -e "${BLUE}================================${NC}"
}

print_menu() {
    clear
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}        ocserv 一键部署脚本${NC}"
    echo -e "${CYAN}    支持SSL证书自动申请和续期${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo ""
    echo -e "${BLUE}部署选项：${NC}"
    echo -e "${YELLOW}1.${NC} 快速自动部署 (预设账号: $DEFAULT_USERNAME/$DEFAULT_PASSWORD)"
    echo -e "${YELLOW}2.${NC} 自定义部署 (用户自定义配置)"
    echo -e "${YELLOW}3.${NC} 管理SSL证书"
    echo -e "${YELLOW}4.${NC} 服务状态管理"
    echo -e "${YELLOW}5.${NC} 端口状态检查"
    echo -e "${YELLOW}6.${NC} 停止并删除ocserv服务"
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

# 检测系统类型
detect_system() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
    elif type lsb_release >/dev/null 2>&1; then
        OS=$(lsb_release -si)
        VER=$(lsb_release -sr)
    elif [[ -f /etc/lsb-release ]]; then
        . /etc/lsb-release
        OS=$DISTRIB_ID
        VER=$DISTRIB_RELEASE
    elif [[ -f /etc/debian_version ]]; then
        OS=Debian
        VER=$(cat /etc/debian_version)
    elif [[ -f /etc/SuSe-release ]]; then
        OS=SuSE
    elif [[ -f /etc/redhat-release ]]; then
        OS=RedHat
    else
        OS=$(uname -s)
        VER=$(uname -r)
    fi
    
    echo "$OS"
}

# 检查并安装Certbot
install_certbot() {
    local system=$(detect_system)
    print_message "检测到系统: $system"
    
    # 检查是否已安装
    if check_certbot; then
        print_message "Certbot 已安装"
        return 0
    fi
    
    print_message "正在安装Certbot..."
    
    case $system in
        *"Ubuntu"*|*"Debian"*)
            # Ubuntu/Debian系统
            if command -v apt-get >/dev/null 2>&1; then
                apt-get update
                apt-get install -y certbot
                return $?
            fi
            ;;
        *"CentOS"*|*"Red Hat"*|*"Rocky"*|*"AlmaLinux"*)
            # CentOS/RHEL系统
            if command -v yum >/dev/null 2>&1; then
                yum install -y epel-release
                yum install -y certbot
                return $?
            elif command -v dnf >/dev/null 2>&1; then
                dnf install -y epel-release
                dnf install -y certbot
                return $?
            fi
            ;;
        *"Amazon Linux"*)
            # Amazon Linux
            if command -v yum >/dev/null 2>&1; then
                yum install -y python3-pip
                pip3 install certbot
                return $?
            fi
            ;;
        *"Arch"*)
            # Arch Linux
            if command -v pacman >/dev/null 2>&1; then
                pacman -S --noconfirm certbot
                return $?
            fi
            ;;
        *)
            # 其他系统，尝试通用方法
            print_warning "未知系统类型，尝试使用snap安装Certbot"
            if command -v snap >/dev/null 2>&1; then
                snap install certbot --classic
                return $?
            elif command -v pip3 >/dev/null 2>&1; then
                pip3 install certbot
                return $?
            else
                print_error "无法自动安装Certbot，请手动安装"
                return 1
            fi
            ;;
    esac
    
    return 1
}

# 检查Certbot是否可用
check_certbot() {
    if command -v certbot >/dev/null 2>&1; then
        # 测试certbot是否正常工作
        if certbot --version >/dev/null 2>&1; then
            return 0
        else
            print_warning "Certbot 存在但无法正常工作，尝试使用snap版本"
            return 1
        fi
    elif [[ -f "/snap/bin/certbot" ]]; then
        return 0
    else
        return 1
    fi
}

# 获取域名输入
get_domain_input() {
    local domain=""
    
    echo ""
    print_message "使用域名"
    print_message "请输入您的域名（例如: example.com）"
    print_message "注意：域名必须已经正确解析到此服务器的IP地址"
    
    while true; do
        echo ""
        read -p "域名: " domain
        
        # 清理域名
        domain=$(echo "$domain" | grep -o '[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z0-9][a-zA-Z0-9.-]*' | tail -1)
        
        # 验证域名不为空
        if [[ -z "$domain" ]]; then
            print_error "域名不能为空，请重新输入"
            continue
        fi
        
        # 域名格式验证
        if [[ "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\.-]*[a-zA-Z0-9])?$ ]] && [[ "$domain" == *.* ]]; then
            print_message "域名格式验证通过: $domain"
            break
        else
            print_error "域名格式不正确，请输入有效的域名（如: example.com）"
            continue
        fi
    done
    
    echo "$domain"
}

# 检查端口占用
check_port_usage() {
    local port="$1"
    
    if command -v netstat >/dev/null 2>&1; then
        netstat -tlnp 2>/dev/null | grep -q ":$port "
        return $?
    elif command -v ss >/dev/null 2>&1; then
        ss -tlnp 2>/dev/null | grep -q ":$port "
        return $?
    else
        timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/$port" 2>/dev/null
        return $?
    fi
}

# 获取占用端口的进程信息
get_port_process() {
    local port="$1"
    
    if command -v netstat >/dev/null 2>&1; then
        netstat -tlnp 2>/dev/null | grep ":$port " | awk '{print $7}' | head -1
    elif command -v ss >/dev/null 2>&1; then
        ss -tlnp 2>/dev/null | grep ":$port " | awk '{print $6}' | head -1
    else
        echo ""
    fi
}

# 停止占用端口的服务
stop_port_service() {
    local port="$1"
    local process_info="$2"
    
    if [[ -z "$process_info" ]]; then
        return 0
    fi
    
    # 检查是否是nginx进程
    if echo "$process_info" | grep -q "nginx"; then
        print_warning "检测到nginx占用${port}端口，尝试停止nginx服务..."
        
        # 尝试使用systemctl停止nginx
        if command -v systemctl >/dev/null 2>&1; then
            if systemctl is-active nginx >/dev/null 2>&1; then
                systemctl stop nginx
                sleep 5
                
                if ! systemctl is-active nginx >/dev/null 2>&1; then
                    print_message "nginx服务已停止"
                    sleep 2
                    return 0
                fi
            fi
        fi
        
        # 尝试强制停止nginx进程
        print_warning "尝试强制停止nginx进程..."
        pkill -TERM nginx 2>/dev/null || true
        sleep 2
        pkill -KILL nginx 2>/dev/null || true
        sleep 3
        
        if ! check_port_usage "$port"; then
            print_message "nginx进程已强制停止"
            return 0
        fi
    fi
    
    return 0
}

# 重新启动nginx服务
restart_nginx_service() {
    print_message "重新启动nginx服务..."
    
    if command -v systemctl >/dev/null 2>&1; then
        systemctl enable nginx >/dev/null 2>&1 || true
        systemctl start nginx
        sleep 2
        
        if systemctl is-active nginx >/dev/null 2>&1; then
            print_message "nginx服务已重新启动"
            return 0
        fi
    fi
    
    if command -v nginx >/dev/null 2>&1; then
        nginx 2>/dev/null
        sleep 2
        
        if check_port_usage 80; then
            local process_info=$(get_port_process 80)
            if echo "$process_info" | grep -q "nginx"; then
                print_message "nginx已重新启动"
                return 0
            fi
        fi
    fi
    
    print_warning "nginx服务重启失败，请手动检查"
    return 1
}

# 申请Let's Encrypt证书
apply_ssl_certificate() {
    local domain="$1"
    local config_dir="$2"
    local nginx_was_stopped=false
    
    print_message "开始为域名 $domain 申请 Let's Encrypt SSL证书..."
    
    # 检查并安装Certbot
    if ! check_certbot; then
        print_message "Certbot 未安装，尝试自动安装..."
        if ! install_certbot; then
            print_error "Certbot 安装失败，无法申请SSL证书"
            return 1
        fi
    fi
    
    # 确定certbot命令
    local certbot_cmd="certbot"
    if [[ -f "/snap/bin/certbot" ]]; then
        certbot_cmd="/snap/bin/certbot"
    fi
    
    # 创建配置目录
    mkdir -p "$config_dir"
    
    # 检查并释放80端口
    print_message "检查并释放80端口..."
    
    if check_port_usage 80; then
        local process_info=$(get_port_process 80)
        print_warning "检测到80端口被占用"
        
        if [[ -n "$process_info" ]]; then
            print_message "进程信息: $process_info"
            
            if echo "$process_info" | grep -q "nginx"; then
                nginx_was_stopped=true
                if command -v systemctl >/dev/null 2>&1; then
                    systemctl disable nginx >/dev/null 2>&1 || true
                fi
            fi
            
            stop_port_service 80 "$process_info"
        fi
    else
        print_message "80端口可用"
    fi
    
    # 申请证书
    print_message "正在申请SSL证书..."
    
    # 多次检查80端口是否已释放
    local port_check_attempts=0
    local max_attempts=5
    
    while [ $port_check_attempts -lt $max_attempts ]; do
        if ! check_port_usage 80; then
            print_message "80端口已释放，可以开始申请证书"
            break
        fi
        
        port_check_attempts=$((port_check_attempts + 1))
        print_warning "80端口仍被占用，等待释放... (尝试 $port_check_attempts/$max_attempts)"
        
        if [ $port_check_attempts -lt $max_attempts ]; then
            sleep 3
        else
            print_error "80端口仍被占用，但继续尝试申请证书"
            break
        fi
    done
    
    sleep 2
    
    local certbot_output
    certbot_output=$($certbot_cmd certonly --standalone --non-interactive --agree-tos --email admin@$domain --domains "$domain" --preferred-challenges http 2>&1)
    local certbot_exit_code=$?
    
    # 检查证书申请结果
    if [[ $certbot_exit_code -eq 0 ]]; then
        print_message "SSL证书申请成功！"
        
        # 复制证书文件
        if [[ -f "/etc/letsencrypt/live/$domain/fullchain.pem" ]]; then
            cp "/etc/letsencrypt/live/$domain/fullchain.pem" "$config_dir/server-cert.pem"
            cp "/etc/letsencrypt/live/$domain/privkey.pem" "$config_dir/server-key.pem"
            cp "/etc/letsencrypt/live/$domain/chain.pem" "$config_dir/ca-cert.pem"
            
            # 设置权限
            chmod 600 "$config_dir/server-key.pem"
            chmod 644 "$config_dir/server-cert.pem"
            chmod 644 "$config_dir/ca-cert.pem"
            
            print_message "证书文件已复制到 $config_dir"
            
            # 重新启动nginx服务（如果之前停止了的话）
            if [[ "$nginx_was_stopped" == "true" ]]; then
                restart_nginx_service
            fi
            
            return 0
        else
            print_error "证书文件未找到"
            
            if [[ "$nginx_was_stopped" == "true" ]]; then
                restart_nginx_service
            fi
            
            return 1
        fi
    else
        print_error "SSL证书申请失败"
        echo "$certbot_output" | head -10
        
        if [[ "$nginx_was_stopped" == "true" ]]; then
            restart_nginx_service
        fi
        
        return 1
    fi
}

# 设置证书自动续签
setup_auto_renewal() {
    local domain="$1"
    local config_dir="$2"
    
    print_message "设置SSL证书自动续签..."
    
    # 创建续签脚本
    cat > /etc/cron.daily/ocserv-renew << EOF
#!/bin/bash
# ocserv SSL证书自动续签脚本

# 使用snap版本的certbot，避免OpenSSL兼容性问题
CERTBOT_CMD="/snap/bin/certbot"
if [[ ! -f "\$CERTBOT_CMD" ]]; then
    CERTBOT_CMD="certbot"
fi

# 续签证书
\$CERTBOT_CMD renew --quiet

# 如果证书更新了，复制新证书
if [ \$? -eq 0 ]; then
    # 复制新证书
    cp /etc/letsencrypt/live/$domain/fullchain.pem $config_dir/server-cert.pem
    cp /etc/letsencrypt/live/$domain/privkey.pem $config_dir/server-key.pem
    cp /etc/letsencrypt/live/$domain/chain.pem $config_dir/ca-cert.pem
    
    # 设置权限
    chmod 600 $config_dir/server-key.pem
    chmod 644 $config_dir/server-cert.pem
    chmod 644 $config_dir/ca-cert.pem
    
    # 重启ocserv容器
    docker restart \$(docker ps --format "table {{.Names}}" | grep ocserv | head -1) > /dev/null 2>&1
fi
EOF
    
    chmod +x /etc/cron.daily/ocserv-renew
    print_message "SSL证书自动续签已设置，每天自动检查并续签"
}

# 快速自动部署
quick_deploy() {
    print_message "开始快速自动部署..."
    
    # 预设配置
    USERNAME="$DEFAULT_USERNAME"
    PASSWORD="$DEFAULT_PASSWORD"
    PORT="443"
    CONTAINER_NAME="$DEFAULT_CONTAINER_NAME"
    
    print_message "使用预设配置："
    echo "  用户名: $USERNAME"
    echo "  密码: $PASSWORD"
    echo "  端口: $PORT"
    echo "  容器名: $CONTAINER_NAME"
    
    # 停止并删除已存在的容器
    if docker ps -a | grep -q $CONTAINER_NAME; then
        print_warning "发现已存在的容器，正在停止并删除..."
        docker stop $CONTAINER_NAME 2>/dev/null || true
        docker rm $CONTAINER_NAME 2>/dev/null || true
    fi
    
    # 创建配置文件目录
    mkdir -p /opt/ocserv/ocserv-config
    
    # 创建ocserv配置文件
    cat > /opt/ocserv/ocserv-config/ocserv.conf << EOF
auth = "plain[passwd=/etc/ocserv/ocpasswd]"
tcp-port = $PORT
udp-port = $PORT
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
ipv4-network = 192.168.1.0
ipv4-netmask = 255.255.255.0
dns = 8.8.8.8
dns = 8.8.4.4
route = default
no-route = 192.168.1.0/255.255.255.0
cisco-client-compat = true
dtls-legacy = true
EOF
    
    # 生成密码哈希并创建用户密码文件
    print_message "生成用户密码文件..."
    PASSWORD_HASH=$(generate_password_hash "$PASSWORD")
    echo "$USERNAME:*:$PASSWORD_HASH" > /opt/ocserv/ocserv-config/ocpasswd
    
    # 拉取镜像
    print_message "拉取 ocserv 镜像..."
    docker pull tommylau/ocserv:latest
    
    # 启动容器
    print_message "启动 ocserv 容器..."
    docker run -d \
        --name $CONTAINER_NAME \
        --restart unless-stopped \
        -p $PORT:$PORT \
        -p $PORT:$PORT/udp \
        -v /opt/ocserv/ocserv-config:/etc/ocserv \
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
        ask_for_ssl_certificate "$server_address" "/opt/ocserv/ocserv-config"
        
        # 检查是否有SSL证书申请成功的域名
        if [[ -f "/opt/ocserv/ocserv-config/domain.txt" ]]; then
            server_address=$(cat "/opt/ocserv/ocserv-config/domain.txt")
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
    read -p "请输入端口 (默认443): " PORT
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
    
    print_message "使用自定义配置："
    echo "  用户名: $USERNAME"
    echo "  密码: $PASSWORD"
    echo "  端口: $PORT"
    echo "  容器名: $CONTAINER_NAME"
    
    # 停止并删除已存在的容器
    if docker ps -a | grep -q $CONTAINER_NAME; then
        print_warning "发现已存在的容器，正在停止并删除..."
        docker stop $CONTAINER_NAME 2>/dev/null || true
        docker rm $CONTAINER_NAME 2>/dev/null || true
    fi
    
    # 创建配置文件目录
    if [[ "$CONTAINER_NAME" == "ocserv" ]]; then
        CONFIG_DIR="/opt/ocserv/ocserv-config"
    else
        CONFIG_DIR="/opt/ocserv/ocserv-config-$CONTAINER_NAME"
    fi
    mkdir -p $CONFIG_DIR
    
    # 创建ocserv配置文件
    cat > $CONFIG_DIR/ocserv.conf << EOF
auth = "plain[passwd=/etc/ocserv/ocpasswd]"
tcp-port = $PORT
udp-port = $PORT
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
ipv4-network = 192.168.1.0
ipv4-netmask = 255.255.255.0
dns = 8.8.8.8
dns = 8.8.4.4
route = default
no-route = 192.168.1.0/255.255.255.0
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
    
    # 启动容器
    print_message "启动 ocserv 容器..."
    docker run -d \
        --name $CONTAINER_NAME \
        --restart unless-stopped \
        -p $PORT:$PORT \
        -p $PORT:$PORT/udp \
        -v $CONFIG_DIR:/etc/ocserv \
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

# 管理SSL证书
manage_ssl_cert() {
    print_message "SSL证书管理..."
    
    # 获取域名
    local domain
    domain=$(get_domain_input)
    
    if [[ -z "$domain" ]]; then
        print_error "域名获取失败"
        return 1
    fi
    
    print_message "使用域名: $domain"
    
    # 确定配置目录
    local config_dir="/opt/ocserv/ocserv-config"
    local container_name=$(docker ps --format "table {{.Names}}" | grep ocserv | head -1)
    if [[ -n "$container_name" ]] && [[ "$container_name" != "ocserv" ]]; then
        config_dir="/opt/ocserv/ocserv-config-$container_name"
    fi
    
    print_message "配置目录: $config_dir"
    
    # 申请Let's Encrypt证书
    print_message "开始申请Let's Encrypt免费SSL证书..."
    
    if apply_ssl_certificate "$domain" "$config_dir"; then
        setup_auto_renewal "$domain" "$config_dir"
        print_message "SSL证书配置完成！"
        
        # 将域名写入文件，供后续使用
        echo "$domain" > "$config_dir/domain.txt"
        
        # 重启ocserv容器以应用新证书
        if [[ -n "$container_name" ]]; then
            print_message "重启ocserv容器以应用新证书..."
            docker restart "$container_name"
            sleep 5
            
            if docker ps | grep -q "$container_name"; then
                print_message "ocserv容器已重启，SSL证书已生效"
            else
                print_error "ocserv容器重启失败"
            fi
        fi
        
        return 0
    else
        print_error "SSL证书申请失败"
        return 1
    fi
}

# 查看服务状态
show_service_status() {
    print_message "ocserv 服务状态..."
    
    # 检查容器状态
    if docker ps | grep -q ocserv; then
        echo ""
        echo "✅ 服务运行中："
        docker ps --filter "name=ocserv" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
        
        # 检查端口监听
        echo ""
        echo "端口监听状态："
        netstat -tlnp | grep :443 || echo "端口 443 未监听"
        
        # 显示连接信息
        echo ""
        echo "连接信息："
        CONTAINER_NAME=$(docker ps --format "table {{.Names}}" | grep ocserv | head -1)
        if [[ -n "$CONTAINER_NAME" ]]; then
            echo "容器名: $CONTAINER_NAME"
            echo "配置文件: /opt/ocserv/ocserv-config"
            echo "端口: 443"
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
                manage_ssl_cert
                return 0
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
    echo "  -q, --quick     快速自动部署 (使用预设账号: $DEFAULT_USERNAME/$DEFAULT_PASSWORD)"
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
        print_header
        print_menu
        
        read -p "请输入选择 (0-6): " choice
        
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
                stop_and_remove_ocserv
                ;;
            0)
                print_message "感谢使用！"
                exit 0
                ;;
            *)
                print_error "无效选择，请输入 0-6"
                ;;
        esac
        
        echo ""
        read -p "按回车键继续..."
        clear
    done
}

# 主函数
main() {
    # 初始化工作目录
    init_work_directory
    
    # 配置防火墙
    configure_firewall
    
    # 检查依赖
    check_docker
    check_openssl
    check_openssl_compatibility
    
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