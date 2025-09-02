#!/bin/bash

# 完全重写的SSL证书申请脚本
# 适用于任意Linux系统，不依赖特定环境
# 
# 修复内容:
# 1. 正确处理nginx服务的停止和重启
# 2. 使用systemctl管理nginx服务而不是直接kill进程
# 3. 只在必要时重启nginx服务
# 4. 增强端口占用检测和错误处理
# 5. 添加证书申请前的最终端口检查

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

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

# 防火墙和端口管理函数
manage_firewall_for_ssl() {
    print_message "为SSL证书申请配置防火墙和端口..."
    
    # 检测防火墙类型并开启端口
    if command -v ufw >/dev/null 2>&1; then
        print_message "检测到UFW防火墙，开启端口80和443..."
        ufw allow 80/tcp >/dev/null 2>&1
        ufw allow 443/tcp >/dev/null 2>&1
        print_message "UFW防火墙端口已开启"
    elif command -v firewall-cmd >/dev/null 2>&1; then
        print_message "检测到firewalld防火墙，开启端口80和443..."
        firewall-cmd --permanent --add-port=80/tcp >/dev/null 2>&1
        firewall-cmd --permanent --add-port=443/tcp >/dev/null 2>&1
        firewall-cmd --reload >/dev/null 2>&1
        print_message "firewalld防火墙端口已开启"
    elif command -v iptables >/dev/null 2>&1; then
        print_message "检测到iptables防火墙，开启端口80和443..."
        iptables -I INPUT -p tcp --dport 80 -j ACCEPT >/dev/null 2>&1
        iptables -I INPUT -p tcp --dport 443 -j ACCEPT >/dev/null 2>&1
        # 尝试保存iptables规则
        if command -v iptables-save >/dev/null 2>&1; then
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        fi
        print_message "iptables防火墙端口已开启"
    else
        print_warning "未检测到已知的防火墙，请手动确保端口80和443已开启"
    fi
    
    print_warning "如果您使用的是云服务器，请确保在安全组中开启了80和443端口！"
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
                print_message "安装方法："
                print_message "  Ubuntu/Debian: apt-get install certbot"
                print_message "  CentOS/RHEL: yum install certbot"
                print_message "  Snap: snap install certbot --classic"
                print_message "  Pip: pip3 install certbot"
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

# 获取域名输入 - 使用最简单的方法
get_domain_input() {
    local domain=""
    
    # 在循环外显示说明信息
    echo ""
    print_message "使用域名"
    print_message "请输入您的域名（例如: example.com）"
    print_message "注意：域名必须已经正确解析到此服务器的IP地址"
    print_message "域名长度必须不超过253个字符，单个标签不超过63个字符"
    
    while true; do
        echo ""
        # 直接读取域名
        read -p "域名: " domain
        
        # 彻底清理域名 - 提取最后一个有效的域名
        domain=$(echo "$domain" | grep -o '[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z0-9][a-zA-Z0-9.-]*' | tail -1)
        
        # 验证域名不为空
        if [[ -z "$domain" ]]; then
            print_error "域名不能为空，请重新输入"
            continue
        fi
        
        # 检查域名长度
        local domain_length=${#domain}
        if [[ $domain_length -gt 253 ]]; then
            print_error "域名过长（${domain_length}字符），请使用253字符以内的域名"
            continue
        fi
        
        # 检查单个标签长度
        IFS='.' read -ra LABELS <<< "$domain"
        local label_error=false
        for label in "${LABELS[@]}"; do
            if [[ ${#label} -gt 63 ]]; then
                print_error "域名标签过长：'$label'（${#label}字符），单个标签不能超过63字符"
                label_error=true
            fi
        done
        
        if [[ "$label_error" == true ]]; then
            continue
        fi
        
        # 域名格式验证
        if [[ "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\.-]*[a-zA-Z0-9])?$ ]] && [[ "$domain" == *.* ]]; then
            print_message "域名格式验证通过: $domain (${domain_length}字符)"
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
    local protocol="${2:-tcp}"
    
    # 检查端口是否被占用
    if command -v netstat >/dev/null 2>&1; then
        netstat -tlnp 2>/dev/null | grep -q ":$port "
        return $?
    elif command -v ss >/dev/null 2>&1; then
        ss -tlnp 2>/dev/null | grep -q ":$port "
        return $?
    else
        # 如果没有netstat或ss，尝试直接绑定端口测试
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
                sleep 5  # 增加等待时间
                
                # 检查nginx是否已停止
                if ! systemctl is-active nginx >/dev/null 2>&1; then
                    print_message "nginx服务已停止"
                    # 额外等待确保端口完全释放
                    sleep 2
                    return 0
                else
                    print_warning "systemctl停止nginx失败，尝试其他方法"
                fi
            fi
        fi
        
        # 尝试使用nginx -s stop
        if command -v nginx >/dev/null 2>&1; then
            print_warning "尝试使用nginx命令停止服务..."
            nginx -s stop 2>/dev/null
            sleep 5  # 增加等待时间
            
            # 再次检查端口
            if ! check_port_usage "$port"; then
                print_message "nginx已停止"
                return 0
            fi
        fi
        
        # 如果nginx仍未停止，尝试强制停止所有nginx进程
        print_warning "尝试强制停止nginx进程..."
        
        # 检测系统类型并使用相应的命令
        if [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]] || command -v taskkill >/dev/null 2>&1; then
            # Windows环境使用taskkill
            taskkill /F /IM nginx.exe 2>/dev/null || true
        else
            # Linux环境使用pkill，先尝试SIGTERM，再尝试SIGKILL
            pkill -TERM nginx 2>/dev/null || true
            sleep 2
            pkill -KILL nginx 2>/dev/null || true
        fi
        sleep 3
        
        # 最后检查端口是否释放
        if ! check_port_usage "$port"; then
            print_message "nginx进程已强制停止"
            return 0
        else
            print_warning "强制停止nginx后端口仍被占用，可能需要手动处理"
            # 不直接返回失败，让调用方继续尝试
            return 0
        fi
    fi
    
    # 提取PID
    local pid=$(echo "$process_info" | sed 's/.*:\([0-9]*\).*/\1/')
    
    if [[ -n "$pid" ]] && [[ "$pid" =~ ^[0-9]+$ ]]; then
        print_warning "停止占用${port}端口的进程 (PID: $pid)..."
        
        # 尝试优雅停止
        kill "$pid" 2>/dev/null
        sleep 3  # 增加等待时间
        
        # 检查是否还在运行
        if kill -0 "$pid" 2>/dev/null; then
            print_warning "进程仍在运行，尝试强制停止..."
            kill -9 "$pid" 2>/dev/null
            sleep 2  # 增加等待时间
        fi
        
        # 最终检查
        if kill -0 "$pid" 2>/dev/null; then
            print_error "无法停止进程 $pid"
            return 1
        else
            print_message "进程 $pid 已停止"
            return 0
        fi
    fi
    
    return 0
}

# 重新启动nginx服务
restart_nginx_service() {
    print_message "重新启动nginx服务..."
    
    # 尝试使用systemctl启动nginx
    if command -v systemctl >/dev/null 2>&1; then
        # 重新启用nginx自动启动
        systemctl enable nginx >/dev/null 2>&1 || true
        systemctl start nginx
        sleep 2
        
        # 检查nginx是否启动成功
        if systemctl is-active nginx >/dev/null 2>&1; then
            print_message "nginx服务已重新启动"
            return 0
        else
            print_warning "systemctl启动nginx失败，尝试其他方法"
        fi
    fi
    
    # 尝试直接启动nginx
    if command -v nginx >/dev/null 2>&1; then
        nginx 2>/dev/null
        sleep 2
        
        # 检查80端口是否被nginx占用（说明启动成功）
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
    
    # 清理域名 - 提取最后一个有效的域名
    local clean_domain=$(echo "$domain" | grep -o '[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z0-9][a-zA-Z0-9.-]*' | tail -1)
    
    print_message "开始为域名 $clean_domain 申请 Let's Encrypt SSL证书..."
    
    # 配置防火墙和端口
    manage_firewall_for_ssl
    
    # 检查并安装Certbot
    if ! check_certbot; then
        print_message "Certbot 未安装或无法正常工作，尝试自动安装..."
        
        # 优先尝试snap安装
        if command -v snap >/dev/null 2>&1; then
            print_message "尝试使用snap安装Certbot..."
            snap install certbot --classic
            if [[ $? -eq 0 ]]; then
                print_message "Snap Certbot 安装成功"
            else
                print_warning "Snap安装失败，尝试其他方法"
                if ! install_certbot; then
                    print_error "Certbot 安装失败，无法申请SSL证书"
                    return 1
                fi
            fi
        else
            if ! install_certbot; then
                print_error "Certbot 安装失败，无法申请SSL证书"
                return 1
            fi
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
            
            # 检查是否是nginx进程
            if echo "$process_info" | grep -q "nginx"; then
                nginx_was_stopped=true
                # 临时禁用nginx自动启动，防止被自动重启
                if command -v systemctl >/dev/null 2>&1; then
                    systemctl disable nginx >/dev/null 2>&1 || true
                fi
            fi
            
            # 尝试停止占用80端口的服务
            stop_port_service 80 "$process_info"
            # 不管停止是否成功，都继续执行后续的端口检查循环
        else
            print_warning "无法获取占用80端口的进程信息"
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
        
        # 如果端口仍被占用，检查是否是nginx重新启动了
        local current_process_info=$(get_port_process 80)
        if echo "$current_process_info" | grep -q "nginx"; then
            print_warning "检测到nginx重新启动，再次尝试停止"
            stop_port_service 80 "$current_process_info"
        fi
        
        if [ $port_check_attempts -lt $max_attempts ]; then
            sleep 3
        else
            print_error "80端口仍被占用，但继续尝试申请证书"
            local process_info=$(get_port_process 80)
            print_warning "占用进程: $process_info"
            break
        fi
    done
    
    # 额外等待确保端口完全可用
    sleep 2
    
    local certbot_output
    certbot_output=$($certbot_cmd certonly --standalone --non-interactive --agree-tos --email admin@$clean_domain --domains "$clean_domain" --preferred-challenges http 2>&1)
    local certbot_exit_code=$?
    
    # 检查证书申请结果
    if [[ $certbot_exit_code -eq 0 ]]; then
        print_message "SSL证书申请成功！"
        
        # 复制证书文件
        if [[ -f "/etc/letsencrypt/live/$clean_domain/fullchain.pem" ]]; then
            cp "/etc/letsencrypt/live/$clean_domain/fullchain.pem" "$config_dir/server-cert.pem"
            cp "/etc/letsencrypt/live/$clean_domain/privkey.pem" "$config_dir/server-key.pem"
            cp "/etc/letsencrypt/live/$clean_domain/chain.pem" "$config_dir/ca-cert.pem"
            
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
            
            # 即使证书申请失败，也尝试重启nginx（如果之前停止了的话）
            if [[ "$nginx_was_stopped" == "true" ]]; then
                restart_nginx_service
            fi
            
            return 1
        fi
    else
        print_error "SSL证书申请失败"
        echo "$certbot_output" | head -10
        
        # 证书申请失败时也要重启nginx（如果之前停止了的话）
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
    
    # 清理域名
    local clean_domain=$(echo "$domain" | grep -o '[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z0-9][a-zA-Z0-9.-]*' | tail -1)
    
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
    cp /etc/letsencrypt/live/$clean_domain/fullchain.pem $config_dir/server-cert.pem
    cp /etc/letsencrypt/live/$clean_domain/privkey.pem $config_dir/server-key.pem
    cp /etc/letsencrypt/live/$clean_domain/chain.pem $config_dir/ca-cert.pem
    
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

# 主函数 - SSL证书申请
main_ssl_certificate() {
    echo ""
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}           SSL证书申请${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo ""
    
    # 获取域名
    local domain
    domain=$(get_domain_input)
    
    if [[ -z "$domain" ]]; then
        print_error "域名获取失败"
        return 1
    fi
    
    print_message "使用域名: $domain"
    
    # 确定配置目录
    local config_dir="/opt/ocserv"
    local container_name=$(docker ps --format "table {{.Names}}" | grep ocserv | head -1)
    if [[ -n "$container_name" ]] && [[ "$container_name" != "ocserv" ]]; then
        config_dir="/opt/ocserv-$container_name"
    fi
    
    # 确保配置目录存在
    mkdir -p "$config_dir"
    if [ $? -ne 0 ]; then
        print_error "无法创建配置目录 $config_dir"
        return 1
    fi
    
    print_message "配置目录: $config_dir"
    
    # 直接开始申请Let's Encrypt证书
    print_message "开始申请Let's Encrypt免费SSL证书..."
    
    if apply_ssl_certificate "$domain" "$config_dir"; then
        setup_auto_renewal "$domain" "$config_dir"
        print_message "SSL证书配置完成！"
        
        # 将域名写入文件，供后续使用
        echo "$domain" > "$config_dir/domain.txt"
        
        return 0
    else
        print_error "Let's Encrypt证书申请失败"
        print_message "请检查域名解析是否正确，或稍后重试"
        return 1
    fi
}

# 如果直接运行此脚本
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main_ssl_certificate
fi
