# OCserv Docker 一键部署脚本

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Shell Script](https://img.shields.io/badge/Shell-Bash-green.svg)](https://www.gnu.org/software/bash/)
[![Docker](https://img.shields.io/badge/Docker-Required-blue.svg)](https://www.docker.com/)

一个功能完整的 OCserv (OpenConnect Server) Docker 一键部署脚本，支持自动 SSL 证书申请、防火墙配置和服务管理。

## 🚀 功能特性

- **一键部署**: 自动化部署 OCserv Docker 容器
- **SSL 证书管理**: 集成 Let's Encrypt 证书自动申请和续签
- **防火墙自动配置**: 自动开启必要端口 (80, 443/tcp, 443/udp)
- **多系统支持**: 支持 CentOS/RHEL、Ubuntu/Debian 系统
- **SELinux 兼容**: 自动处理 SELinux 配置
- **服务管理**: 提供完整的服务启停、状态查看功能
- **用户友好**: 彩色输出界面，清晰的操作提示

## 📋 系统要求

- **操作系统**: CentOS 7+, RHEL 7+, Ubuntu 16.04+, Debian 9+
- **Docker**: 已安装并运行
- **网络**: 服务器需要公网 IP 和域名解析
- **端口**: 80, 443 端口可用
- **权限**: root 用户权限

## 🛠️ 安装使用

### 快速开始

```bash
# 下载脚本
wget https://raw.githubusercontent.com/moli-xia/ocserv-docker/main/ocserv_onekey_deploy.sh

# 添加执行权限
chmod +x ocserv_onekey_deploy.sh

# 运行脚本
./ocserv_onekey_deploy.sh
```

### 使用 curl 下载

```bash
curl -O https://raw.githubusercontent.com/moli-xia/ocserv-docker/main/ocserv_onekey_deploy.sh
chmod +x ocserv_onekey_deploy.sh
./ocserv_onekey_deploy.sh
```

## 📖 使用说明

### 主菜单选项

脚本运行后会显示交互式菜单：

```
========================================
           OCserv 管理脚本
========================================
1. 快速部署 OCserv (推荐)
2. 自定义部署 OCserv
3. 申请/更新 SSL 证书
4. 查看服务状态
5. 显示连接信息
0. 退出脚本
========================================
```

### 1. 快速部署 (推荐)

- 自动检测系统环境
- 自动配置防火墙规则
- 使用默认配置快速部署
- 自动申请 SSL 证书
- 预设用户名: `user`, 密码: `654321`

### 2. 自定义部署

- 可自定义用户名和密码
- 可选择是否申请 SSL 证书
- 更多配置选项

### 3. SSL 证书管理

- 支持 Let's Encrypt 免费证书
- 自动续签配置
- 证书状态检查

## 🔧 配置说明

### 工作目录

脚本会在 `/opt/ocserv` 目录下创建以下文件：

```
/opt/ocserv/
├── ocserv.conf          # OCserv 主配置文件
├── ocpasswd             # 用户密码文件
├── server-cert.pem      # SSL 证书文件
├── server-key.pem       # SSL 私钥文件
└── ca-cert.pem          # CA 证书文件
```

### 默认配置

- **端口**: 443 (TCP/UDP)
- **协议**: AnyConnect, OpenConnect
- **加密**: AES-256-GCM
- **认证**: 用户名/密码
- **DNS**: 8.8.8.8, 8.8.4.4
- **路由**: 全局代理

### 防火墙配置

脚本会自动配置以下防火墙规则：

```bash
# 开启必要端口
firewall-cmd --permanent --add-port=80/tcp
firewall-cmd --permanent --add-port=443/tcp
firewall-cmd --permanent --add-port=443/udp
firewall-cmd --reload
```

## 🔐 SSL 证书

### 自动申请条件

1. 域名已正确解析到服务器 IP
2. 80 端口可访问 (用于域名验证)
3. 服务器可连接互联网

### 手动证书

如果无法自动申请证书，可以手动放置证书文件到 `/opt/ocserv/` 目录：

- `server-cert.pem`: 服务器证书
- `server-key.pem`: 私钥文件
- `ca-cert.pem`: CA 证书 (可选)

## 📱 客户端连接

### AnyConnect 客户端

1. 下载 Cisco AnyConnect 客户端
2. 服务器地址: `https://your-domain.com:443`
3. 用户名: `user` (或自定义)
4. 密码: `654321` (或自定义)

### OpenConnect 客户端

```bash
# Linux/macOS
sudo openconnect -u user https://your-domain.com:443

# 或指定密码
echo '654321' | sudo openconnect -u user --passwd-on-stdin https://your-domain.com:443
```

## 🛡️ 安全建议

1. **修改默认密码**: 部署后立即修改默认密码
2. **定期更新**: 定期更新 Docker 镜像和系统
3. **监控日志**: 定期检查连接日志
4. **限制用户**: 根据需要限制并发连接数
5. **备份配置**: 定期备份配置文件

## 🔍 故障排除

### 常见问题

**1. 证书申请失败**
```bash
# 检查域名解析
nslookup your-domain.com

# 检查 80 端口
telnet your-domain.com 80
```

**2. 连接失败**
```bash
# 检查服务状态
docker ps | grep ocserv

# 查看日志
docker logs ocserv
```

**3. 防火墙问题**
```bash
# 检查防火墙状态
firewall-cmd --list-all

# 临时关闭防火墙测试
systemctl stop firewalld
```

### 日志查看

```bash
# 查看 OCserv 日志
docker logs ocserv

# 实时查看日志
docker logs -f ocserv

# 查看系统日志
journalctl -u docker
```

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启 Pull Request

## 📄 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情。

## 🙏 致谢

- [OCserv](http://www.infradead.org/ocserv/) - OpenConnect VPN Server
- [Let's Encrypt](https://letsencrypt.org/) - 免费 SSL 证书
- [Docker](https://www.docker.com/) - 容器化平台

## 📞 支持

如果您觉得这个项目有用，请给它一个 ⭐️！

如有问题，请提交 [Issue](https://github.com/moli-xia/ocserv-docker/issues)。

---

**注意**: 本脚本仅供学习和合法用途使用，请遵守当地法律法规。