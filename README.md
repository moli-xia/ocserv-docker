# OCserv Docker部署工具

一个功能完整的OCserv (OpenConnect Server) Docker 部署脚本，支持快速部署、SSL证书自动申请、与nginx共存等高级功能。
- Windows和安卓、mac客户端请见[Releases](Releases)Release页面。

## 🚀 功能特性

- **一键部署**: 支持快速部署和自定义部署两种模式
- **SSL证书管理**: 自动申请和续期 Let's Encrypt SSL证书
- **端口共存**: 智能检测端口占用，支持与nginx/OpenResty共存
- **防火墙自动配置**: 自动开启所需端口，支持UFW、firewalld、iptables
- **多系统支持**: 兼容Ubuntu、Debian、CentOS、RHEL等主流Linux发行版
- **配置管理**: 统一配置目录管理，便于维护和备份
- **容器化部署**: 基于Docker，隔离性好，易于管理

## 📋 系统要求

- Linux 系统 (Ubuntu 18.04+, Debian 9+, CentOS 7+)
- Docker 和 Docker Compose
- 域名解析到服务器IP (申请SSL证书时需要)
- 开放端口 80、443 (HTTP/HTTPS)

## 🛠️ 安装使用

### 1. 下载脚本

```bash
# 克隆项目
git clone https://github.com/moli-xia/ocserv-docker.git
cd ocserv-docker

# 给脚本执行权限
chmod +x ocserv_deploy.sh ssl_certificate.sh
```

### 2. 交互式菜单部署(推荐)

直接运行脚本进入交互式菜单:

```bash
./ocserv_deploy.sh
```

### 3. 快速部署

使用预设配置快速部署 (用户名: NoRoute, 密码: 654321):

```bash
./ocserv_deploy.sh -q
```

### 4. 自定义部署

```bash
./ocserv_deploy.sh -c
```



## 📁 目录结构

```
ocserv-docker/
├── ocserv_deploy.sh     # 主部署脚本
├── ssl_certificate.sh   # SSL证书管理脚本
└── README.md           # 说明文档
```

部署后的配置文件位于:
```
/opt/ocserv/            # 主配置目录
├── ocserv.conf         # OCserv主配置文件
├── ocpasswd           # 用户密码文件
├── server-cert.pem    # SSL证书文件
├── server-key.pem     # SSL私钥文件
├── ca-cert.pem        # CA证书文件
└── domain.txt         # 域名记录文件
```

## 🔧 配置说明

### 默认配置

- **用户名**: NoRoute
- **密码**: 654321
- **端口**: 443 (TCP/UDP)
- **协议**: AnyConnect
- **配置目录**: /opt/ocserv

### 支持的客户端

- Cisco AnyConnect
- OpenConnect
- 各平台的兼容客户端

## 📱 客户端连接

### Windows/Mac
1. 下载并安装 Cisco AnyConnect 客户端
2. 输入服务器地址 (域名或IP)
3. 使用用户名和密码登录

### Linux
```bash
# 安装openconnect
sudo apt install openconnect  # Ubuntu/Debian
sudo yum install openconnect  # CentOS/RHEL

# 连接
sudo openconnect your-server.com
```

### Android/iOS
1. 下载 Cisco AnyConnect 应用
2. 添加新的VPN连接
3. 输入服务器信息和认证凭据

## 🔐 SSL证书管理

### 自动申请证书

脚本会自动检测是否需要SSL证书，并引导您完成申请:

```bash
# 单独管理SSL证书
./ssl_certificate.sh
```

### 证书续期

脚本会自动设置证书续期任务，无需手动干预。

## 🚨 故障排除

### 常见问题

1. **端口被占用**
   - 脚本会自动检测并使用端口共存模式
   - 确保防火墙已开启相应端口

2. **SSL证书申请失败**
   - 检查域名是否正确解析到服务器IP
   - 确保端口80、443已开启
   - 检查防火墙和安全组设置

3. **容器启动失败**
   ```bash
   # 查看容器日志
   docker logs ocserv
   
   # 检查容器状态
   docker ps -a
   ```

4. **连接失败**
   - 检查服务器防火墙设置
   - 确认客户端配置正确
   - 查看服务器日志排查问题

### 日志查看

```bash
# 查看OCserv日志
docker logs ocserv

# 实时查看日志
docker logs -f ocserv
```

## 🔄 管理命令

### 服务管理

```bash
# 启动服务
docker start ocserv

# 停止服务
docker stop ocserv

# 重启服务
docker restart ocserv

# 查看状态
docker ps | grep ocserv
```

### 用户管理

```bash
# 进入容器
docker exec -it ocserv /bin/bash

# 添加用户
echo "username:*:$(openssl passwd -1 password)" >> /etc/ocserv/ocpasswd

# 重启服务使配置生效
docker restart ocserv
```

## 🛡️ 安全建议

1. **定期更新密码**: 建议定期更换VPN用户密码
2. **监控连接**: 定期检查连接日志，发现异常及时处理
3. **防火墙配置**: 只开放必要的端口
4. **系统更新**: 保持系统和Docker版本更新

## 📞 技术支持

如果您在使用过程中遇到问题，可以:

1. 查看本文档的故障排除部分
2. 在 [GitHub Issues](https://github.com/moli-xia/ocserv-docker/issues) 提交问题
3. 查看项目 [Wiki](https://github.com/moli-xia/ocserv-docker/wiki) 获取更多信息

## 📄 许可证

本项目采用 MIT 许可证，详情请查看 [LICENSE](LICENSE) 文件。

## 🤝 贡献

欢迎提交 Pull Request 或 Issue 来改进这个项目！

## ⭐ 致谢

感谢所有为这个项目做出贡献的开发者和用户！

---

**注意**: 请确保您有合法使用VPN的权限，并遵守当地法律法规。
