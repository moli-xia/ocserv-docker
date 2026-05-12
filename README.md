# OCserv Docker 部署工具

来源仓库: <https://github.com/moli-xia/ocserv-docker>

一个单脚本版的 OCserv (OpenConnect Server) Docker 部署工具，支持快速部署、自定义部署、Let's Encrypt 证书申请续签，以及与宿主机 `nginx` / OpenResty / 宝塔面板环境共存。

- Windows、Android、macOS 客户端请见 [Releases](Releases) 页面。

## 功能特性

- 一键部署: 支持快速部署和自定义部署
- 单脚本整合: `ocserv_deploy.sh` 同时负责部署、证书申请和续签
- 端口共存: 宿主机 `443` 被占用时，自动切换到 `8443+`
- 宝塔兼容: 检测到宝塔面板后，自动尝试放行实际使用的端口
- 防火墙处理: 同时兼容 `ufw`、`firewalld`、`iptables`
- 证书管理: 集成 Let's Encrypt 申请和自动续签
- 容器化部署: 基于 Docker，便于隔离、迁移和维护

## 系统要求

- Linux 系统: Ubuntu 18.04+, Debian 9+, CentOS 7+, Rocky, AlmaLinux
- Docker 已安装并正常运行
- 域名已解析到服务器 IP
- 申请证书时可访问 `80/tcp`
- 若使用云服务器，还需在安全组中放行实际端口

## 安装使用

### 1. 下载脚本

方式一: 使用 `git clone`

```bash
git clone https://github.com/moli-xia/ocserv-docker.git
cd ocserv-docker
chmod +x ocserv_deploy.sh
```

方式二: 使用 `wget`

```bash
mkdir -p ocserv-docker && cd ocserv-docker
wget -O ocserv_deploy.sh https://raw.githubusercontent.com/moli-xia/ocserv-docker/main/ocserv_deploy.sh
chmod +x ocserv_deploy.sh
```

方式三: 使用 `curl`

```bash
mkdir -p ocserv-docker && cd ocserv-docker
curl -L https://raw.githubusercontent.com/moli-xia/ocserv-docker/main/ocserv_deploy.sh -o ocserv_deploy.sh
chmod +x ocserv_deploy.sh
```

### 2. 交互式菜单部署

```bash
./ocserv_deploy.sh
```

### 3. 快速部署

默认账号:

- 用户名: `NoRoute`
- 密码: `654321`

运行命令:

```bash
./ocserv_deploy.sh -q
```

### 4. 自定义部署

```bash
./ocserv_deploy.sh -c
```

## 目录结构

```text
ocserv-docker/
├── ocserv_deploy.sh
├── README.md
├── LICENSE
└── .gitignore
```

部署后的默认配置目录:

```text
/opt/ocserv/
├── ocserv.conf
├── ocpasswd
├── server-cert.pem
├── server-key.pem
├── ca-cert.pem
└── domain.txt
```

## 配置说明

### 默认行为

- 协议: AnyConnect
- 容器内端口: `443/tcp` 和 `443/udp`
- 宿主机端口: 优先使用 `443`，占用时自动改用 `8443+`
- 配置目录: `/opt/ocserv`

### 宝塔面板说明

- 如果服务器安装了宝塔面板，脚本会优先尝试通过 `bt` 命令放行端口
- 如果宝塔放行失败，脚本会继续尝试 `ufw`、`firewalld` 或 `iptables`
- 若服务器在云厂商上，还需要手动同步安全组规则

## SSL 证书管理

### 菜单内申请证书

直接运行脚本，在菜单中选择 `3. 管理SSL证书` 即可。

### 部署时申请证书

快速部署和自定义部署完成后，脚本会询问是否立即申请 Let's Encrypt 证书。

申请证书时，脚本可能会临时停止占用 `80` 端口的 `nginx`，证书申请结束后会自动尝试恢复 `nginx` 和宝塔面板服务。

### 自动续签

脚本会创建 `/etc/cron.daily/ocserv-renew`，用于自动续签证书并重启容器加载新证书。

## 客户端连接

### Windows / macOS

1. 安装 Cisco AnyConnect 或兼容客户端
2. 输入服务器地址
3. 使用用户名和密码登录

### Linux

```bash
sudo apt install openconnect
sudo openconnect your-server.com
```

如果实际使用的是备用端口，请写成:

```bash
sudo openconnect https://your-server.com:8443
```

### Android / iOS

1. 安装 Cisco AnyConnect 或兼容客户端
2. 新建 VPN 连接
3. 输入服务器地址、用户名和密码

## 常见问题

### 1. 宿主机已经安装 nginx，为什么会冲突？

因为 OCserv 不是普通 Web 应用，原来如果直接映射宿主机 `443`，就会和宿主机 `nginx` 抢占同一端口。

现在脚本会自动检测:

- `443` 可用: 直接使用 `443`
- `443` 被占用: 自动改用 `8443+`

这样宿主机 `nginx` 和 OCserv 可以同时运行。

### 2. 宝塔面板环境下为什么还会连不上？

常见原因:

- 宝塔防火墙未放行实际使用端口
- 云服务器安全组未同步放行
- 宿主机端口已监听，但外网规则未开放

### 3. SSL 证书申请失败

- 检查域名解析是否正确
- 确保 `80/tcp` 可访问
- 检查 `nginx`、防火墙和安全组设置

### 4. 容器启动失败

```bash
docker ps -a
docker logs ocserv
```

## 常用管理命令

```bash
docker start ocserv
docker stop ocserv
docker restart ocserv
docker logs -f ocserv
docker ps --filter "name=ocserv"
```

## 许可证

本项目采用 [MIT License](LICENSE)。

## 说明

请确保你有合法使用 VPN 的权限，并遵守所在地法律法规。
