# KeyOps - 基础设施管理平台

**基于 Go 的企业级 DevOps 一体化平台**

## 核心功能

- 🔐 **SSH Gateway** - 标准 SSH 协议直连
- 🌐 **Web Terminal** - WebSocket 实时终端
- 🖥️ **RDP 图形化** - Windows 远程桌面连接
- 🚨 **命令拦截** - 实时检测危险命令，飞书/钉钉告警
- 📋 **工单审批** - 飞书/钉钉审批流 + 自动授权
- 👥 **权限管理** - 用户组 + 主机组 + 系统用户
- 🎥 **完整审计** - 会话录制 + 命令历史 + 文件传输
- 🔑 **双因子认证** - 密码 / SSH 密钥
- 🌐 **高可用** - 多实例部署
- 📊 **资产同步** - Prometheus 资产同步
- 🔍 **实时监控** - 主机在线状态监控
- ☸️ **K8s 管理** - 多集群管理和权限控制
- 📈 **监控告警** - 告警规则、策略、通知管理
- 🏢 **组织管理** - 部门、应用、人员管理

## 快速部署

### 环境要求

- Docker 20.10+
- Docker Compose 2.0+

### MySQL 部署（推荐）

```bash
# 启动所有服务
docker-compose up -d

# 查看日志
docker-compose logs -f

# 停止服务
docker-compose down
```

**访问系统**: http://localhost:8080  
**默认账号**: `admin` / `admin123`

### PostgreSQL 部署

1. **修改 docker-compose.yml**，将 MySQL 服务替换为 PostgreSQL：

```yaml
services:
  postgres:
    image: postgres:15-alpine
    container_name: keyops-postgres
    restart: unless-stopped
    environment:
      POSTGRES_USER: ${POSTGRES_USER:-postgres}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-postgres}
      POSTGRES_DB: ${POSTGRES_DB:-keyops}
      TZ: Asia/Shanghai
    ports:
      - "${POSTGRES_PORT:-5432}:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./sql/init_postgres.sql:/docker-entrypoint-initdb.d/init.sql:ro
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - keyops-network

volumes:
  postgres_data:
    driver: local
```

2. **修改环境变量**，在 `.env` 文件中设置：

```bash
DB_DRIVER=postgres
DB_HOST=postgres
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=postgres
DB_NAME=keyops
```

3. **启动服务**：

```bash
docker-compose up -d
```

## 端口说明

- `8080`: HTTP（Web + API）
- `2222`: SSH Gateway
- `3306`: MySQL（可选）
- `5432`: PostgreSQL（可选）
- `6379`: Redis（可选）
- `4822`: Guacamole daemon（RDP）

## 环境变量配置

创建 `.env` 文件（可选）：

```bash
# 数据库配置
MYSQL_ROOT_PASSWORD=123456
MYSQL_DATABASE=keyops
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres
POSTGRES_DB=keyops

# Redis配置
REDIS_ENABLED=true
REDIS_PASSWORD=

# 服务端口
HTTP_PORT=8080
SSH_PORT=2222
GUACD_PORT=4822
```

## 许可证

GNU General Public License v3.0 (GPLv3)
