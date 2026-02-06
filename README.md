# KeyOps - 基础设施管理平台 / Infrastructure Management Platform

[English](#english) | [中文](#中文)

---

<a name="中文"></a>

**相关截图**
<img width="2924" height="1374" alt="image" src="https://github.com/user-attachments/assets/8a50b150-3c33-49df-b201-5c398a03f3ab" />
<img width="2504" height="1582" alt="image" src="https://github.com/user-attachments/assets/c20edb04-d634-43a5-94f4-1a982c55e8e7" />

**基于 Go 的企业级 DevOps 一体化平台**

## 核心功能

### 功能概览表

| 功能分类 | 功能名称 | 功能描述 | 状态 |
|---------|---------|---------|------|
| **🛡️ 堡垒机** | 🔐 SSH Gateway | 标准 SSH 协议直连，支持传统 SSH 客户端工具 | ✅ |
| | 🌐 Web Terminal | WebSocket 实时终端，无需安装客户端，支持多会话管理 | ✅ |
| | 🖥️ RDP 图形化 | Windows 远程桌面连接，支持图形界面操作 | ✅ |
| | 🎥 会话录制 | 完整的会话录制和回放功能，支持 Asciinema 格式 | ✅ |
| | 📝 命令历史 | 完整的命令执行历史记录和查询 | ✅ |
| | 📁 文件传输 | 文件上传/下载管理，支持 SFTP 协议 | ✅ |
| | 🚨 命令拦截 | 实时检测危险命令，支持命令黑名单，飞书/钉钉告警 | ✅ |
| | 👤 系统用户管理 | 系统用户（跳板用户）的统一管理和密钥分发 | ✅ |
| | 🔑 双因子认证 | 支持密码 / SSH 密钥等多种认证方式 | ✅ |
| **☸️ K8s 多集群** | 🌐 集群管理 | 多集群统一管理，支持 Token/Kubeconfig 认证 | ✅ |
| | 🔐 集群权限 | 基于用户/角色的集群访问权限控制，支持命名空间隔离 | ✅ |
| | 📦 工作负载 | Deployment、DaemonSet、StatefulSet、Pod、CronJob 管理 | ✅ |
| | ⚙️ 配置管理 | ConfigMap、Secret 的统一管理和编辑 | ✅ |
| | 🌐 服务管理 | Service、Ingress 的创建和管理 | ✅ |
| | 💾 存储管理 | PV、PVC、StorageClass 的配置和管理 | ✅ |
| | 📊 集群监控 | 集群状态概览、资源使用监控、事件查看 | ✅ |
| | 📋 操作审计 | K8s 操作的完整审计日志 | ✅ |
| **📋 工单管理** | 📝 工单创建 | 支持日常工单、发布工单等多种类型 | ✅ |
| | 📑 表单模板 | 可视化表单设计器，支持自定义表单模板 | ✅ |
| | 🔄 审批流程 | 支持飞书/钉钉/企微/内部审批，多级审批流程（企微回调待完善） | ✅ |
| | ✅ 自动授权 | 审批通过后自动授权，支持权限规则自动应用 | ✅ |
| | 📊 工单统计 | 工单状态跟踪、审批历史、统计分析 | ✅ |
| **🏢 组织应用** | 👥 部门管理 | 多级部门结构管理，支持部门树形组织 | ✅ |
| | 📱 应用管理 | 应用信息管理，关联部门和人员 | ✅ |
| | 👤 人员管理 | 用户信息管理，支持部门关联和角色分配 | ✅ |
| | 🔧 服务管理 | 服务目录管理，支持服务分类和详情配置 | ✅ |
| **🔐 多态权限** | 👥 用户组（角色） | 基于角色的权限管理，支持角色成员管理 | ✅ |
| | 🖥️ 主机组 | 主机分组管理，支持主机组权限批量授权 | ✅ |
| | 👤 系统用户 | 系统用户与权限规则的关联，支持多对多关系 | ✅ |
| | ⏰ 时间限制 | 权限规则支持时间范围限制（有效起止时间） | ✅ |
| | 🎯 优先级控制 | 权限规则支持优先级设置，高优先级规则优先匹配 | ✅ |
| | 📍 细粒度权限 | 支持主机组、指定主机、系统用户的多维度权限组合 | ✅ |
| **📈 监控告警** | 📊 Prometheus 监控 | Prometheus 数据源集成，支持监控指标查询 | ✅ |
| | 📋 告警规则 | 告警规则管理，支持 PromQL 表达式 | ✅ |
| | 🎯 告警策略 | 告警策略配置，支持告警聚合、抑制、静默 | ✅ |
| | 📢 告警通知 | 多渠道告警通知（飞书/钉钉/邮件/Webhook） | ✅ |
| | 📝 告警模板 | 自定义告警消息模板，支持变量替换 | ✅ |
| | 📊 告警事件 | 告警事件管理，支持告警确认、处理、恢复 | ✅ |
| | 🔔 证书监控 | SSL 证书过期监控和告警 | ✅ |
| | 👨‍💼 值班管理 | OnCall 排班管理，支持值班日历和通知 | ✅ |
| **💾 数据库管理** | 🗄️ 多数据库支持 | MySQL、PostgreSQL、MongoDB、Redis 统一管理 | ✅ |
| | 🔍 查询功能 | SQL 查询、MongoDB 查询、Redis 命令执行 | ✅ |
| | 📝 查询日志 | 完整的查询审计日志，记录用户、时间、IP | ✅ |
| | 🔐 细粒度权限 | 基于 Casbin 的权限控制（实例→数据库→表→权限类型） | ✅ |
| **🔧 基础设施** | 🌐 高可用 | 支持多实例部署，Redis 分布式锁，配置同步 | ✅ |

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

**修改环境变量**，在 `.env` 文件中设置：

```bash
docker-compose -f docker-compose-pg.yaml up -d

DB_DRIVER=postgres
DB_HOST=postgres
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=postgres
DB_NAME=keyops
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
```

---

<a name="english"></a>

# KeyOps - Infrastructure Management Platform

**Enterprise-grade DevOps platform built with Go**

## Core Features

### Feature Overview

| Category | Feature | Description | Status |
|---------|---------|-------------|--------|
| **🛡️ Bastion Host** | 🔐 SSH Gateway | Standard SSH protocol direct connection, supports traditional SSH clients | ✅ |
| | 🌐 Web Terminal | WebSocket real-time terminal, no client installation required, supports multi-session management | ✅ |
| | 🖥️ RDP Graphical | Windows remote desktop connection with GUI support | ✅ |
| | 🎥 Session Recording | Complete session recording and playback, supports Asciinema format | ✅ |
| | 📝 Command History | Complete command execution history and query | ✅ |
| | 📁 File Transfer | File upload/download management, supports SFTP protocol | ✅ |
| | 🚨 Command Interception | Real-time detection of dangerous commands, supports command blacklist, Feishu/DingTalk alerts | ✅ |
| | 👤 System User Management | Unified management of system users (jump users) and key distribution | ✅ |
| | 🔑 Two-Factor Authentication | Multiple authentication methods: Password / SSH key | ✅ |
| **☸️ K8s Multi-Cluster** | 🌐 Cluster Management | Unified multi-cluster management, supports Token/Kubeconfig authentication | ✅ |
| | 🔐 Cluster Permissions | User/role-based cluster access control, supports namespace isolation | ✅ |
| | 📦 Workloads | Management of Deployment, DaemonSet, StatefulSet, Pod, CronJob | ✅ |
| | ⚙️ Config Management | Unified management and editing of ConfigMap and Secret | ✅ |
| | 🌐 Service Management | Creation and management of Service and Ingress | ✅ |
| | 💾 Storage Management | Configuration and management of PV, PVC, StorageClass | ✅ |
| | 📊 Cluster Monitoring | Cluster status overview, resource usage monitoring, event viewing | ✅ |
| | 📋 Operation Audit | Complete audit logs for K8s operations | ✅ |
| **📋 Ticket Management** | 📝 Ticket Creation | Supports daily tickets, deployment tickets, and other types | ✅ |
| | 📑 Form Templates | Visual form designer, supports custom form templates | ✅ |
| | 🔄 Approval Workflow | Supports Feishu/DingTalk/WeChat Work/internal approval, multi-level approval process (WeChat Work callback pending) | ✅ |
| | ✅ Auto Authorization | Automatic authorization after approval, supports automatic application of permission rules | ✅ |
| | 📊 Ticket Statistics | Ticket status tracking, approval history, statistical analysis | ✅ |
| **🏢 Organization & Apps** | 👥 Department Management | Multi-level department structure management, supports department tree organization | ✅ |
| | 📱 Application Management | Application information management, associated with departments and personnel | ✅ |
| | 👤 Personnel Management | User information management, supports department association and role assignment | ✅ |
| | 🔧 Service Management | Service catalog management, supports service classification and detail configuration | ✅ |
| **🔐 Polymorphic Permissions** | 👥 User Groups (Roles) | Role-based permission management, supports role member management | ✅ |
| | 🖥️ Host Groups | Host grouping management, supports batch authorization of host group permissions | ✅ |
| | 👤 System Users | Association of system users with permission rules, supports many-to-many relationships | ✅ |
| | ⏰ Time Restrictions | Permission rules support time range restrictions (valid from/to) | ✅ |
| | 🎯 Priority Control | Permission rules support priority settings, high-priority rules matched first | ✅ |
| | 📍 Fine-grained Permissions | Supports multi-dimensional permission combinations: host groups, specific hosts, system users | ✅ |
| **📈 Monitoring & Alerts** | 📊 Prometheus Monitoring | Prometheus datasource integration, supports monitoring metric queries | ✅ |
| | 📋 Alert Rules | Alert rule management, supports PromQL expressions | ✅ |
| | 🎯 Alert Policies | Alert policy configuration, supports alert aggregation, suppression, silence | ✅ |
| | 📢 Alert Notifications | Multi-channel alert notifications (Feishu/DingTalk/Email/Webhook) | ✅ |
| | 📝 Alert Templates | Custom alert message templates, supports variable substitution | ✅ |
| | 📊 Alert Events | Alert event management, supports alert acknowledgment, handling, recovery | ✅ |
| | 🔔 Certificate Monitoring | SSL certificate expiration monitoring and alerts | ✅ |
| | 👨‍💼 OnCall Management | OnCall shift management, supports duty calendar and notifications | ✅ |
| **💾 Database Management** | 🗄️ Multi-DB Support | Unified management of MySQL, PostgreSQL, MongoDB, Redis | ✅ |
| | 🔍 Query Function | SQL queries, MongoDB queries, Redis command execution | ✅ |
| | 📝 Query Logs | Complete query audit logs, records user, time, IP | ✅ |
| | 🔐 Fine-grained Permissions | Casbin-based permission control (instance → database → table → permission type) | ✅ |
| **🔧 Infrastructure** | 🌐 High Availability | Multi-instance deployment, Redis distributed locks, configuration synchronization | ✅ |

## Quick Deployment

### Requirements

- Docker 20.10+
- Docker Compose 2.0+

### MySQL Deployment (Recommended)

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

**Access System**: http://localhost:8080  
**Default Account**: `admin` / `admin123`

### PostgreSQL Deployment

**Modify environment variables** in `.env` file:

```bash
docker-compose -f docker-compose-pg.yaml up -d

DB_DRIVER=postgres
DB_HOST=postgres
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=postgres
DB_NAME=keyops
```

## Port Description

- `8080`: HTTP (Web + API)
- `2222`: SSH Gateway
- `3306`: MySQL (optional)
- `5432`: PostgreSQL (optional)
- `6379`: Redis (optional)
- `4822`: Guacamole daemon (RDP)

## Environment Variables Configuration

Create `.env` file (optional):

```bash
# Database configuration
MYSQL_ROOT_PASSWORD=123456
MYSQL_DATABASE=keyops
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres
POSTGRES_DB=keyops

# Redis configuration
REDIS_ENABLED=true
REDIS_PASSWORD=
```

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
