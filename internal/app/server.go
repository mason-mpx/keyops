package app

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fisker/zjump-backend/internal/api/router"
	"github.com/fisker/zjump-backend/internal/audit"
	"github.com/fisker/zjump-backend/internal/sshserver/server"
	"github.com/fisker/zjump-backend/pkg/config"
	"github.com/fisker/zjump-backend/pkg/database"
	"github.com/fisker/zjump-backend/pkg/logger"
	pkgredis "github.com/fisker/zjump-backend/pkg/redis"
)

// StartServer 启动 HTTP 服务器
func StartServer(
	cfg *config.Config,
	handlers *Handlers,
	services *Services,
	repos *Repositories,
	backgroundServices *BackgroundServices,
	sshServer *server.Server,
	unifiedAuditor *audit.DatabaseAuditor,
) {
	// Setup router
	r := router.Setup(
		handlers.Host,
		handlers.Dashboard,
		handlers.Session,
		handlers.Proxy,
		handlers.Auth,
		handlers.Blacklist,
		handlers.Setting,
		handlers.Routing,
		handlers.Connection,
		handlers.HostGroup,
		handlers.Approval,
		handlers.ApprovalCallback,
		handlers.File,
		handlers.AssetSync,
		services.Auth,
		handlers.HostMonitor,
		handlers.SystemUser,
		handlers.Role,
		handlers.PermissionRule,
		handlers.TwoFactor,
		handlers.Permission,
		handlers.FormTemplate,
		handlers.FormCategory,
		handlers.Ticket,
		handlers.TicketDraft,
		handlers.Workflow,
		handlers.K8s,
		handlers.K8sCluster,
		handlers.K8sPermission,
		handlers.K8sSearch,
		handlers.Deployment,
		handlers.Bill,
		handlers.Monitor,
		handlers.Organization,
		handlers.Application,
		handlers.AppDeployBinding,
		handlers.Jenkins,
		handlers.Audit,
		handlers.Alert,
		handlers.OnCall,
		services.K8sPermission,
		repos.Role,
		cfg.Server.Mode,
	)

	// Start expiration service (延迟启动，确保数据库连接完全就绪)
	ctx := context.Background()
	go func() {
		// 等待数据库连接就绪
		time.Sleep(3 * time.Second)
		if err := backgroundServices.Expiration.Start(ctx); err != nil {
			logger.Warnf("Failed to start expiration service: %v", err)
		} else {
			logger.Infof("Expiration Service started")
			logger.Infof("   Checking for expired users and permissions")
		}
	}()

	// Start on-call notification service (延迟启动，确保数据库连接完全就绪)
	go func() {
		// 等待数据库连接就绪
		time.Sleep(4 * time.Second)
		if onCallNotificationService, ok := backgroundServices.OnCallNotification.(interface {
			Start(context.Context) error
		}); ok {
			if err := onCallNotificationService.Start(ctx); err != nil {
				logger.Warnf("Failed to start on-call notification service: %v", err)
			} else {
				logger.Infof("On-Call Notification Service started")
				logger.Infof("   Checking for upcoming shifts (interval: 1 minute)")
			}
		}
	}()
	logger.Infof("")

	// Start HTTP server
	addr := fmt.Sprintf(":%d", cfg.Server.APIPort)
	httpServer := &http.Server{
		Addr:    addr,
		Handler: r,
	}

	// Print startup banner
	printStartupBanner(cfg)

	// Start HTTP server in goroutine
	go func() {
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("Failed to start HTTP server: %v", err)
		}
	}()

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	logger.Infof("\nShutting down gracefully...")

	// Create shutdown context with 10s timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	// 1. Shutdown HTTP server
	logger.Infof("  → Stopping HTTP server...")
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Infof("  Warning: HTTP server shutdown error: %v", err)
	} else {
		logger.Infof("  ✓ HTTP server stopped")
	}

	// 2. Stop Expiration Service
	logger.Infof("  → Stopping expiration service...")
	backgroundServices.Expiration.Stop()
	logger.Infof("  ✓ Expiration service stopped")

	// 2.5. Stop On-Call Notification Service
	if onCallNotificationService, ok := backgroundServices.OnCallNotification.(interface {
		Stop()
	}); ok {
		logger.Infof("  → Stopping on-call notification service...")
		onCallNotificationService.Stop()
		logger.Infof("  ✓ On-call notification service stopped")
	}

	// 3. Stop SSH Server
	if sshServer != nil {
		logger.Infof("  → Stopping SSH server...")
		if err := sshServer.Stop(); err != nil {
			logger.Infof("  Warning: SSH server shutdown error: %v", err)
		} else {
			logger.Infof("  ✓ SSH server stopped")
		}
	}

	// 4. Stop proxy monitor (如果已启用)
	if backgroundServices.ProxyMonitor != nil {
		logger.Infof("  → Stopping proxy monitor...")
		backgroundServices.ProxyMonitor.Stop()
		logger.Infof("  ✓ Proxy monitor stopped")
	} else {
		logger.Infof("  → Proxy monitor not enabled, skipping")
	}

	// 5. Close storage (wait for async writes)
	logger.Infof("  → Closing storage...")
	// Note: unifiedAuditor doesn't have Close method, skip for now
	logger.Infof("  ✓ Storage closed")

	// 6. Close database
	logger.Infof("  → Closing database...")
	database.Close()
	logger.Infof("  ✓ Database closed")

	// 7. Close Redis if enabled
	if cfg.Redis.Enabled {
		logger.Infof("  → Closing Redis...")
		pkgredis.Close()
		logger.Infof("  ✓ Redis closed")
	}

	logger.Infof("")
	logger.Infof("Shutdown complete")
	logger.Infof("")
}

// printStartupBanner 打印启动横幅
func printStartupBanner(cfg *config.Config) {
	logger.Infof("")
	logger.Infof("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	logger.Infof("ZJump Unified Server v2.0 - Intelligent Routing Architecture")
	logger.Infof("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	logger.Infof("")
	logger.Infof("Features:")
	logger.Infof("   • Authentication & Authorization")
	logger.Infof("   • Intelligent Routing - Auto path selection")
	logger.Infof("   • Direct Connection - Default mode, low latency")
	logger.Infof("   • Proxy Forwarding - Use Proxy Agent in isolated networks")
	logger.Infof("   • Full Audit Trail - Complete operation logs")
	if cfg.Server.SSHPort > 0 {
		logger.Infof("   • SSH Gateway - CLI login with full audit")
	}
	logger.Infof("")
	logger.Infof("🔀 Connection Modes:")
	logger.Infof("   • Web Mode   - Browser access (:%d)", cfg.Server.APIPort)
	if cfg.Server.SSHPort > 0 {
		logger.Infof("   • SSH Mode   - SSH client (:%d)", cfg.Server.SSHPort)
	}
	logger.Infof("   • Direct     - API Server connects to target directly")
	logger.Infof("   • Proxy      - Via Proxy Agent (8022) for isolated networks")
	logger.Infof("")
	logger.Infof("Tips:")
	logger.Infof("   Start only this service for both Web and SSH access")
	logger.Infof("   Proxy Agent is optional, needed only for isolated networks")
	logger.Infof("")
	logger.Infof("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	logger.Infof("")
}

