package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fisker/zjump-backend/internal/bastion/client"
	"github.com/fisker/zjump-backend/internal/bastion/registry"
	"github.com/fisker/zjump-backend/internal/bastion/websocket"
	"github.com/fisker/zjump-backend/pkg/config"
	"github.com/fisker/zjump-backend/pkg/logger"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func main() {
	// 加载配置
	cfg, err := config.Load("config/config.yaml")
	if err != nil {
		fmt.Printf("Warning: Failed to load config: %v, using defaults\n", err)
		cfg = getDefaultConfig()
	}

	// 初始化日志
	if err := logger.Init(&cfg.Logging); err != nil {
		fmt.Printf("Failed to init logger: %v\n", err)
		return
	}

	logger.Infof("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	logger.Infof("Starting ZJump Proxy Agent...")
	logger.Infof("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	// 生成或使用配置的 Proxy ID
	proxyID := cfg.Server.ProxyID
	if proxyID == "" {
		proxyID = uuid.New().String()
	}
	logger.Infof("Proxy ID: %s", proxyID)

	// 初始化 WebSocket 会话管理器
	sessionManager := websocket.NewSessionManager()

	// 初始化注册器（用于向 API Server 注册和心跳）
	registryObj := registry.NewRegistry(registry.Config{
		BackendURL:        cfg.Server.BackendURL,
		ProxyID:           proxyID,
		Port:              cfg.Server.LinuxProxyPort,
		HeartbeatInterval: 30 * time.Second,
		Version:           "1.0.0",
	})

	// 启动注册器（自动注册和心跳）
	logger.Infof("📡 Starting registry with API Server: %s", cfg.Server.BackendURL)
	if err := registryObj.Start(); err != nil {
		logger.Warnf("Failed to start registry: %v", err)
	} else {
		logger.Infof("Successfully started registry")
	}

	// 初始化 API 客户端（用于上报数据）
	_ = client.NewApiClient(client.Config{
		BaseURL: cfg.Server.BackendURL,
		Timeout: 10 * time.Second,
		ProxyID: proxyID,
	})

	// 设置 Gin 模式
	if cfg.Server.Mode == "release" {
		gin.SetMode(gin.ReleaseMode)
	}

	// 创建路由
	r := gin.Default()

	// 健康检查端点
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":    "healthy",
			"proxy_id":  proxyID,
			"version":   "1.0.0",
			"timestamp": time.Now().Unix(),
			"sessions":  sessionManager.GetActiveSessionCount(),
		})
	})

	// WebSocket 连接端点（用于接收来自 API Server 的连接请求）
	// 这个端点由 connection_handler.go 中的 handleProxyConnection 调用
	r.GET("/ws/connect", func(c *gin.Context) {
		// TODO: 实现 proxy connection handler
		c.JSON(http.StatusNotImplemented, gin.H{
			"error": "Proxy connection not implemented yet",
		})
	})

	// 启动 HTTP 服务器
	addr := fmt.Sprintf(":%d", cfg.Server.LinuxProxyPort)
	srv := &http.Server{
		Addr:    addr,
		Handler: r,
	}

	// 启动服务器
	go func() {
		logger.Infof("")
		logger.Infof("Proxy Agent Started Successfully")
		logger.Infof("   Listen Address:  %s", addr)
		logger.Infof("   Proxy ID:        %s", proxyID)
		logger.Infof("   API Server:      %s", cfg.Server.BackendURL)
		logger.Infof("")
		logger.Infof("Proxy Agent is ready to accept connections")
		logger.Infof("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		logger.Infof("")

		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("Failed to start server: %v", err)
		}
	}()

	// 优雅关闭
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Infof("")
	logger.Infof("Shutting down Proxy Agent...")

	// 注销
	registryObj.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Errorf("Server forced to shutdown: %v", err)
	}

	logger.Infof("Proxy Agent stopped gracefully")
}

// getDefaultConfig 返回默认配置
func getDefaultConfig() *config.Config {
	return &config.Config{
		Server: config.ServerConfig{
			LinuxProxyPort: 9090,
			BackendURL:     "http://localhost:8080",
			Mode:           "debug",
		},
		Logging: config.LoggingConfig{
			Level:      "info",
			Output:     "console",
			File:       "logs/proxy-agent.log",
			MaxSize:    100,
			MaxBackups: 3,
			MaxAge:     7,
			Compress:   true,
		},
	}
}
