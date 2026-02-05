package app

import (
	"os"
	"time"

	oncallNotification "github.com/fisker/zjump-backend/internal/alert/oncall"
	alertnotification "github.com/fisker/zjump-backend/internal/alert/notification"
	"github.com/fisker/zjump-backend/internal/notification"
	"github.com/fisker/zjump-backend/internal/service"
	bastionService "github.com/fisker/zjump-backend/internal/service/bastion"
	certificateService "github.com/fisker/zjump-backend/internal/service/certificate"
	"github.com/fisker/zjump-backend/internal/service/dms"
	"github.com/fisker/zjump-backend/pkg/config"
	"github.com/fisker/zjump-backend/pkg/crypto"
	"github.com/fisker/zjump-backend/pkg/database"
	"github.com/fisker/zjump-backend/pkg/logger"
)

// Services 包含所有 Service 实例
type Services struct {
	Host          *service.HostService
	Session       *service.SessionService
	Auth          *service.AuthService
	AssetSync     *service.AssetSyncService
	K8s           *service.K8sService
	K8sCluster    *service.K8sClusterService
	K8sPermission *service.K8sPermissionService
	Deployment    *service.DeploymentService
	Bill          *service.BillService
	Monitor       *service.MonitorService
	Jenkins       *service.JenkinsService
	Alert         *service.AlertService
	OnCall        *service.OnCallService
	DMSInstance   *dms.InstanceService
	DMSQuery      *dms.QueryService
	DMSPermission *dms.PermissionService
}

// InitializeServices 初始化所有 Service
func InitializeServices(repos *Repositories, cfg *config.Config) *Services {
	hostService := service.NewHostService(repos.Host)
	sessionService := service.NewSessionService(repos.Session, repos.Host)
	authService := service.NewAuthService(repos.User, repos.Setting, cfg.Security.JWTSecret)

	assetSyncService := service.NewAssetSyncService(repos.AssetSync, repos.Host)

	k8sClusterService := service.NewK8sClusterService(repos.K8sCluster)
	k8sService := service.NewK8sService(repos.K8sCluster)
	k8sPermissionService := service.NewK8sPermissionService()
	kubedogService := service.NewKubeDogService(cfg)
	deploymentService := service.NewDeploymentService(repos.Deployment, kubedogService, k8sService, cfg)
	billService := service.NewBillService(repos.Bill)
	monitorService := service.NewMonitorService(repos.Monitor)
	cryptoService := crypto.NewCrypto(cfg.Security.JWTSecret)
	jenkinsService := service.NewJenkinsService(repos.Jenkins, repos.Deployment, cryptoService)
	// 规则文件目录，可以从配置或环境变量读取，默认使用 /etc/prometheus/rules
	ruleDir := os.Getenv("ALERT_RULE_DIR")
	if ruleDir == "" {
		ruleDir = "/etc/prometheus/rules" // 默认规则目录
	}
	alertService := service.NewAlertService(
		repos.AlertRuleGroup,
		repos.AlertRuleSource,
		repos.AlertRule,
		repos.AlertEvent,
		repos.AlertLog,
		repos.AlertStrategy,
		repos.AlertLevel,
		repos.AlertAggregation,
		repos.AlertSilence,
		repos.AlertRestrain,
		repos.AlertTemplate,
		repos.AlertChannel,
		repos.ChannelTemplate,
		repos.AlertGroup,
		repos.StrategyLog,
		ruleDir,
	)

	// 启动数据源同步调度器
	if err := alertService.StartSyncScheduler(); err != nil {
		logger.Warnf("Failed to start datasource sync scheduler: %v", err)
	} else {
		logger.Infof("Datasource sync scheduler started")
	}
	onCallSvc := service.NewOnCallService(
		repos.OnCallSchedule,
		repos.OnCallShift,
		repos.OnCallAssignment,
	)

	// DMS 服务
	dmsPermissionService := dms.NewPermissionService(repos.DBPermission, repos.DBInstance)
	dmsInstanceService := dms.NewInstanceService(repos.DBInstance, cryptoService)
	dmsQueryService := dms.NewQueryService(repos.DBInstance, repos.QueryLog, dmsPermissionService, cryptoService)

	return &Services{
		Host:          hostService,
		Session:       sessionService,
		Auth:          authService,
		AssetSync:     assetSyncService,
		K8s:           k8sService,
		K8sCluster:    k8sClusterService,
		K8sPermission: k8sPermissionService,
		Deployment:    deploymentService,
		Bill:          billService,
		Monitor:       monitorService,
		Jenkins:       jenkinsService,
		Alert:         alertService,
		OnCall:        onCallSvc,
		DMSInstance:   dmsInstanceService,
		DMSQuery:      dmsQueryService,
		DMSPermission: dmsPermissionService,
	}
}

// BackgroundServices 后台服务
type BackgroundServices struct {
	HostMonitor        *service.HostMonitorService
	ProxyMonitor       *service.ProxyMonitor
	Expiration         *service.ExpirationService
	OnCallNotification interface{} // OnCallNotificationService (使用interface避免循环依赖)
	CertificateAlert   *certificateService.CertificateAlertService
}

// InitializeBackgroundServices 初始化后台服务
func InitializeBackgroundServices(repos *Repositories, cfg *config.Config, notificationMgr *notification.NotificationManager, alertService *service.AlertService) *BackgroundServices {
	// Host monitor (check every 5 minutes)
	hostMonitor := service.NewHostMonitorService(repos.Host, repos.Setting, 5)
	hostMonitor.Start()

	// Proxy monitor (仅在启用Proxy时启动)
	var proxyMonitor *service.ProxyMonitor
	if cfg.Proxy.Enabled {
		proxyMonitor = service.NewProxyMonitor(database.DB, service.MonitorConfig{
			CheckInterval:    1 * time.Minute,
			HeartbeatTimeout: 2 * time.Minute,
		})
		go proxyMonitor.Start()
	}

	// Expiration service
	expirationService := service.NewExpirationService(database.DB, notificationMgr)

	// On-call notification service
	onCallNotificationService := oncallNotification.NewOnCallNotificationService(
		database.DB,
		repos.OnCallShift,
		repos.OnCallSchedule,
	)

	// Certificate alert service
	// 创建 AlertNotifier（与 AlertService 使用相同的配置）
	frontendURL := os.Getenv("FRONTEND_URL")
	if frontendURL == "" {
		frontendURL = ""
	}
	alertNotifier := alertnotification.NewAlertNotifier(
		repos.StrategyLog,
		repos.AlertTemplate,
		repos.AlertChannel,
		repos.ChannelTemplate,
		repos.AlertGroup,
		repos.AlertRuleSource,
		frontendURL,
	)
	certificateAlertService := certificateService.NewCertificateAlertService(
		repos.DomainCertificate,
		repos.AlertTemplate,
		repos.AlertChannel,
		alertNotifier,
		database.DB,
	)

	// 启动证书告警定时任务（每天检查一次）
	go func() {
		// 等待数据库连接就绪
		time.Sleep(5 * time.Second)
		
		// 立即执行一次检查
		if err := certificateAlertService.CheckAndSendAlerts(); err != nil {
			logger.Errorf("Failed to check certificate alerts: %v", err)
		}
		
		// 设置定时任务：每天凌晨2点执行
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		
		for range ticker.C {
			// 每天执行一次检查
			if err := certificateAlertService.CheckAndSendAlerts(); err != nil {
				logger.Errorf("Failed to check certificate alerts: %v", err)
			}
		}
	}()
	logger.Infof("Certificate alert service started, will check daily at 2:00 AM")

	// Recording converter service (convert .guac to MP4)
	recordingConverter := bastionService.GetRecordingConverter()
	recordingBasePath := os.Getenv("RECORDING_CONTAINER_PATH")
	if recordingBasePath == "" {
		recordingBasePath = "/replay" // 默认路径
	}
	// 启动后台转换服务，每5分钟扫描一次
	go recordingConverter.StartBackgroundConverter(recordingBasePath, 5*time.Minute)
	logger.Infof("Recording converter service started, scanning: %s, interval: 5 minutes", recordingBasePath)

	return &BackgroundServices{
		HostMonitor:        hostMonitor,
		ProxyMonitor:       proxyMonitor,
		Expiration:         expirationService,
		OnCallNotification: onCallNotificationService,
		CertificateAlert:   certificateAlertService,
	}
}
