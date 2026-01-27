package system

import (
	"context"
	"fmt"
	"time"

	"github.com/fisker/zjump-backend/internal/model"
	"github.com/fisker/zjump-backend/internal/notification"
	"github.com/fisker/zjump-backend/pkg/database"
	"github.com/fisker/zjump-backend/pkg/logger"

	"gorm.io/gorm"
)

// ExpirationService 过期检测服务
type ExpirationService struct {
	db                  *gorm.DB
	stopChan            chan struct{}
	isRunning           bool
	checkInterval       time.Duration
	notificationManager *notification.NotificationManager
}

// NewExpirationService 创建过期检测服务
func NewExpirationService(db *gorm.DB, notificationManager *notification.NotificationManager) *ExpirationService {
	return &ExpirationService{
		db:                  db,
		stopChan:            make(chan struct{}),
		checkInterval:       time.Hour, // 默认每小时检查一次
		notificationManager: notificationManager,
	}
}

// Start 启动过期检测服务
func (s *ExpirationService) Start(ctx context.Context) error {
	if s.isRunning {
		return fmt.Errorf("expiration service is already running")
	}

	// 等待数据库连接就绪
	if err := s.waitForDatabase(); err != nil {
		return fmt.Errorf("failed to wait for database: %w", err)
	}

	// 从设置读取检查间隔
	var setting model.Setting
	// 根据数据库类型使用正确的引号
	keyColumn := "`key`"
	if s.db.Dialector.Name() == "postgres" {
		keyColumn = "\"key\""
	}
	if err := s.db.Where(keyColumn+" = ?", "expiration_check_interval").First(&setting).Error; err == nil {
		if interval, err := time.ParseDuration(setting.Value + "s"); err == nil {
			s.checkInterval = interval
		}
	}

	s.isRunning = true
	logger.Infof("Expiration service started, check interval: %v", s.checkInterval)

	// 启动定时检查
	go s.runPeriodicCheck(ctx)

	return nil
}

// waitForDatabase 等待数据库连接就绪
func (s *ExpirationService) waitForDatabase() error {
	maxRetries := 30                 // 增加到30次重试
	retryInterval := 1 * time.Second // 增加到1秒间隔

	for i := 0; i < maxRetries; i++ {
		// 优先使用全局 database.DB，如果本地 db 为 nil
		db := s.db
		if db == nil {
			db = database.DB
		}

		// 检查 db 是否为 nil
		if db == nil {
			logger.Debugf("Database connection is nil, retrying... (%d/%d)", i+1, maxRetries)
			time.Sleep(retryInterval)
			continue
		}

		sqlDB, err := db.DB()
		if err != nil {
			logger.Debugf("Failed to get database instance: %v, retrying... (%d/%d)", err, i+1, maxRetries)
			time.Sleep(retryInterval)
			continue
		}

		// 尝试 ping 数据库
		if err := sqlDB.Ping(); err == nil {
			// 如果本地 db 为 nil，更新它
			if s.db == nil {
				s.db = db
			}
			logger.Debugf("Database connection is ready")
			return nil
		}

		logger.Debugf("Database ping failed: %v, retrying... (%d/%d)", err, i+1, maxRetries)
		time.Sleep(retryInterval)
	}

	return fmt.Errorf("database connection not ready after %d retries (%v total wait time)", maxRetries, time.Duration(maxRetries)*retryInterval)
}

// Stop 停止过期检测服务
func (s *ExpirationService) Stop() {
	if !s.isRunning {
		return
	}

	close(s.stopChan)
	s.isRunning = false
	logger.Infof("Expiration service stopped")
}

// runPeriodicCheck 运行定期检查
func (s *ExpirationService) runPeriodicCheck(ctx context.Context) {
	ticker := time.NewTicker(s.checkInterval)
	defer ticker.Stop()

	// 延迟执行首次检查，确保数据库连接完全就绪
	time.Sleep(2 * time.Second)
	s.performCheck(ctx)

	for {
		select {
		case <-ticker.C:
			s.performCheck(ctx)
		case <-s.stopChan:
			return
		case <-ctx.Done():
			return
		}
	}
}

// performCheck 执行检查
func (s *ExpirationService) performCheck(ctx context.Context) {
	logger.Infof("Starting expiration check...")

	// 检查用户过期
	if err := s.checkUserExpiration(ctx); err != nil {
		logger.Errorf("Failed to check user expiration: %v", err)
	}

	// 检查授权规则过期
	if err := s.checkPermissionExpiration(ctx); err != nil {
		logger.Errorf("Failed to check permission expiration: %v", err)
	}

	logger.Infof("Expiration check completed")
}

// checkUserExpiration 检查用户过期
func (s *ExpirationService) checkUserExpiration(ctx context.Context) error {
	now := time.Now()

	// 获取通知配置
	var config model.ExpirationNotificationConfig
	if err := s.db.Where("type = ?", "user").First(&config).Error; err != nil {
		logger.Warnf("User expiration config not found, using default: %v", err)
		config.WarningDays = 7
		config.Enabled = true
	}

	if !config.Enabled {
		logger.Debugf("User expiration check is disabled")
		return nil
	}

	// 1. 查找需要发送警告的用户（即将过期但还未发送过警告）
	warningTime := now.AddDate(0, 0, config.WarningDays)
	var usersToWarn []model.User
	err := s.db.Where("expires_at IS NOT NULL").
		Where("expires_at <= ?", warningTime).
		Where("expires_at > ?", now).
		Where("expiration_warning_sent = ?", false).
		Where("status = ?", "active").
		Find(&usersToWarn).Error

	if err != nil {
		return fmt.Errorf("failed to query users to warn: %w", err)
	}

	logger.Infof("Found %d users to warn about expiration", len(usersToWarn))

	// 发送警告通知
	for _, user := range usersToWarn {
		if err := s.sendUserExpirationWarning(ctx, &user, config); err != nil {
			logger.Errorf("Failed to send warning to user %s: %v", user.Username, err)
			continue
		}

		// 标记已发送警告
		s.db.Model(&user).Update("expiration_warning_sent", true)

		// 记录日志
		log := model.UserExpirationLog{
			UserID:    user.ID,
			Username:  user.Username,
			Action:    "warning_sent",
			ExpiresAt: user.ExpiresAt,
			Reason:    fmt.Sprintf("Account will expire in %d days", config.WarningDays),
		}
		s.db.Create(&log)
	}

	// 2. 查找已过期的用户
	var expiredUsers []model.User
	err = s.db.Where("expires_at IS NOT NULL").
		Where("expires_at <= ?", now).
		Where("status = ?", "active").
		Find(&expiredUsers).Error

	if err != nil {
		return fmt.Errorf("failed to query expired users: %w", err)
	}

	logger.Infof("Found %d expired users", len(expiredUsers))

	// 检查是否自动禁用过期用户
	var autoDisableSetting model.Setting
	autoDisable := true
	// 根据数据库类型使用正确的引号
	keyColumn := "`key`"
	if s.db.Dialector.Name() == "postgres" {
		keyColumn = "\"key\""
	}
	if err := s.db.Where(keyColumn+" = ?", "user_expiration_auto_disable").First(&autoDisableSetting).Error; err == nil {
		autoDisable = autoDisableSetting.Value == "true"
	}

	// 处理过期用户
	for _, user := range expiredUsers {
		if autoDisable && user.AutoDisableOnExpiry {
			// 自动禁用账号
			s.db.Model(&user).Update("status", "inactive")

			// 发送过期通知
			s.sendUserExpiredNotification(ctx, &user, config)

			// 记录日志
			log := model.UserExpirationLog{
				UserID:    user.ID,
				Username:  user.Username,
				Action:    "disabled",
				ExpiresAt: user.ExpiresAt,
				Reason:    "Account expired and auto-disabled",
			}
			s.db.Create(&log)

			logger.Infof("User %s has been disabled due to expiration", user.Username)
		} else {
			// 仅发送通知，不自动禁用
			s.sendUserExpiredNotification(ctx, &user, config)

			// 记录日志
			log := model.UserExpirationLog{
				UserID:    user.ID,
				Username:  user.Username,
				Action:    "expired",
				ExpiresAt: user.ExpiresAt,
				Reason:    "Account expired (not auto-disabled)",
			}
			s.db.Create(&log)

			logger.Infof("User %s has expired (not auto-disabled)", user.Username)
		}
	}

	return nil
}

// checkPermissionExpiration 检查授权规则过期
func (s *ExpirationService) checkPermissionExpiration(ctx context.Context) error {
	now := time.Now()

	// 获取通知配置
	var config model.ExpirationNotificationConfig
	if err := s.db.Where("type = ?", "permission").First(&config).Error; err != nil {
		logger.Warnf("Permission expiration config not found, using default: %v", err)
		config.WarningDays = 3
		config.Enabled = true
	}

	if !config.Enabled {
		logger.Debugf("Permission expiration check is disabled")
		return nil
	}

	// 1. 查找即将过期的授权规则
	warningTime := now.AddDate(0, 0, config.WarningDays)
	var rulesToWarn []model.PermissionRule
	err := s.db.Where("valid_to IS NOT NULL").
		Where("valid_to <= ?", warningTime).
		Where("valid_to > ?", now).
		Where("enabled = ?", true).
		Find(&rulesToWarn).Error

	if err != nil {
		return fmt.Errorf("failed to query rules to warn: %w", err)
	}

	logger.Infof("Found %d permission rules to warn about expiration", len(rulesToWarn))

	// 发送警告（这里简化处理，实际可能需要更复杂的逻辑）
	for _, rule := range rulesToWarn {
		// 获取角色信息
		var role model.Role
		s.db.Where("id = ?", rule.RoleID).First(&role)

		// 记录日志
		log := model.PermissionExpirationLog{
			RuleID:   rule.ID,
			RuleName: rule.Name,
			RoleID:   rule.RoleID,
			RoleName: role.Name,
			Action:   "warning_sent",
			ValidTo:  rule.ValidTo,
			Reason:   fmt.Sprintf("Permission will expire in %d days", config.WarningDays),
		}
		s.db.Create(&log)

		// 发送通知给管理员
		s.sendPermissionExpirationWarning(ctx, &rule, &role, config)
	}

	// 2. 查找已过期的授权规则
	var expiredRules []model.PermissionRule
	err = s.db.Where("valid_to IS NOT NULL").
		Where("valid_to <= ?", now).
		Where("enabled = ?", true).
		Find(&expiredRules).Error

	if err != nil {
		return fmt.Errorf("failed to query expired rules: %w", err)
	}

	logger.Infof("Found %d expired permission rules", len(expiredRules))

	// 检查是否自动禁用过期规则
	var autoDisableSetting model.Setting
	autoDisable := true
	// 根据数据库类型使用正确的引号
	keyColumn := "`key`"
	if s.db.Dialector.Name() == "postgres" {
		keyColumn = "\"key\""
	}
	if err := s.db.Where(keyColumn+" = ?", "permission_expiration_auto_disable").First(&autoDisableSetting).Error; err == nil {
		autoDisable = autoDisableSetting.Value == "true"
	}

	// 处理过期规则
	for _, rule := range expiredRules {
		// 获取角色信息
		var role model.Role
		s.db.Where("id = ?", rule.RoleID).First(&role)

		if autoDisable {
			// 自动禁用规则
			s.db.Model(&rule).Update("enabled", false)

			// 记录日志
			log := model.PermissionExpirationLog{
				RuleID:   rule.ID,
				RuleName: rule.Name,
				RoleID:   rule.RoleID,
				RoleName: role.Name,
				Action:   "disabled",
				ValidTo:  rule.ValidTo,
				Reason:   "Permission expired and auto-disabled",
			}
			s.db.Create(&log)

			logger.Infof("Permission rule %s has been disabled due to expiration", rule.Name)
		} else {
			// 仅记录，不自动禁用
			log := model.PermissionExpirationLog{
				RuleID:   rule.ID,
				RuleName: rule.Name,
				RoleID:   rule.RoleID,
				RoleName: role.Name,
				Action:   "expired",
				ValidTo:  rule.ValidTo,
				Reason:   "Permission expired (not auto-disabled)",
			}
			s.db.Create(&log)

			logger.Infof("Permission rule %s has expired (not auto-disabled)", rule.Name)
		}

		// 发送过期通知
		s.sendPermissionExpiredNotification(ctx, &rule, &role, config)
	}

	return nil
}

// sendUserExpirationWarning 发送用户过期警告
func (s *ExpirationService) sendUserExpirationWarning(ctx context.Context, user *model.User, config model.ExpirationNotificationConfig) error {
	if user.ExpiresAt == nil {
		return nil
	}

	daysLeft := int(time.Until(*user.ExpiresAt).Hours() / 24)

	title := "⚠️ 账号即将过期提醒"
	content := fmt.Sprintf(
		"**用户**：%s (%s)\n"+
			"**过期时间**：%s\n"+
			"**剩余天数**：%d 天\n\n"+
			"请尽快联系管理员续期。",
		user.FullName,
		user.Username,
		user.ExpiresAt.Format("2006-01-02 15:04:05"),
		daysLeft,
	)

	// 记录日志
	logger.Warnf("User expiration warning: %s - %s", title, content)

	// 发送通知
	if s.notificationManager != nil {
		s.notificationManager.SendAlert(title, content)
	}

	return nil
}

// sendUserExpiredNotification 发送用户已过期通知
func (s *ExpirationService) sendUserExpiredNotification(ctx context.Context, user *model.User, config model.ExpirationNotificationConfig) error {
	title := "🚨 账号已过期通知"
	content := fmt.Sprintf(
		"**用户**：%s (%s)\n"+
			"**过期时间**：%s\n"+
			"**当前状态**：%s\n\n"+
			"账号已过期，请联系管理员续期。",
		user.FullName,
		user.Username,
		user.ExpiresAt.Format("2006-01-02 15:04:05"),
		user.Status,
	)

	logger.Warnf("%s - %s", title, content)

	// 发送通知
	if s.notificationManager != nil {
		s.notificationManager.SendAlert(title, content)
	}

	return nil
}

// sendPermissionExpirationWarning 发送授权过期警告
func (s *ExpirationService) sendPermissionExpirationWarning(ctx context.Context, rule *model.PermissionRule, role *model.Role, config model.ExpirationNotificationConfig) error {
	if rule.ValidTo == nil {
		return nil
	}

	daysLeft := int(time.Until(*rule.ValidTo).Hours() / 24)

	title := "⚠️ 授权规则即将过期提醒"
	content := fmt.Sprintf(
		"**规则名称**：%s\n"+
			"**角色**：%s\n"+
			"**过期时间**：%s\n"+
			"**剩余天数**：%d 天\n\n"+
			"请及时续期或调整授权规则。",
		rule.Name,
		role.Name,
		rule.ValidTo.Format("2006-01-02 15:04:05"),
		daysLeft,
	)

	logger.Warnf("%s - %s", title, content)

	// 发送通知
	if s.notificationManager != nil {
		s.notificationManager.SendAlert(title, content)
	}

	return nil
}

// sendPermissionExpiredNotification 发送授权已过期通知
func (s *ExpirationService) sendPermissionExpiredNotification(ctx context.Context, rule *model.PermissionRule, role *model.Role, config model.ExpirationNotificationConfig) error {
	title := "🚨 授权规则已过期通知"
	content := fmt.Sprintf(
		"**规则名称**：%s\n"+
			"**角色**：%s\n"+
			"**过期时间**：%s\n"+
			"**当前状态**：%s\n\n"+
			"授权规则已过期，请及时处理。",
		rule.Name,
		role.Name,
		rule.ValidTo.Format("2006-01-02 15:04:05"),
		func() string {
			if rule.Enabled {
				return "启用"
			}
			return "已禁用"
		}(),
	)

	logger.Warnf("%s - %s", title, content)

	// 发送通知
	if s.notificationManager != nil {
		s.notificationManager.SendAlert(title, content)
	}

	return nil
}

// RenewUserExpiration 续期用户
func (s *ExpirationService) RenewUserExpiration(userID string, newExpiresAt *time.Time, reason string, performedBy string) error {
	var user model.User
	if err := s.db.Where("id = ?", userID).First(&user).Error; err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	oldExpiresAt := user.ExpiresAt

	// 更新过期时间
	updates := map[string]interface{}{
		"expires_at":              newExpiresAt,
		"expiration_warning_sent": false, // 重置警告标记
	}

	// 如果新的过期时间在未来，则自动激活账号
	if newExpiresAt != nil && newExpiresAt.After(time.Now()) && user.Status == "inactive" {
		updates["status"] = "active"
	}

	if err := s.db.Model(&user).Updates(updates).Error; err != nil {
		return fmt.Errorf("failed to renew user: %w", err)
	}

	// 记录日志
	log := model.UserExpirationLog{
		UserID:       user.ID,
		Username:     user.Username,
		Action:       "renewed",
		ExpiresAt:    oldExpiresAt,
		NewExpiresAt: newExpiresAt,
		Reason:       reason,
		PerformedBy:  performedBy,
	}
	s.db.Create(&log)

	logger.Infof("User %s expiration renewed by %s", user.Username, performedBy)
	return nil
}

// RenewPermissionExpiration 续期授权规则
func (s *ExpirationService) RenewPermissionExpiration(ruleID string, newValidTo *time.Time, reason string, performedBy string) error {
	var rule model.PermissionRule
	if err := s.db.Where("id = ?", ruleID).First(&rule).Error; err != nil {
		return fmt.Errorf("permission rule not found: %w", err)
	}

	oldValidTo := rule.ValidTo

	// 更新过期时间
	updates := map[string]interface{}{
		"valid_to": newValidTo,
	}

	// 如果新的过期时间在未来，则自动启用规则
	if newValidTo != nil && newValidTo.After(time.Now()) && !rule.Enabled {
		updates["enabled"] = true
	}

	if err := s.db.Model(&rule).Updates(updates).Error; err != nil {
		return fmt.Errorf("failed to renew permission rule: %w", err)
	}

	// 获取角色信息
	var role model.Role
	s.db.Where("id = ?", rule.RoleID).First(&role)

	// 记录日志
	log := model.PermissionExpirationLog{
		RuleID:      rule.ID,
		RuleName:    rule.Name,
		RoleID:      rule.RoleID,
		RoleName:    role.Name,
		Action:      "renewed",
		ValidTo:     oldValidTo,
		NewValidTo:  newValidTo,
		Reason:      reason,
		PerformedBy: performedBy,
	}
	s.db.Create(&log)

	logger.Infof("Permission rule %s expiration renewed by %s", rule.Name, performedBy)
	return nil
}
