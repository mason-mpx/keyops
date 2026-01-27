package scheduler

import (
	"log"
	"sync"
	"time"

	"github.com/fisker/zjump-backend/internal/model"
	"github.com/fisker/zjump-backend/internal/repository"
)

// DatasourceSyncScheduler 数据源同步调度器
type DatasourceSyncScheduler struct {
	ruleSourceRepo *repository.AlertRuleSourceRepository
	alertService   DatasourceSyncService // 同步服务接口
	tasks          map[uint]*syncTask     // 数据源ID -> 定时任务
	tasksMu        sync.RWMutex          // 保护 tasks 的并发访问
	stopChan       chan struct{}         // 全局停止信号
	wg             sync.WaitGroup         // 等待所有 goroutine 退出
}

// DatasourceSyncService 同步服务接口，由 AlertService 实现
type DatasourceSyncService interface {
	SyncRulesFromDatasource(sourceID uint) error
}

// syncTask 单个数据源的同步任务
type syncTask struct {
	sourceID    uint
	sourceName  string
	interval    time.Duration
	ticker      *time.Ticker
	stopChan    chan struct{} // 停止信号
	stoppedChan chan struct{} // 确认已停止
}

// NewDatasourceSyncScheduler 创建数据源同步调度器
func NewDatasourceSyncScheduler(
	ruleSourceRepo *repository.AlertRuleSourceRepository,
	alertService DatasourceSyncService,
) *DatasourceSyncScheduler {
	return &DatasourceSyncScheduler{
		ruleSourceRepo: ruleSourceRepo,
		alertService:   alertService,
		tasks:          make(map[uint]*syncTask),
		stopChan:       make(chan struct{}),
	}
}

// Start 启动调度器，加载所有启用了自动同步的数据源并启动定时任务
func (s *DatasourceSyncScheduler) Start() error {
	log.Println("[DatasourceSyncScheduler] 📅 Starting datasource sync scheduler...")

	// 加载所有启用了自动同步的数据源
	_, sources, err := s.ruleSourceRepo.ListAll(1, 1000) // 获取所有数据源
	if err != nil {
		return err
	}

	var startedCount int
	for _, source := range sources {
		if source.AutoSync {
			if err := s.StartTask(source.ID, source.SourceName, source.SyncInterval); err != nil {
				log.Printf("[DatasourceSyncScheduler] Failed to start task for source %d: %v", source.ID, err)
				continue
			}
			startedCount++
		}
	}

	log.Printf("[DatasourceSyncScheduler] ✅ Scheduler started, %d auto-sync tasks running", startedCount)
	return nil
}

// StartTask 为指定数据源启动定时同步任务
func (s *DatasourceSyncScheduler) StartTask(sourceID uint, sourceName string, intervalMinutes int) error {
	s.tasksMu.Lock()
	defer s.tasksMu.Unlock()

	// 如果任务已存在，先停止它
	if task, exists := s.tasks[sourceID]; exists {
		log.Printf("[DatasourceSyncScheduler] Task for source %d already exists, stopping old task...", sourceID)
		s.stopTaskInternal(task)
		delete(s.tasks, sourceID)
	}

	// 设置默认间隔
	if intervalMinutes <= 0 {
		intervalMinutes = 10 // 默认10分钟
	}

	interval := time.Duration(intervalMinutes) * time.Minute

	// 创建新的任务
	task := &syncTask{
		sourceID:    sourceID,
		sourceName:  sourceName,
		interval:    interval,
		ticker:      time.NewTicker(interval),
		stopChan:    make(chan struct{}),
		stoppedChan: make(chan struct{}),
	}

	s.tasks[sourceID] = task

	// 启动 goroutine
	s.wg.Add(1)
	go s.runTask(task)

	log.Printf("[DatasourceSyncScheduler] ▶️  Started sync task for source %d (%s), interval: %v", sourceID, sourceName, interval)
	return nil
}

// StopTask 停止指定数据源的定时同步任务
func (s *DatasourceSyncScheduler) StopTask(sourceID uint) error {
	s.tasksMu.Lock()
	defer s.tasksMu.Unlock()

	task, exists := s.tasks[sourceID]
	if !exists {
		log.Printf("[DatasourceSyncScheduler] Task for source %d not found", sourceID)
		return nil
	}

	log.Printf("[DatasourceSyncScheduler] ⏹️  Stopping sync task for source %d (%s)...", sourceID, task.sourceName)
	s.stopTaskInternal(task)
	delete(s.tasks, sourceID)

	log.Printf("[DatasourceSyncScheduler] ✅ Task for source %d stopped", sourceID)
	return nil
}

// stopTaskInternal 内部方法：停止任务
func (s *DatasourceSyncScheduler) stopTaskInternal(task *syncTask) {
	// 发送停止信号
	close(task.stopChan)

	// 停止 ticker
	task.ticker.Stop()

	// 等待 goroutine 退出
	select {
	case <-task.stoppedChan:
		// goroutine 已退出
	case <-time.After(5 * time.Second):
		log.Printf("[DatasourceSyncScheduler] ⚠️  Timeout waiting for task %d to stop", task.sourceID)
	}
}

// runTask 运行单个数据源的同步任务
func (s *DatasourceSyncScheduler) runTask(task *syncTask) {
	defer func() {
		s.wg.Done()
		close(task.stoppedChan)
	}()

	log.Printf("[DatasourceSyncScheduler] 🔄 Sync task started for source %d (%s)", task.sourceID, task.sourceName)

	for {
		select {
		case <-task.ticker.C:
			// 执行同步
			log.Printf("[DatasourceSyncScheduler] 🔄 Syncing rules from datasource %d (%s)...", task.sourceID, task.sourceName)
			if err := s.alertService.SyncRulesFromDatasource(task.sourceID); err != nil {
				log.Printf("[DatasourceSyncScheduler] ❌ Sync failed for source %d (%s): %v", task.sourceID, task.sourceName, err)
			} else {
				log.Printf("[DatasourceSyncScheduler] ✅ Sync completed for source %d (%s)", task.sourceID, task.sourceName)
			}

		case <-task.stopChan:
			// 收到停止信号
			log.Printf("[DatasourceSyncScheduler] ⏹️  Sync task stopping for source %d (%s)", task.sourceID, task.sourceName)
			return

		case <-s.stopChan:
			// 全局停止信号
			log.Printf("[DatasourceSyncScheduler] ⏹️  Sync task stopping (global stop) for source %d (%s)", task.sourceID, task.sourceName)
			return
		}
	}
}

// UpdateTask 更新数据源的定时任务（如果启用了自动同步则启动/更新，否则停止）
func (s *DatasourceSyncScheduler) UpdateTask(source *model.AlertRuleSource) error {
	if source.AutoSync {
		// 启动或更新任务
		return s.StartTask(source.ID, source.SourceName, source.SyncInterval)
	} else {
		// 停止任务
		return s.StopTask(source.ID)
	}
}

// Stop 停止所有定时任务
func (s *DatasourceSyncScheduler) Stop() {
	log.Println("[DatasourceSyncScheduler] ⏹️  Stopping all sync tasks...")

	// 发送全局停止信号
	close(s.stopChan)

	// 停止所有任务
	s.tasksMu.Lock()
	for sourceID, task := range s.tasks {
		log.Printf("[DatasourceSyncScheduler] Stopping task for source %d...", sourceID)
		task.ticker.Stop()
		close(task.stopChan)
	}
	s.tasksMu.Unlock()

	// 等待所有 goroutine 退出
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Println("[DatasourceSyncScheduler] ✅ All sync tasks stopped")
	case <-time.After(10 * time.Second):
		log.Println("[DatasourceSyncScheduler] ⚠️  Timeout waiting for all tasks to stop")
	}
}

// GetRunningTasks 获取正在运行的任务列表
func (s *DatasourceSyncScheduler) GetRunningTasks() []uint {
	s.tasksMu.RLock()
	defer s.tasksMu.RUnlock()

	var sourceIDs []uint
	for sourceID := range s.tasks {
		sourceIDs = append(sourceIDs, sourceID)
	}
	return sourceIDs
}

