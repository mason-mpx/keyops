package distributed

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/go-redis/redis/v8"
)

// ConfigSyncManager 配置同步管理器
type ConfigSyncManager struct {
	client    *redis.Client
	channel   string
	listeners []ConfigChangeListener
	ctx       context.Context
	cancelFn  context.CancelFunc
}

// ConfigChangeListener 配置变更监听器
type ConfigChangeListener func(key string, value string)

// NewConfigSyncManager 创建配置同步管理器
// 如果client为nil（Redis未启用），返回的管理器不会工作，但不影响主流程
func NewConfigSyncManager(client *redis.Client, channel string) *ConfigSyncManager {
	ctx, cancel := context.WithCancel(context.Background())
	return &ConfigSyncManager{
		client:    client,
		channel:   channel,
		listeners: make([]ConfigChangeListener, 0),
		ctx:       ctx,
		cancelFn:  cancel,
	}
}

// AddListener 添加配置变更监听器
func (m *ConfigSyncManager) AddListener(listener ConfigChangeListener) {
	m.listeners = append(m.listeners, listener)
}

// Start 启动配置同步
// 如果Redis未启用（client为nil），直接返回（优雅降级）
func (m *ConfigSyncManager) Start() {
	if m.client == nil {
		log.Printf("[ConfigSync] Redis not available, config sync disabled (single-server mode)")
		return
	}

	pubsub := m.client.Subscribe(m.ctx, m.channel)
	defer pubsub.Close()

	log.Printf("[ConfigSync] Started listening on channel: %s", m.channel)

	// 接收消息
	ch := pubsub.Channel()
	for {
		select {
		case msg := <-ch:
			m.handleMessage(msg)
		case <-m.ctx.Done():
			log.Printf("[ConfigSync] Stopped listening on channel: %s", m.channel)
			return
		}
	}
}

// Stop 停止配置同步
func (m *ConfigSyncManager) Stop() {
	m.cancelFn()
}

// PublishConfigChange 发布配置变更
// 如果Redis未启用（client为nil），返回nil（优雅降级，单机模式下不需要同步）
func (m *ConfigSyncManager) PublishConfigChange(key string, value string) error {
	if m.client == nil {
		// Redis未启用，单机模式不需要同步
		return nil
	}

	data := map[string]string{
		"key":       key,
		"value":     value,
		"timestamp": time.Now().Format(time.RFC3339),
	}

	payload, err := json.Marshal(data)
	if err != nil {
		return err
	}

	return m.client.Publish(m.ctx, m.channel, payload).Err()
}

// handleMessage 处理接收到的配置变更消息
func (m *ConfigSyncManager) handleMessage(msg *redis.Message) {
	var data map[string]string
	if err := json.Unmarshal([]byte(msg.Payload), &data); err != nil {
		log.Printf("[ConfigSync] Failed to parse message: %v", err)
		return
	}

	key := data["key"]
	value := data["value"]

	log.Printf("[ConfigSync] Received config change: %s = %s", key, value)

	// 通知所有监听器
	for _, listener := range m.listeners {
		go listener(key, value)
	}
}
