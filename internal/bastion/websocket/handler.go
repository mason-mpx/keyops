package websocket

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/fisker/zjump-backend/internal/bastion/blacklist"
	apiclient "github.com/fisker/zjump-backend/internal/bastion/client"
	"github.com/fisker/zjump-backend/internal/bastion/parser"
	"github.com/fisker/zjump-backend/internal/bastion/recorder"
	"github.com/fisker/zjump-backend/internal/bastion/storage"
	"github.com/fisker/zjump-backend/internal/model"
	"github.com/fisker/zjump-backend/internal/repository"
	"github.com/fisker/zjump-backend/pkg/sshclient"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true // 允许所有来源（开发环境）
	},
}

// Handler WebSocket 处理器
type Handler struct {
	hostRepo       *repository.HostRepository
	storage        storage.Storage
	proxyID        string
	sessionManager *SessionManager
	blacklistMgr   *blacklist.Manager
	apiClient      *apiclient.ApiClient // API 客户端
}

// TokenInfo 令牌信息（从 API Server 验证返回）
type TokenInfo struct {
	HostID   string `json:"hostId"`
	UserID   string `json:"userId"`
	Username string `json:"username"`
}

// NewHandler 创建新的 WebSocket 处理器
func NewHandler(hostRepo *repository.HostRepository, st storage.Storage, proxyID string, sm *SessionManager, blMgr *blacklist.Manager, apiClient *apiclient.ApiClient) *Handler {
	return &Handler{
		hostRepo:       hostRepo,
		storage:        st,
		proxyID:        proxyID,
		sessionManager: sm,
		blacklistMgr:   blMgr,
		apiClient:      apiClient,
	}
}

// HandleSSH 处理 SSH WebSocket 连接
func (h *Handler) HandleSSH(c *gin.Context) {
	// 获取 Token（从 API Server 获取）
	token := c.Query("token")
	if token == "" {
		log.Printf("Missing token")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing token"})
		return
	}

	// 验证 Token（调用 API Server）
	tokenInfo, err := h.validateToken(token)
	if err != nil {
		log.Printf("Invalid token: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
		return
	}

	// 根据 Token 中的 HostID 获取主机信息
	host, err := h.hostRepo.FindByID(tokenInfo.HostID)
	if err != nil {
		log.Printf("Host not found: %s, error: %v", tokenInfo.HostID, err)
		c.JSON(http.StatusNotFound, gin.H{"error": "Host not found"})
		return
	}

	// 升级到 WebSocket
	ws, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("Failed to upgrade to websocket: %v", err)
		return
	}
	defer ws.Close()

	sessionID := uuid.New().String()
	log.Printf("New WebSocket connection for host %s (%s), session: %s", host.Name, host.IP, sessionID)

	// 添加会话到管理器
	h.sessionManager.AddSession(sessionID, ws)

	// 创建会话录制器（默认终端大小，后续会更新）
	rec := recorder.NewRecorder(sessionID, 120, 30)

	connectionSuccess := false // 标记连接是否成功
	startTime := time.Now()

	// 先创建登录记录（无论连接成功与否都需要记录）
	loginRecord := &storage.LoginRecord{
		SessionID: sessionID,
		UserID:    tokenInfo.UserID,
		HostID:    host.ID,
		HostName:  host.Name,
		HostIP:    host.IP,
		Username:  tokenInfo.Username,
		LoginTime: startTime,
		Status:    "connecting",
	}
	h.storage.SaveLoginRecord(loginRecord)

	// 确保会话关闭时更新状态和保存录制（无论如何退出都会执行）
	defer func() {
		// 从会话管理器中移除
		h.sessionManager.RemoveSession(sessionID)

		rec.Close()
		log.Printf("Session %s closing, events: %d", sessionID, rec.GetEventCount())

		// 导出录制内容
		recording, err := rec.ToAsciinema()
		if err != nil {
			log.Printf("Failed to export recording: %v", err)
			recording = ""
		}

		if connectionSuccess {
			// 连接成功，关闭会话并保存录制
			if err := h.storage.CloseSession(sessionID, recording); err != nil {
				log.Printf("Failed to close session: %v", err)
			} else {
				log.Printf("Session %s closed successfully", sessionID)
			}
			h.storage.UpdateLoginRecordStatus(sessionID, "completed", time.Now())
		} else {
			// 连接失败，不创建会话录制记录，只更新登录记录为失败状态
			h.storage.UpdateLoginRecordStatus(sessionID, "failed", time.Time{})
			log.Printf("Session %s marked as failed", sessionID)
		}
	}()

	// 发送连接开始消息
	ws.WriteJSON(map[string]interface{}{
		"type":    "info",
		"message": fmt.Sprintf("正在连接到 %s (%s:%d)...", host.Name, host.IP, host.Port),
	})

	// 连接到目标主机
	if err := h.proxySSHConnection(ws, host, sessionID, rec); err != nil {
		log.Printf("SSH proxy error: %v", err)
		// 发送错误消息给客户端
		errMsg := map[string]interface{}{
			"type":    "error",
			"message": fmt.Sprintf("SSH 连接失败: %v\r\n请检查主机地址、端口、用户名和密码是否正确", err),
		}
		ws.WriteJSON(errMsg)
		// 等待一小段时间让客户端接收错误消息
		time.Sleep(500 * time.Millisecond)
		// connectionSuccess 保持 false，defer 中会标记为 failed
	} else {
		// 连接成功，创建会话录制记录
		connectionSuccess = true
		sessionRecord := &storage.SessionRecord{
			ProxyID:      h.proxyID,
			SessionID:    sessionID,
			HostID:       host.ID,
			HostName:     host.Name,
			UserID:       tokenInfo.UserID,
			Username:     tokenInfo.Username,
			HostIP:       host.IP,
			StartTime:    startTime,
			TerminalCols: 120,
			TerminalRows: 30,
			Status:       "active",
		}
		if err := h.storage.SaveSession(sessionRecord); err != nil {
			log.Printf("Failed to save session: %v", err)
		}
	}

	// defer 会自动调用 CloseSession
	log.Printf("WebSocket handler for session %s completed", sessionID)
}

// proxySSHConnection 代理 SSH 连接
func (h *Handler) proxySSHConnection(ws *websocket.Conn, host *model.Host, sessionID string, rec *recorder.Recorder) error {
	// 创建命令拦截器和解析器
	var blockedCount int

	commandParser := parser.NewCommandExtractor(func(cmd string) {
		log.Printf("[Command] Detected from output: %q", cmd)

		// 检查是否为危险命令（只检测，不通知，因为输入拦截器已经通知过了）
		isBlocked := false
		reason := ""
		// TODO: host.Username 已移除，需要从 SystemUser 获取
		username := "" // TODO: 从 SystemUser 获取
		if h.blacklistMgr != nil && h.blacklistMgr.IsBlocked(cmd, username) {
			reason = h.blacklistMgr.GetBlockReason(cmd, username)
			blockedCount++
			isBlocked = true
			log.Printf("[Command] Command was blocked: %s - %s", cmd, reason)
		}

		// 记录命令到数据库（包括被阻止的命令）
		commandRecord := &storage.CommandRecord{
			ProxyID:    h.proxyID,
			SessionID:  sessionID,
			HostID:     host.ID,
			UserID:     "system", // TODO: 从认证获取
			Username:   username, // TODO: 从 SystemUser 获取
			HostIP:     host.IP,
			Command:    cmd,
			ExecutedAt: time.Now(),
		}

		if isBlocked {
			commandRecord.Output = fmt.Sprintf("[BLOCKED] %s", reason)
			commandRecord.ExitCode = -1 // 表示被阻止
		}

		if err := h.storage.SaveCommand(commandRecord); err != nil {
			log.Printf("[Command] Failed to save: %v", err)
		} else {
			log.Printf("[Command] Saved successfully: %s", cmd)
		}
	})

	// 创建 SSH 客户端配置
	// TODO: 认证信息需要从 SystemUser 获取
	cfg := sshclient.SSHConfig{
		Host:       host.IP,
		Port:       host.Port,
		Username:   "", // TODO: 从 SystemUser 获取
		Password:   "", // TODO: 从 SystemUser 获取
		PrivateKey: "", // TODO: 从 SystemUser 获取
		Passphrase: "", // TODO: 从 SystemUser 获取
		AuthType:   "", // TODO: 从 SystemUser 获取（"password" 或 "key"）
		Timeout:    30 * time.Second,
	}

	// 连接到目标主机
	client, err := sshclient.NewSSHClient(cfg)
	if err != nil {
		return fmt.Errorf("failed to connect to host: %w", err)
	}
	defer client.Close()

	// 创建 SSH session
	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	// 设置终端模式
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}

	// 请求 PTY
	if err := session.RequestPty("xterm-256color", 30, 120, modes); err != nil {
		return fmt.Errorf("failed to request pty: %w", err)
	}

	// 获取 session 的输入输出
	stdin, err := session.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to get stdin: %w", err)
	}

	stdout, err := session.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to get stdout: %w", err)
	}

	stderr, err := session.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to get stderr: %w", err)
	}

	// 启动 shell
	if err := session.Shell(); err != nil {
		return fmt.Errorf("failed to start shell: %w", err)
	}

	// 创建通道用于错误传递
	errChan := make(chan error, 2)

	// 从 WebSocket 读取并写入 SSH stdin
	// 命令缓冲区，用于拼接完整命令
	var commandBuffer []byte

	go func() {
		defer stdin.Close()
		for {
			_, message, err := ws.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					log.Printf("WebSocket read error: %v", err)
				}
				errChan <- err
				return
			}

			// 解析消息
			var msg map[string]interface{}
			if err := json.Unmarshal(message, &msg); err != nil {
				// 不是 JSON，直接发送
				stdin.Write(message)
				continue
			}

			// 处理不同类型的消息
			msgType, ok := msg["type"].(string)
			if !ok {
				continue
			}

			switch msgType {
			case "init":
				// 初始化消息，更新终端大小
				if cols, ok := msg["cols"].(float64); ok {
					if rows, ok := msg["rows"].(float64); ok {
						if err := session.WindowChange(int(rows), int(cols)); err != nil {
							log.Printf("Failed to change window size: %v", err)
						}
					}
				}

			case "resize":
				// 调整终端大小
				if cols, ok := msg["cols"].(float64); ok {
					if rows, ok := msg["rows"].(float64); ok {
						if err := session.WindowChange(int(rows), int(cols)); err != nil {
							log.Printf("Failed to resize: %v", err)
						}
					}
				}

			case "input":
				// 用户输入
				data, ok := msg["data"].(string)
				if !ok {
					continue
				}

				// 异步录制输入（不阻塞用户操作）
				rec.RecordInput(data)

				// 检查是否是回车键（命令执行前拦截）
				if data == "\r" || data == "\n" {
					// 获取完整命令
					command := string(commandBuffer)

					// 检查黑名单（在命令执行前，带通知功能）
					// TODO: host.Username 已移除，需要从 SystemUser 获取
					username := "" // TODO: 从 SystemUser 获取
					if command != "" && h.blacklistMgr != nil && h.blacklistMgr.IsBlockedWithNotify(command, username, host.IP) {
						reason := h.blacklistMgr.GetBlockReason(command, username)
						log.Printf("[ProxyAgent] ⛔ BLOCKING command for user %s on %s: %s - %s", username, host.IP, command, reason)

						// 清空缓冲区
						commandBuffer = commandBuffer[:0]

						// 发送阻止警告给客户端（不发送回车到SSH，命令不执行但已显示）
						blockMsg := map[string]interface{}{
							"type": "output",
							"data": fmt.Sprintf("\r\n\033[1;31m🛡️ [安全策略阻止] %s\033[0m\r\n", reason),
						}
						ws.WriteJSON(blockMsg)

						// 命令已被阻止，不发送回车键到远程
						continue
					}

					// 清空缓冲区
					commandBuffer = commandBuffer[:0]
				} else if data == "\x03" { // Ctrl+C
					// 清空缓冲区
					commandBuffer = commandBuffer[:0]
				} else if data == "\x7f" || data == "\b" { // 退格
					// 从缓冲区删除最后一个字符
					if len(commandBuffer) > 0 {
						commandBuffer = commandBuffer[:len(commandBuffer)-1]
					}
				} else {
					// 添加到命令缓冲区
					commandBuffer = append(commandBuffer, []byte(data)...)
				}

				// 写入 SSH stdin
				stdin.Write([]byte(data))
			}
		}
	}()

	// 从 SSH stdout 读取并写入 WebSocket
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := stdout.Read(buf)
			if err != nil {
				errChan <- err
				return
			}
			if n > 0 {
				data := string(buf[:n])

				// 异步录制输出（不阻塞）
				rec.RecordOutput(data)

				// 将输出喂给命令解析器（从输出流中提取命令）
				commandParser.Feed(data)

				// 发送输出到客户端
				output := map[string]interface{}{
					"type": "output",
					"data": data,
				}
				if err := ws.WriteJSON(output); err != nil {
					errChan <- err
					return
				}
			}
		}
	}()

	// 从 SSH stderr 读取并写入 WebSocket
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := stderr.Read(buf)
			if err != nil {
				return
			}
			if n > 0 {
				data := string(buf[:n])

				// 异步录制错误输出（不阻塞）
				rec.RecordOutput(data)

				// stderr 通常不包含命令，但为了完整性也解析
				// commandParser.Feed(data)

				output := map[string]interface{}{
					"type": "output",
					"data": data,
				}
				ws.WriteJSON(output)
			}
		}
	}()

	// 等待会话结束或错误
	select {
	case err := <-errChan:
		return err
	}
}

// validateToken 验证令牌（调用 API Server）
func (h *Handler) validateToken(token string) (*TokenInfo, error) {
	// 调用 API Server 验证令牌
	resp, err := h.apiClient.ValidateSessionToken(token)
	if err != nil {
		return nil, err
	}

	// 解析响应
	var tokenInfo TokenInfo
	if data, ok := resp["data"].(map[string]interface{}); ok {
		if hostID, ok := data["hostId"].(string); ok {
			tokenInfo.HostID = hostID
		}
		if userID, ok := data["userId"].(string); ok {
			tokenInfo.UserID = userID
		}
		if username, ok := data["username"].(string); ok {
			tokenInfo.Username = username
		}
		return &tokenInfo, nil
	}

	return nil, fmt.Errorf("invalid response format")
}
