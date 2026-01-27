package bastion

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/fisker/zjump-backend/internal/model"
	"github.com/fisker/zjump-backend/internal/repository"
	"github.com/fisker/zjump-backend/pkg/sshclient"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type FileHandler struct {
	db             *gorm.DB
	hostRepo       *repository.HostRepository
	systemUserRepo *repository.SystemUserRepository
}

func NewFileHandler(db *gorm.DB, hostRepo *repository.HostRepository, systemUserRepo *repository.SystemUserRepository) *FileHandler {
	return &FileHandler{
		db:             db,
		hostRepo:       hostRepo,
		systemUserRepo: systemUserRepo,
	}
}

// UploadFile 上传文件到目标服务器
func (h *FileHandler) UploadFile(c *gin.Context) {
	// 获取参数
	hostID := c.PostForm("hostId")
	remotePath := c.PostForm("remotePath")

	if hostID == "" {
		c.JSON(http.StatusBadRequest, model.Error(400, "Missing hostId"))
		return
	}

	if remotePath == "" {
		remotePath = "/tmp"
	}

	// 获取上传的文件
	file, header, err := c.Request.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, model.Error(400, "Failed to get file: "+err.Error()))
		return
	}
	defer file.Close()

	// 获取用户信息（修复：使用驼峰命名与中间件一致）
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, model.Error(401, "未找到用户信息"))
		return
	}
	username, _ := c.Get("username")

	// 获取主机信息
	host, err := h.hostRepo.FindByID(hostID)
	if err != nil {
		c.JSON(http.StatusNotFound, model.Error(404, "Host not found"))
		return
	}

	// 创建文件传输记录
	transferID := uuid.New().String()
	startTime := time.Now()

	// 安全的类型转换
	userIDStr, ok := userID.(string)
	if !ok {
		c.JSON(http.StatusInternalServerError, model.Error(500, "用户ID类型错误"))
		return
	}
	usernameStr, ok := username.(string)
	if !ok {
		usernameStr = "unknown" // 如果username获取失败，使用默认值
	}

	transfer := &model.FileTransfer{
		ID:            transferID,
		SessionID:     uuid.New().String(), // 文件传输也需要会话ID
		UserID:        userIDStr,
		Username:      usernameStr,
		HostID:        host.ID,
		HostIP:        host.IP,
		HostName:      host.Name,
		Direction:     "upload",
		LocalPath:     header.Filename,
		RemotePath:    filepath.Join(remotePath, header.Filename),
		FileName:      header.Filename,
		FileSize:      header.Size,
		Status:        "uploading",
		Progress:      0,
		TransferredAt: startTime,
	}

	if err := h.db.Create(transfer).Error; err != nil {
		log.Printf("[FileHandler] Failed to create transfer record: %v", err)
	}

	// 通过SFTP上传文件
	err = h.uploadFileSFTP(host, remotePath, header.Filename, file, func(progress int) {
		// 更新进度
		h.db.Model(&model.FileTransfer{}).Where("id = ?", transferID).Update("progress", progress)
	})

	completedAt := time.Now()
	duration := int(completedAt.Sub(startTime).Seconds())

	if err != nil {
		// 更新为失败状态
		h.db.Model(&model.FileTransfer{}).Where("id = ?", transferID).Updates(map[string]interface{}{
			"status":        "failed",
			"error_message": err.Error(),
			"completed_at":  completedAt,
			"duration":      duration,
		})

		c.JSON(http.StatusInternalServerError, model.Error(500, "Failed to upload file: "+err.Error()))
		return
	}

	// 更新为成功状态
	h.db.Model(&model.FileTransfer{}).Where("id = ?", transferID).Updates(map[string]interface{}{
		"status":       "completed",
		"progress":     100,
		"completed_at": completedAt,
		"duration":     duration,
	})

	c.JSON(http.StatusOK, model.Response{
		Code:    0,
		Message: "File uploaded successfully",
		Data: gin.H{
			"transferId": transferID,
			"fileName":   header.Filename,
			"fileSize":   header.Size,
			"remotePath": filepath.Join(remotePath, header.Filename),
			"duration":   duration,
		},
	})
}

// uploadFileSFTP 通过SFTP上传文件
// TODO: 需要重构此方法，传入 SystemUser 参数以获取认证信息
// 当前实现已不可用，因为 Host 模型已移除认证字段
func (h *FileHandler) uploadFileSFTP(host *model.Host, remotePath, filename string, fileReader io.Reader, progressCallback func(int)) error {
	// TODO: 需要从 SystemUser 获取认证信息
	return fmt.Errorf("文件上传功能需要重构以支持系统用户认证，请稍后再试")

	// 以下代码需要重构
	/*
		// 创建SSH连接
		config := &ssh.ClientConfig{
			User: systemUser.Username,  // 从 SystemUser 获取
			Auth: []ssh.AuthMethod{
				ssh.Password(systemUser.Password),
			},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         30 * time.Second,
		}

		if systemUser.PrivateKey != "" {
			signer, err := ssh.ParsePrivateKey([]byte(systemUser.PrivateKey))
			if err == nil {
				config.Auth = append(config.Auth, ssh.PublicKeys(signer))
			}
		}


		conn, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", host.IP, host.Port), config)
		if err != nil {
			return fmt.Errorf("failed to dial: %w", err)
		}
		defer conn.Close()

		// 创建SFTP会话
		session, err := conn.NewSession()
		if err != nil {
			return fmt.Errorf("failed to create session: %w", err)
		}
		defer session.Close()

		// 获取stdin管道
		stdin, err := session.StdinPipe()
		if err != nil {
			return fmt.Errorf("failed to get stdin pipe: %w", err)
		}

		// 创建目标文件
		remoteFile := filepath.Join(remotePath, filename)
		cmd := fmt.Sprintf("cat > %s", remoteFile)

		if err := session.Start(cmd); err != nil {
			return fmt.Errorf("failed to start command: %w", err)
		}

		// 复制文件内容
		buffer := make([]byte, 32*1024) // 32KB buffer
		var totalWritten int64

		for {
			n, err := fileReader.Read(buffer)
			if n > 0 {
				written, writeErr := stdin.Write(buffer[:n])
				if writeErr != nil {
					return fmt.Errorf("failed to write: %w", writeErr)
				}
				totalWritten += int64(written)

				// 更新进度（暂时简化，实际需要知道文件总大小）
				if progressCallback != nil {
					progressCallback(50) // 简化的进度更新
				}
			}

			if err == io.EOF {
				break
			}
			if err != nil {
				return fmt.Errorf("failed to read: %w", err)
			}
		}

		stdin.Close()

		if progressCallback != nil {
			progressCallback(100)
		}

		return session.Wait()
	*/
}

// GetFileTransfers 获取文件传输记录列表
func (h *FileHandler) GetFileTransfers(c *gin.Context) {
	var transfers []model.FileTransfer

	query := h.db.Model(&model.FileTransfer{}).Order("transferred_at DESC")

	// 可选过滤条件
	if hostID := c.Query("hostId"); hostID != "" {
		query = query.Where("host_id = ?", hostID)
	}
	if userID := c.Query("userId"); userID != "" {
		query = query.Where("user_id = ?", userID)
	}
	if direction := c.Query("direction"); direction != "" {
		query = query.Where("direction = ?", direction)
	}

	if err := query.Find(&transfers).Error; err != nil {
		c.JSON(http.StatusInternalServerError, model.Error(500, "Failed to get file transfers: "+err.Error()))
		return
	}

	c.JSON(http.StatusOK, model.Response{
		Code:    0,
		Message: "File transfers retrieved successfully",
		Data:    gin.H{"transfers": transfers},
	})
}

// ListFiles 列出远程目录的文件
func (h *FileHandler) ListFiles(c *gin.Context) {
	hostID := c.Query("hostId")
	path := c.Query("path")
	systemUserID := c.Query("systemUserId")

	if hostID == "" {
		c.JSON(http.StatusBadRequest, model.Error(400, "Missing hostId parameter"))
		return
	}

	if path == "" {
		path = "/"
	}

	// 获取主机信息
	host, err := h.hostRepo.FindByID(hostID)
	if err != nil {
		c.JSON(http.StatusNotFound, model.Error(404, "Host not found"))
		return
	}

	// 获取系统用户信息
	if systemUserID == "" {
		c.JSON(http.StatusBadRequest, model.Error(400, "Missing systemUserId parameter"))
		return
	}

	systemUser, err := h.systemUserRepo.FindByID(systemUserID)
	if err != nil {
		c.JSON(http.StatusNotFound, model.Error(404, "System user not found"))
		return
	}

	// 通过SSH连接执行 ls 命令获取文件列表
	files, err := h.listFilesViaSSH(host, systemUser, path)
	if err != nil {
		log.Printf("[FileHandler] Failed to list files via SSH: %v", err)
		c.JSON(http.StatusInternalServerError, model.Error(500, "Failed to list files: "+err.Error()))
		return
	}

	c.JSON(http.StatusOK, model.Response{
		Code:    0,
		Message: "File list retrieved successfully",
		Data: gin.H{
			"files": files,
		},
	})
}

// listFilesViaSSH 通过SSH连接执行 ls 命令获取文件列表
func (h *FileHandler) listFilesViaSSH(host *model.Host, systemUser *model.SystemUser, path string) ([]gin.H, error) {
	// 构建SSH配置
	sshConfig := sshclient.SSHConfig{
		Host:       host.IP,
		Port:       host.Port,
		Username:   systemUser.Username,
		Password:   systemUser.Password,
		PrivateKey: systemUser.PrivateKey,
		Passphrase: systemUser.Passphrase,
		AuthType:   systemUser.AuthType,
		Timeout:    30 * time.Second,
	}

	// 创建SSH客户端
	client, err := sshclient.NewSSHClient(sshConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create SSH client: %w", err)
	}
	defer client.Close()

	// 创建会话
	session, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	// 执行 ls -la 命令
	// 转义路径中的特殊字符
	escapedPath := strings.ReplaceAll(path, "'", "'\"'\"'")
	cmd := fmt.Sprintf("cd '%s' && ls -la 2>/dev/null | tail -n +2", escapedPath)
	output, err := session.CombinedOutput(cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to execute ls command: %w", err)
	}

	// 解析输出
	files := h.parseLsOutput(string(output), path)
	return files, nil
}

// parseLsOutput 解析 ls -la 命令的输出
func (h *FileHandler) parseLsOutput(output, basePath string) []gin.H {
	var files []gin.H
	lines := strings.Split(strings.TrimSpace(output), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "total ") {
			continue
		}

		// 解析 ls -la 输出格式: -rw-r--r-- 1 user group 1024 Jan 16 21:00 filename
		// 或者: drwxr-xr-x 2 user group 4096 Jan 16 21:00 dirname
		// 注意：文件名可能包含空格，所以需要从第8个字段开始到末尾都是文件名
		parts := strings.Fields(line)
		if len(parts) < 9 {
			continue
		}

		mode := parts[0]
		// parts[1] 是链接数
		// parts[2] 是用户
		// parts[3] 是组
		size := parts[4]
		// parts[5:7] 是日期时间的前3部分（月 日 时间/年）
		modTime := strings.Join(parts[5:8], " ")
		// 从第8个字段开始到末尾都是文件名（可能包含空格）
		name := strings.Join(parts[8:], " ")

		// 跳过 . 和 .. 目录
		if name == "." || name == ".." {
			continue
		}

		// 判断是否为目录
		isDir := strings.HasPrefix(mode, "d")

		// 构建完整路径
		fullPath := basePath
		if !strings.HasSuffix(fullPath, "/") && fullPath != "/" {
			fullPath += "/"
		}
		if fullPath == "/" {
			fullPath = "/" + name
		} else {
			fullPath += name
		}

		// 转换文件大小
		var fileSize int64
		fmt.Sscanf(size, "%d", &fileSize)

		files = append(files, gin.H{
			"name":    name,
			"path":    fullPath,
			"size":    fileSize,
			"isDir":   isDir,
			"mode":    mode,
			"modTime": modTime,
		})
	}

	return files
}

// DownloadFile 从目标服务器下载文件
func (h *FileHandler) DownloadFile(c *gin.Context) {
	// TODO: 实现文件下载功能
	c.JSON(http.StatusNotImplemented, model.Error(501, "Download not implemented yet"))
}
