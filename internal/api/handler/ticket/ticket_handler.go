package ticket

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/fisker/zjump-backend/internal/model"
)

// TicketHandler 工单处理器
type TicketHandler struct {
	db *gorm.DB
}

// NewTicketHandler 创建工单处理器
func NewTicketHandler(db *gorm.DB) *TicketHandler {
	return &TicketHandler{
		db: db,
	}
}

// generateTicketNumber 生成工单编号
func generateTicketNumber() string {
	return fmt.Sprintf("TKT-%s", time.Now().Format("20060102150405")+uuid.New().String()[:8])
}

// DeploymentWithJenkinsInfo 包含Jenkins服务器信息的部署记录
type DeploymentWithJenkinsInfo struct {
	model.Deployment
	JenkinsServerURL string `json:"jenkins_server_url,omitempty"` // Jenkins服务器URL（如果部署类型是Jenkins）
}

// buildDeploymentWithJenkinsInfo 构建包含Jenkins服务器信息的部署记录
func buildDeploymentWithJenkinsInfo(db *gorm.DB, deployment model.Deployment) DeploymentWithJenkinsInfo {
	deploymentWithInfo := DeploymentWithJenkinsInfo{
		Deployment: deployment,
	}

	// 如果是Jenkins部署，查询Jenkins服务器URL
	if deployment.DeployType == "jenkins" && deployment.DeployConfig != "" {
		var deployConfig map[string]interface{}
		if err := json.Unmarshal([]byte(deployment.DeployConfig), &deployConfig); err == nil {
			if serverID, ok := deployConfig["jenkins_server_id"].(float64); ok {
				var jenkinsServer model.JenkinsServer
				if err := db.First(&jenkinsServer, uint(serverID)).Error; err == nil {
					// 直接使用 URL 字段
					deploymentWithInfo.JenkinsServerURL = jenkinsServer.URL
				}
			}
		}
	}

	return deploymentWithInfo
}

// ListTickets 获取工单列表
func (h *TicketHandler) ListTickets(c *gin.Context) {
	var tickets []model.Ticket
	query := h.db.Model(&model.Ticket{})

	// 预加载模板（如果有的话）
	query = query.Preload("Template")

	// 权限检查：如果查询全部工单（没有传 applicant_id 且 exclude_status=draft），需要管理员权限
	applicantID := c.Query("applicant_id")
	excludeStatus := c.Query("exclude_status")
	if applicantID == "" && excludeStatus == "draft" {
		// 查询全部工单，需要管理员权限
		role, exists := c.Get("role")
		if !exists || role != "admin" {
			c.JSON(http.StatusForbidden, gin.H{
				"code":    403,
				"message": "需要管理员权限才能查看全部工单",
			})
			return
		}
	}

	// 过滤条件
	if status := c.Query("status"); status != "" {
		query = query.Where("status = ?", status)
	}
	// 排除特定状态（例如：排除草稿）
	if excludeStatus != "" {
		query = query.Where("status != ?", excludeStatus)
	}
	if templateID := c.Query("template_id"); templateID != "" {
		query = query.Where("template_id = ?", templateID)
	}
	if applicantID != "" {
		query = query.Where("applicant_id = ?", applicantID)
	} else {
		// 如果没有传 applicant_id，但也不是查询全部工单（没有 exclude_status=draft），则默认查询当前用户的工单
		// 这是为了安全：普通用户查询时，如果没有传 applicant_id，自动限制为自己的工单
		if excludeStatus != "draft" {
			if userID, exists := c.Get("user_id"); exists {
				query = query.Where("applicant_id = ?", userID)
			}
		}
	}
	if keyword := c.Query("keyword"); keyword != "" {
		query = query.Where("title LIKE ? OR ticket_number LIKE ?", "%"+keyword+"%", "%"+keyword+"%")
	}

	// 分页
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 20
	}

	var total int64
	query.Count(&total)

	offset := (page - 1) * pageSize
	if err := query.Offset(offset).Limit(pageSize).Order("created_at DESC").Find(&tickets).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":    500,
			"message": "获取工单列表失败",
			"error":   err.Error(),
		})
		return
	}

	// 为每个工单查询关联的审批和部署信息
	type TicketWithStatus struct {
		model.Ticket
		ApprovalStatus   string `json:"approval_status"` // pending, approved, rejected
		DeploymentID     string `json:"deployment_id"`
		DeploymentStatus string `json:"deployment_status"` // pending, running, success, failed
	}

	ticketsWithStatus := make([]TicketWithStatus, len(tickets))
	for i, ticket := range tickets {
		ticketsWithStatus[i] = TicketWithStatus{
			Ticket: ticket,
		}

		// 如果工单有审批实例ID，查询审批状态
		if ticket.ApprovalInstanceID != "" {
			var approval model.Approval
			// 尝试通过 external_id 或 id 查找审批
			if err := h.db.Where("external_id = ? OR id = ?", ticket.ApprovalInstanceID, ticket.ApprovalInstanceID).First(&approval).Error; err == nil {
				ticketsWithStatus[i].ApprovalStatus = string(approval.Status)
				ticketsWithStatus[i].DeploymentID = approval.DeploymentID

				// 如果审批有部署ID，查询部署状态
				if approval.DeploymentID != "" {
					var deployment model.Deployment
					if err := h.db.Where("id = ?", approval.DeploymentID).First(&deployment).Error; err == nil {
						ticketsWithStatus[i].DeploymentStatus = deployment.Status
					}
				}
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    0,
		"message": "success",
		"data":    ticketsWithStatus,
		"total":   total,
	})
}

// GetTicket 获取工单详情
func (h *TicketHandler) GetTicket(c *gin.Context) {
	id := c.Param("id")

	var ticket model.Ticket
	if err := h.db.Preload("Template").First(&ticket, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{
				"code":    404,
				"message": "工单不存在",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":    500,
			"message": "获取工单详情失败",
			"error":   err.Error(),
		})
		return
	}

	// 查询关联的审批和部署信息
	type TicketDetailResponse struct {
		model.Ticket
		ApprovalStatus   string                      `json:"approval_status"`
		DeploymentID     string                      `json:"deployment_id"`
		DeploymentStatus string                      `json:"deployment_status"`
		Deployments      []DeploymentWithJenkinsInfo `json:"deployments"` // 关联的部署列表
	}

	response := TicketDetailResponse{
		Ticket:      ticket,
		Deployments: []DeploymentWithJenkinsInfo{}, // 初始化为空数组
	}

	// 查询关联的审批和部署信息
	var foundDeployments []DeploymentWithJenkinsInfo

	// 方式1: 如果工单有审批实例ID，通过审批实例ID查找
	if ticket.ApprovalInstanceID != "" {
		var approval model.Approval
		if err := h.db.Where("external_id = ? OR id = ?", ticket.ApprovalInstanceID, ticket.ApprovalInstanceID).First(&approval).Error; err == nil {
			response.ApprovalStatus = string(approval.Status)
			response.DeploymentID = approval.DeploymentID

			// 如果审批有部署ID，查询部署状态和Jenkins服务器信息
			if approval.DeploymentID != "" {
				var deployment model.Deployment
				if err := h.db.Where("id = ?", approval.DeploymentID).First(&deployment).Error; err == nil {
					response.DeploymentStatus = deployment.Status
					deploymentWithInfo := buildDeploymentWithJenkinsInfo(h.db, deployment)
					foundDeployments = append(foundDeployments, deploymentWithInfo)
				}
			}
		}
	}

	// 方式2: 如果没有找到，尝试通过工单申请人查找类型为deployment的审批记录
	if len(foundDeployments) == 0 {
		var approvals []model.Approval
		// 查找申请人是工单申请人，类型为deployment的审批记录（时间范围扩大到工单创建时间前后24小时内）
		timeRange := ticket.CreatedAt.Add(-24 * time.Hour)
		if err := h.db.Where("applicant_id = ? AND type = ? AND created_at >= ?",
			ticket.ApplicantID, "deployment", timeRange).Order("created_at DESC").Find(&approvals).Error; err == nil {
			for _, approval := range approvals {
				if approval.DeploymentID != "" {
					var deployment model.Deployment
					if err := h.db.Where("id = ?", approval.DeploymentID).First(&deployment).Error; err == nil {
						deploymentWithInfo := buildDeploymentWithJenkinsInfo(h.db, deployment)
						foundDeployments = append(foundDeployments, deploymentWithInfo)
					}
				}
			}
		}
	}

	// 方式3: 如果还是没有找到，尝试通过工单申请人查找最近创建的部署记录（作为备选）
	if len(foundDeployments) == 0 {
		var deployments []model.Deployment
		// 查找创建人是工单申请人的部署记录（时间范围扩大到工单创建时间前后24小时内）
		timeRange := ticket.CreatedAt.Add(-24 * time.Hour)
		if err := h.db.Where("created_by = ? AND created_at >= ?",
			ticket.ApplicantID, timeRange).Order("created_at DESC").Limit(20).Find(&deployments).Error; err == nil {
			for _, deployment := range deployments {
				deploymentWithInfo := buildDeploymentWithJenkinsInfo(h.db, deployment)
				foundDeployments = append(foundDeployments, deploymentWithInfo)
			}
		}
	}

	// 方式4: 如果工单有描述或标题中包含项目名称，尝试通过项目名称查找部署记录
	if len(foundDeployments) == 0 && len(ticket.FormData) > 0 {
		var formData map[string]interface{}
		if err := json.Unmarshal(ticket.FormData, &formData); err == nil {
			// 尝试从表单数据中提取项目名称或服务名称
			var projectName string
			if name, ok := formData["project_name"].(string); ok && name != "" {
				projectName = name
			} else if name, ok := formData["service_name"].(string); ok && name != "" {
				projectName = name
			} else if name, ok := formData["application_name"].(string); ok && name != "" {
				projectName = name
			}

			if projectName != "" {
				var deployments []model.Deployment
				timeRange := ticket.CreatedAt.Add(-24 * time.Hour)
				if err := h.db.Where("project_name = ? AND created_at >= ?",
					projectName, timeRange).Order("created_at DESC").Limit(10).Find(&deployments).Error; err == nil {
					for _, deployment := range deployments {
						deploymentWithInfo := buildDeploymentWithJenkinsInfo(h.db, deployment)
						foundDeployments = append(foundDeployments, deploymentWithInfo)
					}
				}
			}
		}
	}

	response.Deployments = foundDeployments

	c.JSON(http.StatusOK, gin.H{
		"code":    0,
		"message": "success",
		"data":    response,
	})
}

// CreateTicket 创建工单
func (h *TicketHandler) CreateTicket(c *gin.Context) {
	var ticket model.Ticket
	if err := c.ShouldBindJSON(&ticket); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    400,
			"message": "请求参数错误",
			"error":   err.Error(),
		})
		return
	}

	// 生成工单编号
	ticket.TicketNumber = generateTicketNumber()

	// 设置默认值
	if ticket.Status == "" {
		ticket.Status = "draft"
	}
	if ticket.Priority == "" {
		ticket.Priority = "normal"
	}
	// 设置工单类型：如果有 template_id，则为日常工单；否则为发布工单
	if ticket.Type == "" {
		if ticket.TemplateID != nil && *ticket.TemplateID > 0 {
			ticket.Type = "daily"
		} else {
			ticket.Type = "deployment"
		}
	}

	// 如果工单状态是已提交（非草稿），需要验证三方审批配置
	if ticket.Status != "draft" && ticket.TemplateID != nil && *ticket.TemplateID > 0 {
		var template model.FormTemplate
		if err := h.db.First(&template, *ticket.TemplateID).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				c.JSON(http.StatusBadRequest, gin.H{
					"code":    400,
					"message": "工单模板不存在",
				})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{
				"code":    500,
				"message": "获取工单模板失败",
				"error":   err.Error(),
			})
			return
		}

		// 检查三方审批配置
		if len(template.ApprovalConfig) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{
				"code":    400,
				"message": "该工单模板未配置三方审批，请先在\"设计工单\"页面完善三方审批配置后再提交工单",
			})
			return
		}

		// 解析审批配置
		var approvalConfig map[string]interface{}
		if err := json.Unmarshal(template.ApprovalConfig, &approvalConfig); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"code":    400,
				"message": "工单模板的三方审批配置格式错误",
				"error":   err.Error(),
			})
			return
		}

		// 验证审批代码是否存在
		approvalCode, ok := approvalConfig["approval_code"].(string)
		if !ok || approvalCode == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"code":    400,
				"message": "该工单模板未配置三方审批代码，请先在\"设计工单\"页面完善三方审批配置后再提交工单",
			})
			return
		}
	}

	// 从上下文获取当前用户信息（如果中间件设置了）
	if userID, exists := c.Get("user_id"); exists {
		if ticket.ApplicantID == "" {
			ticket.ApplicantID = userID.(string)
		}
	}
	if userName, exists := c.Get("username"); exists {
		if ticket.ApplicantName == "" {
			ticket.ApplicantName = userName.(string)
		}
	}

	if err := h.db.Create(&ticket).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":    500,
			"message": "创建工单失败",
			"error":   err.Error(),
		})
		return
	}

	// 重新加载以获取关联数据（如果 template_id 不为空）
	if ticket.TemplateID != nil && *ticket.TemplateID > 0 {
		if ticket.TemplateID != nil && *ticket.TemplateID > 0 {
			h.db.Preload("Template").First(&ticket, ticket.ID)
		} else {
			h.db.First(&ticket, ticket.ID)
		}
	} else {
		h.db.First(&ticket, ticket.ID)
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    0,
		"message": "success",
		"data":    ticket,
	})
}

// UpdateTicket 更新工单
func (h *TicketHandler) UpdateTicket(c *gin.Context) {
	id := c.Param("id")

	var ticket model.Ticket
	if err := h.db.First(&ticket, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{
				"code":    404,
				"message": "工单不存在",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":    500,
			"message": "获取工单失败",
			"error":   err.Error(),
		})
		return
	}

	var updateData model.Ticket
	if err := c.ShouldBindJSON(&updateData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    400,
			"message": "请求参数错误",
			"error":   err.Error(),
		})
		return
	}

	// 更新字段
	if updateData.Title != "" {
		ticket.Title = updateData.Title
	}
	if updateData.FormData != nil {
		ticket.FormData = updateData.FormData
	}
	if updateData.Status != "" {
		ticket.Status = updateData.Status
	}
	if updateData.Priority != "" {
		ticket.Priority = updateData.Priority
	}

	if err := h.db.Save(&ticket).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":    500,
			"message": "更新工单失败",
			"error":   err.Error(),
		})
		return
	}

	if ticket.TemplateID != nil && *ticket.TemplateID > 0 {
		h.db.Preload("Template").First(&ticket, ticket.ID)
	} else {
		h.db.First(&ticket, ticket.ID)
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    0,
		"message": "success",
		"data":    ticket,
	})
}

// SubmitTicket 提交工单
func (h *TicketHandler) SubmitTicket(c *gin.Context) {
	id := c.Param("id")

	var ticket model.Ticket
	if err := h.db.First(&ticket, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{
				"code":    404,
				"message": "工单不存在",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":    500,
			"message": "获取工单失败",
			"error":   err.Error(),
		})
		return
	}

	if ticket.Status != "draft" {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    400,
			"message": "只能提交草稿状态的工单",
		})
		return
	}

	ticket.Status = "submitted"
	if err := h.db.Save(&ticket).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":    500,
			"message": "提交工单失败",
			"error":   err.Error(),
		})
		return
	}

	if ticket.TemplateID != nil && *ticket.TemplateID > 0 {
		h.db.Preload("Template").First(&ticket, ticket.ID)
	} else {
		h.db.First(&ticket, ticket.ID)
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    0,
		"message": "success",
		"data":    ticket,
	})
}

// CancelTicket 取消工单
func (h *TicketHandler) CancelTicket(c *gin.Context) {
	id := c.Param("id")

	var ticket model.Ticket
	if err := h.db.First(&ticket, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{
				"code":    404,
				"message": "工单不存在",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":    500,
			"message": "获取工单失败",
			"error":   err.Error(),
		})
		return
	}

	if ticket.Status == "approved" || ticket.Status == "rejected" || ticket.Status == "cancelled" {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    400,
			"message": "该状态的工单无法取消",
		})
		return
	}

	ticket.Status = "cancelled"
	if err := h.db.Save(&ticket).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":    500,
			"message": "取消工单失败",
			"error":   err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    0,
		"message": "success",
		"data":    ticket,
	})
}

// GetRenderForm 获取渲染表单（用于编辑）
func (h *TicketHandler) GetRenderForm(c *gin.Context) {
	id := c.Param("id")

	var ticket model.Ticket
	// 先加载工单，然后根据是否有 template_id 决定是否加载模板
	if err := h.db.First(&ticket, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{
				"code":    404,
				"message": "工单不存在",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":    500,
			"message": "获取工单失败",
			"error":   err.Error(),
		})
		return
	}

	// 如果工单有 template_id，加载模板
	if ticket.TemplateID != nil && *ticket.TemplateID > 0 {
		h.db.Preload("Template").First(&ticket, ticket.ID)
	}

	// 如果工单没有模板，返回空 schema
	var schema interface{}
	if ticket.TemplateID != nil && *ticket.TemplateID > 0 && ticket.Template.ID > 0 {
		schema = ticket.Template.Schema
	} else {
		schema = nil
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    0,
		"message": "success",
		"data": gin.H{
			"schema":    schema,
			"form_data": ticket.FormData,
		},
	})
}
