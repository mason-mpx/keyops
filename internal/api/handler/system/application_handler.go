package system

import (
	"net/http"
	"strings"

	"github.com/fisker/zjump-backend/internal/model"
	"github.com/fisker/zjump-backend/internal/repository"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type ApplicationHandler struct {
	repo *repository.ApplicationRepository
}

func NewApplicationHandler(repo *repository.ApplicationRepository) *ApplicationHandler {
	return &ApplicationHandler{repo: repo}
}

// normalizeSrvType 将应用类型转换为大写格式
// 支持的应用类型：SERVER、WEB、MIDDLEWARE、DATAWARE、MOBILE、DATABASE、
// MICROSERVICE、BATCH、SCHEDULER、GATEWAY、CACHE、MESSAGE_QUEUE、BACKEND
// 注意：API 类型已合并到 BACKEND，api 输入会自动转换为 BACKEND
func normalizeSrvType(srvType string) string {
	if srvType == "" {
		return ""
	}
	lower := strings.ToLower(srvType)
	// 处理特殊映射
	switch lower {
	case "server":
		return "SERVER"
	case "web":
		return "WEB"
	case "middleware":
		return "MIDDLEWARE"
	case "dataware", "data_ware", "data-ware":
		return "DATAWARE"
	case "mobile", "app":
		return "MOBILE"
	case "api":
		// API 类型已合并到 BACKEND
		return "BACKEND"
	case "database", "db":
		return "DATABASE"
	case "microservice", "micro_service", "micro-service":
		return "MICROSERVICE"
	case "batch":
		return "BATCH"
	case "scheduler", "cron":
		return "SCHEDULER"
	case "gateway":
		return "GATEWAY"
	case "cache", "redis", "memcached":
		return "CACHE"
	case "message_queue", "message-queue", "mq", "messagequeue":
		return "MESSAGE_QUEUE"
	case "backend", "back-end", "back_end":
		return "BACKEND"
	default:
		// 如果已经是其他格式，直接返回大写
		return strings.ToUpper(srvType)
	}
}

// ListApplications 获取应用列表
// @Summary 获取应用列表
// @Tags applications
// @Produce json
// @Param name query string false "应用名称（模糊搜索）"
// @Param org query string false "事业部"
// @Param department query string false "部门"
// @Param status query string false "应用状态"
// @Param srvType query string false "应用类型"
// @Param virtualTech query string false "虚拟化技术"
// @Param site query string false "应用站点"
// @Param isCritical query boolean false "是否核心应用"
// @Success 200 {object} model.Response
// @Router /api/applications [get]
func (h *ApplicationHandler) ListApplications(c *gin.Context) {
	params := make(map[string]interface{})

	if name := c.Query("name"); name != "" {
		params["name"] = name
	}
	if org := c.Query("org"); org != "" {
		params["org"] = org
	}
	if department := c.Query("department"); department != "" {
		params["department"] = department
	}
	if status := c.Query("status"); status != "" {
		params["status"] = status
	}
	if srvType := c.Query("srvType"); srvType != "" {
		params["srvType"] = normalizeSrvType(srvType)
	}
	if virtualTech := c.Query("virtualTech"); virtualTech != "" {
		params["virtualTech"] = virtualTech
	}
	if site := c.Query("site"); site != "" {
		params["site"] = site
	}
	if isCritical := c.Query("isCritical"); isCritical == "true" {
		params["isCritical"] = true
	} else if isCritical == "false" {
		params["isCritical"] = false
	}

	// 权限控制：从 token 中获取用户ID和角色
	// 管理员可以看到所有应用，普通用户只能看到自己作为负责人的应用
	role, exists := c.Get("role")
	isAdmin := exists && role == "admin"
	
	// 获取当前用户ID（从 token 中获取，由 AuthMiddleware 设置）
	var currentUserID string
	if userID, exists := c.Get("user_id"); exists {
		if userIDStr, ok := userID.(string); ok && userIDStr != "" {
			currentUserID = userIDStr
		}
	} else if userID, exists := c.Get("userID"); exists {
		// 兼容不同的字段名
		if userIDStr, ok := userID.(string); ok && userIDStr != "" {
			currentUserID = userIDStr
		}
	}

	var apps []model.Application
	var err error

	// 使用 SearchWithUserFilter 方法，它会根据 isAdmin 和 userID 自动进行权限过滤
	if len(params) > 0 {
		apps, err = h.repo.SearchWithUserFilter(params, currentUserID, isAdmin)
	} else {
		// 如果没有其他查询参数
		if isAdmin {
			// 管理员：返回所有应用
			apps, err = h.repo.FindAll()
		} else if currentUserID != "" {
			// 普通用户：使用空参数但带上用户过滤
			apps, err = h.repo.SearchWithUserFilter(map[string]interface{}{}, currentUserID, false)
		} else {
			// 无法获取用户ID，返回空列表
			apps = []model.Application{}
		}
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, model.Response{
			Code:    http.StatusInternalServerError,
			Message: "Failed to fetch applications",
			Data:    nil,
		})
		return
	}

	c.JSON(http.StatusOK, model.Response{
		Code:    http.StatusOK,
		Message: "Success",
		Data:    apps,
	})
}

// GetApplication 获取单个应用
// @Summary 获取单个应用
// @Tags applications
// @Produce json
// @Param id path string true "Application ID"
// @Success 200 {object} model.Response
// @Router /api/applications/{id} [get]
func (h *ApplicationHandler) GetApplication(c *gin.Context) {
	id := c.Param("id")

	app, err := h.repo.FindByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, model.Response{
			Code:    http.StatusNotFound,
			Message: "Application not found",
			Data:    nil,
		})
		return
	}

	c.JSON(http.StatusOK, model.Response{
		Code:    http.StatusOK,
		Message: "Success",
		Data:    app,
	})
}

// CreateApplication 创建应用
// @Summary 创建应用
// @Tags applications
// @Accept json
// @Produce json
// @Param application body model.CreateApplicationRequest true "Application"
// @Success 200 {object} model.Response
// @Router /api/applications [post]
func (h *ApplicationHandler) CreateApplication(c *gin.Context) {
	var req model.CreateApplicationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.Response{
			Code:    http.StatusBadRequest,
			Message: "Invalid request body: " + err.Error(),
			Data:    nil,
		})
		return
	}

	// 检查应用名称是否已存在
	exists, err := h.repo.CheckNameExists(req.Name, "")
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.Response{
			Code:    http.StatusInternalServerError,
			Message: "Failed to check application name",
			Data:    nil,
		})
		return
	}
	if exists {
		c.JSON(http.StatusBadRequest, model.Response{
			Code:    http.StatusBadRequest,
			Message: "Application name already exists",
			Data:    nil,
		})
		return
	}

	// 设置默认状态
	if req.Status == "" {
		req.Status = "Initializing"
	}

	// 规范化应用类型为大写
	normalizedSrvType := normalizeSrvType(req.SrvType)
	if normalizedSrvType == "" {
		c.JSON(http.StatusBadRequest, model.Response{
			Code:    http.StatusBadRequest,
			Message: "Invalid srvType",
			Data:    nil,
		})
		return
	}

	app := &model.Application{
		ID:          uuid.New().String(),
		Org:         req.Org,
		LineOfBiz:   req.LineOfBiz,
		Name:        req.Name,
		IsCritical:  req.IsCritical,
		SrvType:     normalizedSrvType,
		VirtualTech: req.VirtualTech,
		Status:      req.Status,
		Site:        req.Site,
		Department:  req.Department,
		Description: req.Description,
		OnlineAt:    req.OnlineAt,
		OfflineAt:   req.OfflineAt,
		GitURL:      req.GitURL,
		OpsOwners:   req.OpsOwners,
		TestOwners:  req.TestOwners,
		DevOwners:   req.DevOwners,
	}

	if err := h.repo.Create(app); err != nil {
		c.JSON(http.StatusInternalServerError, model.Response{
			Code:    http.StatusInternalServerError,
			Message: "Failed to create application: " + err.Error(),
			Data:    nil,
		})
		return
	}

	c.JSON(http.StatusOK, model.Response{
		Code:    http.StatusOK,
		Message: "Application created successfully",
		Data:    app,
	})
}

// UpdateApplication 更新应用
// @Summary 更新应用
// @Tags applications
// @Accept json
// @Produce json
// @Param id path string true "Application ID"
// @Param application body model.UpdateApplicationRequest true "Application"
// @Success 200 {object} model.Response
// @Router /api/applications/{id} [put]
func (h *ApplicationHandler) UpdateApplication(c *gin.Context) {
	id := c.Param("id")

	var req model.UpdateApplicationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.Response{
			Code:    http.StatusBadRequest,
			Message: "Invalid request body: " + err.Error(),
			Data:    nil,
		})
		return
	}

	// 检查应用是否存在
	app, err := h.repo.FindByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, model.Response{
			Code:    http.StatusNotFound,
			Message: "Application not found",
			Data:    nil,
		})
		return
	}

	// 如果名称改变，检查新名称是否已存在
	if req.Name != app.Name {
		exists, err := h.repo.CheckNameExists(req.Name, id)
		if err != nil {
			c.JSON(http.StatusInternalServerError, model.Response{
				Code:    http.StatusInternalServerError,
				Message: "Failed to check application name",
				Data:    nil,
			})
			return
		}
		if exists {
			c.JSON(http.StatusBadRequest, model.Response{
				Code:    http.StatusBadRequest,
				Message: "Application name already exists",
				Data:    nil,
			})
			return
		}
	}

	// 规范化应用类型为大写
	normalizedSrvType := normalizeSrvType(req.SrvType)
	if normalizedSrvType == "" {
		c.JSON(http.StatusBadRequest, model.Response{
			Code:    http.StatusBadRequest,
			Message: "Invalid srvType",
			Data:    nil,
		})
		return
	}

	// 更新应用信息
	app.Org = req.Org
	app.LineOfBiz = req.LineOfBiz
	app.Name = req.Name
	app.IsCritical = req.IsCritical
	app.SrvType = normalizedSrvType
	app.VirtualTech = req.VirtualTech
	if req.Status != "" {
		app.Status = req.Status
	}
	app.Site = req.Site
	app.Department = req.Department
	app.Description = req.Description
	app.OnlineAt = req.OnlineAt
	app.OfflineAt = req.OfflineAt
	app.GitURL = req.GitURL
	app.OpsOwners = req.OpsOwners
	app.TestOwners = req.TestOwners
	app.DevOwners = req.DevOwners

	if err := h.repo.Update(app); err != nil {
		c.JSON(http.StatusInternalServerError, model.Response{
			Code:    http.StatusInternalServerError,
			Message: "Failed to update application: " + err.Error(),
			Data:    nil,
		})
		return
	}

	c.JSON(http.StatusOK, model.Response{
		Code:    http.StatusOK,
		Message: "Application updated successfully",
		Data:    app,
	})
}

// DeleteApplication 删除应用
// @Summary 删除应用
// @Tags applications
// @Produce json
// @Param id path string true "Application ID"
// @Success 200 {object} model.Response
// @Router /api/applications/{id} [delete]
func (h *ApplicationHandler) DeleteApplication(c *gin.Context) {
	id := c.Param("id")

	// 检查应用是否存在
	_, err := h.repo.FindByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, model.Response{
			Code:    http.StatusNotFound,
			Message: "Application not found",
			Data:    nil,
		})
		return
	}

	if err := h.repo.Delete(id); err != nil {
		c.JSON(http.StatusInternalServerError, model.Response{
			Code:    http.StatusInternalServerError,
			Message: "Failed to delete application: " + err.Error(),
			Data:    nil,
		})
		return
	}

	c.JSON(http.StatusOK, model.Response{
		Code:    http.StatusOK,
		Message: "Application deleted successfully",
		Data:    nil,
	})
}
