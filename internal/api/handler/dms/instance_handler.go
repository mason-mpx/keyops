package dms

import (
	"net/http"
	"strconv"

	"github.com/fisker/zjump-backend/internal/model"
	"github.com/fisker/zjump-backend/internal/service/dms"
	"github.com/gin-gonic/gin"
)

type InstanceHandler struct {
	instanceService *dms.InstanceService
}

func NewInstanceHandler(instanceService *dms.InstanceService) *InstanceHandler {
	return &InstanceHandler{
		instanceService: instanceService,
	}
}

// ListInstances 获取实例列表
// @Summary 获取数据库实例列表
// @Tags DMS
// @Accept json
// @Produce json
// @Param page query int false "页码" default(1)
// @Param page_size query int false "每页数量" default(10)
// @Param db_type query string false "数据库类型"
// @Param is_enabled query bool false "是否启用"
// @Param name query string false "实例名称（模糊搜索）"
// @Success 200 {object} model.Response{data=object{list=[]model.DBInstance,total=int64}}
// @Router /api/dms/instances [get]
func (h *InstanceHandler) ListInstances(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "10"))
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 10
	}

	offset := (page - 1) * pageSize

	filters := make(map[string]interface{})
	if dbType := c.Query("db_type"); dbType != "" {
		filters["db_type"] = dbType
	}
	if isEnabled := c.Query("is_enabled"); isEnabled != "" {
		filters["is_enabled"] = isEnabled == "true"
	}
	if name := c.Query("name"); name != "" {
		filters["name"] = name
	}

	instances, total, err := h.instanceService.ListInstances(offset, pageSize, filters)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.Error(500, "获取实例列表失败: "+err.Error()))
		return
	}

	c.JSON(http.StatusOK, model.Success(gin.H{
		"list":  instances,
		"total": total,
	}))
}

// CreateInstance 创建实例
// @Summary 创建数据库实例
// @Tags DMS
// @Accept json
// @Produce json
// @Param request body dms.CreateInstanceRequest true "实例信息"
// @Success 200 {object} model.Response{data=model.DBInstance}
// @Router /api/dms/instances [post]
func (h *InstanceHandler) CreateInstance(c *gin.Context) {
	var req dms.CreateInstanceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.Error(400, "参数错误: "+err.Error()))
		return
	}

	// 对于非 Redis 和 MongoDB 类型，密码是必填的
	if req.DBType != "redis" && req.DBType != "mongodb" && req.Password == "" {
		c.JSON(http.StatusBadRequest, model.Error(400, "密码是必填项（Redis 和 MongoDB 类型除外）"))
		return
	}

	userID, _ := c.Get("userID")
	userIDStr := userID.(string)

	instance, err := h.instanceService.CreateInstance(&req, userIDStr)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.Error(500, "创建实例失败: "+err.Error()))
		return
	}

	c.JSON(http.StatusOK, model.Success(instance))
}

// GetInstance 获取实例详情
// @Summary 获取数据库实例详情
// @Tags DMS
// @Accept json
// @Produce json
// @Param id path int true "实例ID"
// @Success 200 {object} model.Response{data=model.DBInstance}
// @Router /api/dms/instances/:id [get]
func (h *InstanceHandler) GetInstance(c *gin.Context) {
	var uriParams struct {
		ID uint `uri:"id" binding:"required"`
	}
	if err := c.ShouldBindUri(&uriParams); err != nil {
		c.JSON(http.StatusBadRequest, model.Error(400, "参数错误: "+err.Error()))
		return
	}

	instance, err := h.instanceService.GetInstance(uriParams.ID)
	if err != nil {
		c.JSON(http.StatusNotFound, model.Error(404, "实例不存在"))
		return
	}

	c.JSON(http.StatusOK, model.Success(instance))
}

// UpdateInstance 更新实例
// @Summary 更新数据库实例
// @Tags DMS
// @Accept json
// @Produce json
// @Param id path int true "实例ID"
// @Param request body dms.UpdateInstanceRequest true "实例信息"
// @Success 200 {object} model.Response{data=model.DBInstance}
// @Router /api/dms/instances/:id [put]
func (h *InstanceHandler) UpdateInstance(c *gin.Context) {
	var uriParams struct {
		ID uint `uri:"id" binding:"required"`
	}
	if err := c.ShouldBindUri(&uriParams); err != nil {
		c.JSON(http.StatusBadRequest, model.Error(400, "参数错误: "+err.Error()))
		return
	}

	var req dms.UpdateInstanceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.Error(400, "参数错误: "+err.Error()))
		return
	}

	userID, _ := c.Get("userID")
	userIDStr := userID.(string)

	instance, err := h.instanceService.UpdateInstance(uriParams.ID, &req, userIDStr)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.Error(500, "更新实例失败: "+err.Error()))
		return
	}

	c.JSON(http.StatusOK, model.Success(instance))
}

// DeleteInstance 删除实例
// @Summary 删除数据库实例
// @Tags DMS
// @Accept json
// @Produce json
// @Param id path int true "实例ID"
// @Success 200 {object} model.Response
// @Router /api/dms/instances/:id [delete]
func (h *InstanceHandler) DeleteInstance(c *gin.Context) {
	var uriParams struct {
		ID uint `uri:"id" binding:"required"`
	}
	if err := c.ShouldBindUri(&uriParams); err != nil {
		c.JSON(http.StatusBadRequest, model.Error(400, "参数错误: "+err.Error()))
		return
	}

	if err := h.instanceService.DeleteInstance(uriParams.ID); err != nil {
		c.JSON(http.StatusInternalServerError, model.Error(500, "删除实例失败: "+err.Error()))
		return
	}

	c.JSON(http.StatusOK, model.Success(nil))
}

// TestConnection 测试连接
// @Summary 测试数据库连接
// @Tags DMS
// @Accept json
// @Produce json
// @Param id path int true "实例ID"
// @Success 200 {object} model.Response
// @Router /api/dms/instances/:id/test [post]
func (h *InstanceHandler) TestConnection(c *gin.Context) {
	var uriParams struct {
		ID uint `uri:"id" binding:"required"`
	}
	if err := c.ShouldBindUri(&uriParams); err != nil {
		c.JSON(http.StatusBadRequest, model.Error(400, "参数错误: "+err.Error()))
		return
	}

	if err := h.instanceService.TestConnection(uriParams.ID); err != nil {
		c.JSON(http.StatusBadRequest, model.Error(400, "连接测试失败: "+err.Error()))
		return
	}

	c.JSON(http.StatusOK, model.Success(gin.H{"message": "连接成功"}))
}
