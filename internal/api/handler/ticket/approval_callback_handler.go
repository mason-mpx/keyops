package ticket

import (
	"fmt"
	"net/http"
	"time"

	"github.com/fisker/zjump-backend/internal/model"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// ApprovalCallbackHandler 审批回调处理器
type ApprovalCallbackHandler struct {
	db *gorm.DB
}

// NewApprovalCallbackHandler 创建审批回调处理器
func NewApprovalCallbackHandler(db *gorm.DB) *ApprovalCallbackHandler {
	return &ApprovalCallbackHandler{
		db: db,
	}
}

// FeishuCallbackRequest 飞书回调请求结构
type FeishuCallbackRequest struct {
	Type      string `json:"type"`
	AppID     string `json:"app_id"`
	TenantKey string `json:"tenant_key"`
	Token     string `json:"token"`
	Challenge string `json:"challenge"`
	Header    struct {
		EventType  string `json:"event_type"`
		Token      string `json:"token"`
		CreateTime string `json:"create_time"`
		EventID    string `json:"event_id"`
		AppID      string `json:"app_id"`
		TenantKey  string `json:"tenant_key"`
	} `json:"header"`
	Event struct {
		AppID        string `json:"app_id"`
		TenantKey    string `json:"tenant_key"`
		Type         string `json:"type"`
		InstanceCode string `json:"instance_code"`
		UserID       string `json:"user_id"`
		OpenID       string `json:"open_id"`
		StartTime    int64  `json:"start_time"`
		EndTime      int64  `json:"end_time"`
		Status       string `json:"status"`
		Form         string `json:"form"`
		TaskID       string `json:"task_id"`
		Comment      string `json:"comment"`
		OperateTime  int64  `json:"operate_time"`
		Operator     struct {
			UserID string `json:"user_id"`
			OpenID string `json:"open_id"`
		} `json:"operator"`
	} `json:"event"`
}

// DingTalkCallbackRequest 钉钉回调请求结构
type DingTalkCallbackRequest struct {
	EventType             string `json:"eventType"`
	ProcessInstanceID     string `json:"processInstanceId"`
	CorpID                string `json:"corpId"`
	EventTime             int64  `json:"eventTime"`
	Type                  string `json:"type"`
	Title                 string `json:"title"`
	Content               string `json:"content"`
	URL                   string `json:"url"`
	ProcessCode           string `json:"processCode"`
	BizCategoryID         string `json:"bizCategoryId"`
	BizType               string `json:"bizType"`
	TitleInEnglish        string `json:"titleInEnglish"`
	BizNumber             string `json:"bizNumber"`
	MainProcessInstanceID string `json:"mainProcessInstanceId"`
	Data                  struct {
		ProcessInstanceID   string `json:"processInstanceId"`
		OriginatorUserID    string `json:"originatorUserId"`
		OriginatorDeptID    string `json:"originatorDeptId"`
		Title               string `json:"title"`
		CreateTime          string `json:"createTime"`
		FinishTime          string `json:"finishTime"`
		Status              string `json:"status"`
		Result              string `json:"result"`
		BusinessID          string `json:"businessId"`
		FormComponentValues []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"formComponentValues"`
		OperationRecords []struct {
			UserID          string `json:"userId"`
			Date            string `json:"date"`
			OperationType   string `json:"operationType"`
			OperationResult string `json:"operationResult"`
			Remark          string `json:"remark"`
		} `json:"operationRecords"`
		Tasks []struct {
			UserID     string `json:"userId"`
			TaskID     string `json:"taskId"`
			CreateTime string `json:"createTime"`
			FinishTime string `json:"finishTime"`
			TaskResult string `json:"taskResult"`
			TaskStatus string `json:"taskStatus"`
		} `json:"tasks"`
	} `json:"data"`
}

// WeChatCallbackRequest 企业微信回调请求结构
type WeChatCallbackRequest struct {
	ToUserName   string `json:"ToUserName"`
	FromUserName string `json:"FromUserName"`
	CreateTime   int64  `json:"CreateTime"`
	MsgType      string `json:"MsgType"`
	Event        string `json:"Event"`
	EventKey     string `json:"EventKey"`
	AgentID      int    `json:"AgentID"`
	Content      struct {
		ProcessInstanceID string `json:"process_instance_id"`
		ProcessCode       string `json:"process_code"`
		ProcessType       string `json:"process_type"`
		Title             string `json:"title"`
		CreateTime        int64  `json:"create_time"`
		FinishTime        int64  `json:"finish_time"`
		Status            string `json:"status"`
		Result            string `json:"result"`
		FormData          []struct {
			Title string `json:"title"`
			Value string `json:"value"`
		} `json:"form_data"`
		ApproverInfo []struct {
			UserID string `json:"userid"`
			Status string `json:"status"`
		} `json:"approver_info"`
	} `json:"content"`
}

// HandleFeishuCallback 处理飞书审批回调
func (h *ApprovalCallbackHandler) HandleFeishuCallback(c *gin.Context) {
	var req FeishuCallbackRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	// 处理URL验证
	if req.Type == "url_verification" {
		c.JSON(http.StatusOK, gin.H{"challenge": req.Challenge})
		return
	}

	// 处理审批事件
	if req.Header.EventType == "approval_instance" {
		err := h.handleFeishuApprovalEvent(&req)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "success"})
}

// HandleDingTalkCallback 处理钉钉审批回调
func (h *ApprovalCallbackHandler) HandleDingTalkCallback(c *gin.Context) {
	var req DingTalkCallbackRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	// 处理审批事件
	if req.EventType == "bpms_task_change" || req.EventType == "bpms_instance_change" {
		err := h.handleDingTalkApprovalEvent(&req)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "success"})
}

// HandleWeChatCallback 处理企业微信审批回调
func (h *ApprovalCallbackHandler) HandleWeChatCallback(c *gin.Context) {
	var req WeChatCallbackRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	// 处理审批事件
	if req.Event == "sys_approval_change" {
		err := h.handleWeChatApprovalEvent(&req)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "success"})
}

// handleFeishuApprovalEvent 处理飞书审批事件
func (h *ApprovalCallbackHandler) handleFeishuApprovalEvent(req *FeishuCallbackRequest) error {
	// 查找对应的审批记录
	var approval model.Approval
	err := h.db.Where("external_id = ?", req.Event.InstanceCode).First(&approval).Error
	if err != nil {
		return fmt.Errorf("未找到对应的审批记录: %v", err)
	}

	// 更新审批状态
	status := h.mapFeishuStatus(req.Event.Status)
	approval.Status = status
	approval.UpdatedAt = time.Now()

	// 如果审批完成，设置完成时间
	if status == model.ApprovalStatusApproved {
		approval.ApprovedAt = &time.Time{}
		*approval.ApprovedAt = time.Unix(req.Event.EndTime/1000, 0)
	} else if status == model.ApprovalStatusRejected {
		approval.RejectedAt = &time.Time{}
		*approval.RejectedAt = time.Unix(req.Event.EndTime/1000, 0)
	}

	// 保存更新
	return h.db.Save(&approval).Error
}

// handleDingTalkApprovalEvent 处理钉钉审批事件
func (h *ApprovalCallbackHandler) handleDingTalkApprovalEvent(req *DingTalkCallbackRequest) error {
	// 查找对应的审批记录
	var approval model.Approval
	err := h.db.Where("external_id = ?", req.ProcessInstanceID).First(&approval).Error
	if err != nil {
		return fmt.Errorf("未找到对应的审批记录: %v", err)
	}

	// 更新审批状态
	status := h.mapDingTalkStatus(req.Data.Status)
	approval.Status = status
	approval.UpdatedAt = time.Now()

	// 如果审批完成，设置完成时间
	if status == model.ApprovalStatusApproved {
		approval.ApprovedAt = &time.Time{}
		if req.Data.FinishTime != "" {
			if finishTime, err := time.Parse("2006-01-02 15:04:05", req.Data.FinishTime); err == nil {
				*approval.ApprovedAt = finishTime
			}
		}
	} else if status == model.ApprovalStatusRejected {
		approval.RejectedAt = &time.Time{}
		if req.Data.FinishTime != "" {
			if finishTime, err := time.Parse("2006-01-02 15:04:05", req.Data.FinishTime); err == nil {
				*approval.RejectedAt = finishTime
			}
		}
	}

	// 保存更新
	return h.db.Save(&approval).Error
}

// handleWeChatApprovalEvent 处理企业微信审批事件
func (h *ApprovalCallbackHandler) handleWeChatApprovalEvent(req *WeChatCallbackRequest) error {
	// 查找对应的审批记录
	var approval model.Approval
	err := h.db.Where("external_id = ?", req.Content.ProcessInstanceID).First(&approval).Error
	if err != nil {
		return fmt.Errorf("未找到对应的审批记录: %v", err)
	}

	// 更新审批状态
	status := h.mapWeChatStatus(req.Content.Status)
	approval.Status = status
	approval.UpdatedAt = time.Now()

	// 如果审批完成，设置完成时间
	if status == model.ApprovalStatusApproved {
		approval.ApprovedAt = &time.Time{}
		if req.Content.FinishTime > 0 {
			*approval.ApprovedAt = time.Unix(req.Content.FinishTime, 0)
		}
	} else if status == model.ApprovalStatusRejected {
		approval.RejectedAt = &time.Time{}
		if req.Content.FinishTime > 0 {
			*approval.RejectedAt = time.Unix(req.Content.FinishTime, 0)
		}
	}

	// 保存更新
	return h.db.Save(&approval).Error
}

// mapFeishuStatus 映射飞书状态到系统状态
func (h *ApprovalCallbackHandler) mapFeishuStatus(feishuStatus string) model.ApprovalStatus {
	switch feishuStatus {
	case "PENDING":
		return model.ApprovalStatusPending
	case "APPROVED":
		return model.ApprovalStatusApproved
	case "REJECTED":
		return model.ApprovalStatusRejected
	case "CANCELLED":
		return model.ApprovalStatusCanceled
	default:
		return model.ApprovalStatusPending
	}
}

// mapDingTalkStatus 映射钉钉状态到系统状态
func (h *ApprovalCallbackHandler) mapDingTalkStatus(dingTalkStatus string) model.ApprovalStatus {
	switch dingTalkStatus {
	case "RUNNING":
		return model.ApprovalStatusPending
	case "COMPLETED":
		return model.ApprovalStatusApproved
	case "TERMINATED":
		return model.ApprovalStatusRejected
	case "CANCELED":
		return model.ApprovalStatusCanceled
	default:
		return model.ApprovalStatusPending
	}
}

// mapWeChatStatus 映射企业微信状态到系统状态
func (h *ApprovalCallbackHandler) mapWeChatStatus(weChatStatus string) model.ApprovalStatus {
	switch weChatStatus {
	case "1": // 审批中
		return model.ApprovalStatusPending
	case "2": // 已通过
		return model.ApprovalStatusApproved
	case "3": // 已驳回
		return model.ApprovalStatusRejected
	case "4": // 已撤销
		return model.ApprovalStatusCanceled
	default:
		return model.ApprovalStatusPending
	}
}
