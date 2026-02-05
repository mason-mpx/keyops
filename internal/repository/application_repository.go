package repository

import (
	"fmt"
	"github.com/fisker/zjump-backend/internal/model"
	"gorm.io/gorm"
)

type ApplicationRepository struct {
	db *gorm.DB
}

func NewApplicationRepository(db *gorm.DB) *ApplicationRepository {
	return &ApplicationRepository{db: db}
}

// Create 创建应用
func (r *ApplicationRepository) Create(app *model.Application) error {
	return r.db.Create(app).Error
}

// Update 更新应用
func (r *ApplicationRepository) Update(app *model.Application) error {
	return r.db.Model(&model.Application{}).
		Where("id = ?", app.ID).
		Omit("created_at").
		Updates(app).Error
}

// Delete 删除应用
func (r *ApplicationRepository) Delete(id string) error {
	return r.db.Delete(&model.Application{}, "id = ?", id).Error
}

// FindByID 根据ID查找应用
func (r *ApplicationRepository) FindByID(id string) (*model.Application, error) {
	var app model.Application
	err := r.db.Where("id = ?", id).First(&app).Error
	if err != nil {
		return nil, err
	}
	return &app, nil
}

// FindAll 查找所有应用
func (r *ApplicationRepository) FindAll() ([]model.Application, error) {
	var apps []model.Application
	err := r.db.Order("updated_at DESC").Find(&apps).Error
	return apps, err
}

// FindByOrg 根据事业部查找应用
func (r *ApplicationRepository) FindByOrg(org string) ([]model.Application, error) {
	var apps []model.Application
	err := r.db.Where("org = ?", org).Order("updated_at DESC").Find(&apps).Error
	return apps, err
}

// FindByDepartment 根据部门查找应用
func (r *ApplicationRepository) FindByDepartment(department string) ([]model.Application, error) {
	var apps []model.Application
	err := r.db.Where("department = ?", department).Order("updated_at DESC").Find(&apps).Error
	return apps, err
}

// FindByStatus 根据状态查找应用
func (r *ApplicationRepository) FindByStatus(status string) ([]model.Application, error) {
	var apps []model.Application
	err := r.db.Where("status = ?", status).Order("updated_at DESC").Find(&apps).Error
	return apps, err
}

// FindBySrvType 根据应用类型查找应用
func (r *ApplicationRepository) FindBySrvType(srvType string) ([]model.Application, error) {
	var apps []model.Application
	err := r.db.Where("srv_type = ?", srvType).Order("updated_at DESC").Find(&apps).Error
	return apps, err
}

// Search 搜索应用（支持多条件）
func (r *ApplicationRepository) Search(params map[string]interface{}) ([]model.Application, error) {
	var apps []model.Application
	query := r.db.Model(&model.Application{})

	if name, ok := params["name"].(string); ok && name != "" {
		query = query.Where("name LIKE ?", "%"+name+"%")
	}
	if org, ok := params["org"].(string); ok && org != "" {
		query = query.Where("org = ?", org)
	}
	if department, ok := params["department"].(string); ok && department != "" {
		query = query.Where("department = ?", department)
	}
	if status, ok := params["status"].(string); ok && status != "" {
		query = query.Where("status = ?", status)
	}
	if srvType, ok := params["srvType"].(string); ok && srvType != "" {
		query = query.Where("srv_type = ?", srvType)
	}
	if virtualTech, ok := params["virtualTech"].(string); ok && virtualTech != "" {
		query = query.Where("virtual_tech = ?", virtualTech)
	}
	if site, ok := params["site"].(string); ok && site != "" {
		query = query.Where("site = ?", site)
	}
	if isCritical, ok := params["isCritical"].(bool); ok {
		query = query.Where("is_critical = ?", isCritical)
	}

	err := query.Order("updated_at DESC").Find(&apps).Error
	return apps, err
}

// SearchWithUserFilter 搜索应用（支持多条件和用户权限过滤）
// userID: 当前用户ID，如果为空则不进行用户过滤
// isAdmin: 是否为管理员，管理员可以看到所有应用
func (r *ApplicationRepository) SearchWithUserFilter(params map[string]interface{}, userID string, isAdmin bool) ([]model.Application, error) {
	var apps []model.Application
	query := r.db.Model(&model.Application{})

	if name, ok := params["name"].(string); ok && name != "" {
		query = query.Where("name LIKE ?", "%"+name+"%")
	}
	if org, ok := params["org"].(string); ok && org != "" {
		query = query.Where("org = ?", org)
	}
	if department, ok := params["department"].(string); ok && department != "" {
		query = query.Where("department = ?", department)
	}
	if status, ok := params["status"].(string); ok && status != "" {
		query = query.Where("status = ?", status)
	}
	if srvType, ok := params["srvType"].(string); ok && srvType != "" {
		query = query.Where("srv_type = ?", srvType)
	}
	if virtualTech, ok := params["virtualTech"].(string); ok && virtualTech != "" {
		query = query.Where("virtual_tech = ?", virtualTech)
	}
	if site, ok := params["site"].(string); ok && site != "" {
		query = query.Where("site = ?", site)
	}
	if isCritical, ok := params["isCritical"].(bool); ok {
		query = query.Where("is_critical = ?", isCritical)
	}

	// 权限过滤：普通用户只能看到自己作为负责人的应用（运维/测试/研发负责人）
	if !isAdmin && userID != "" {
		query = r.addUserFilter(query, userID)
	}

	err := query.Order("updated_at DESC").Find(&apps).Error
	return apps, err
}

// addUserFilter 添加用户过滤条件（检查用户是否在运维/测试/研发负责人中）
// 数据库字段 ops_owners、test_owners、dev_owners 存储为 JSON/JSONB 字符串数组格式，例如：["user-id-1", "user-id-2"]
// userID: 当前用户ID（字符串类型，varchar(36)）
func (r *ApplicationRepository) addUserFilter(query *gorm.DB, userID string) *gorm.DB {
	// 根据数据库类型使用不同的 JSON 查询语法
	if r.db.Dialector.Name() == "postgres" {
		// PostgreSQL: 使用 JSONB @> 操作符
		// 检查用户是否在 ops_owners、test_owners 或 dev_owners 中
		// 格式：["userID"] 表示包含该用户ID的数组
		// 例如：如果 ops_owners = ["user1", "user2"]，查询 ops_owners::jsonb @> '["user1"]' 会返回 true
		userIDArray := fmt.Sprintf(`["%s"]`, userID)
		return query.Where(
			"ops_owners::jsonb @> ? OR test_owners::jsonb @> ? OR dev_owners::jsonb @> ?",
			userIDArray,
			userIDArray,
			userIDArray,
		)
	} else {
		// MySQL: 使用 JSON_CONTAINS
		// JSON_CONTAINS 检查 JSON 文档中是否包含指定的值
		// 格式："userID" 表示要查找的字符串值
		// 例如：如果 ops_owners = ["user1", "user2"]，查询 JSON_CONTAINS(ops_owners, '"user1"') 会返回 1（true）
		userIDJSON := fmt.Sprintf(`"%s"`, userID)
		return query.Where(
			"JSON_CONTAINS(ops_owners, ?) OR JSON_CONTAINS(test_owners, ?) OR JSON_CONTAINS(dev_owners, ?)",
			userIDJSON,
			userIDJSON,
			userIDJSON,
		)
	}
}

// CheckNameExists 检查应用名称是否存在
func (r *ApplicationRepository) CheckNameExists(name string, excludeID string) (bool, error) {
	var count int64
	query := r.db.Model(&model.Application{}).Where("name = ?", name)
	if excludeID != "" {
		query = query.Where("id != ?", excludeID)
	}
	err := query.Count(&count).Error
	return count > 0, err
}

