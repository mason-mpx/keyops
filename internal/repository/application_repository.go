package repository

import (
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

