package models

import (
	"errors"
	"time"

	log "github.com/gophish/gophish/logger"
	"github.com/jinzhu/gorm"
)

// ExtractedLead represents an email address extracted from an SMTP profile's mailbox
type ExtractedLead struct {
	Id                int64     `json:"id" gorm:"column:id; primary_key:yes"`
	SMTPId            int64     `json:"smtp_id" gorm:"column:smtp_id"`
	UserId            int64     `json:"-" gorm:"column:user_id"`
	Email             string    `json:"email" gorm:"column:email"`
	Name              string    `json:"name,omitempty" gorm:"column:name"`
	Source            string    `json:"source" gorm:"column:source"` // 'inbox', 'sent', 'all_mail'
	ExtractedAt       time.Time `json:"extracted_at" gorm:"column:extracted_at"`
	ImportedToGroupId int64     `json:"imported_to_group_id,omitempty" gorm:"column:imported_to_group_id"`
}

// LeadExtractionJob represents a background job for extracting leads from a mailbox
type LeadExtractionJob struct {
	Id              int64     `json:"id" gorm:"column:id; primary_key:yes"`
	SMTPId          int64     `json:"smtp_id" gorm:"column:smtp_id"`
	UserId          int64     `json:"-" gorm:"column:user_id"`
	Status          string    `json:"status" gorm:"column:status"`   // 'pending', 'running', 'completed', 'failed'
	Folders         string    `json:"folders" gorm:"column:folders"` // JSON array of folders
	DaysBack        int       `json:"days_back" gorm:"column:days_back"`
	TotalEmails     int       `json:"total_emails" gorm:"column:total_emails"`
	ProcessedEmails int       `json:"processed_emails" gorm:"column:processed_emails"`
	LeadsFound      int       `json:"leads_found" gorm:"column:leads_found"`
	ErrorMessage    string    `json:"error_message,omitempty" gorm:"column:error_message"`
	StartedAt       time.Time `json:"started_at,omitempty" gorm:"column:started_at"`
	CompletedAt     time.Time `json:"completed_at,omitempty" gorm:"column:completed_at"`
	CreatedAt       time.Time `json:"created_at" gorm:"column:created_at"`
}

// LeadExtractionRequest is the request body for starting a lead extraction job
type LeadExtractionRequest struct {
	Folders  []string `json:"folders"`
	DaysBack int      `json:"days_back"`
}

// LeadImportRequest is the request body for importing leads to a group
type LeadImportRequest struct {
	LeadIds    []int64 `json:"lead_ids"`
	GroupId    int64   `json:"group_id"`
	GroupName  string  `json:"group_name"`  // If GroupId is 0, create new group with this name
	MergeLeads bool    `json:"merge_leads"` // Merge with existing targets in group
}

// LeadExtractionStats provides statistics about extracted leads
type LeadExtractionStats struct {
	TotalLeads    int64 `json:"total_leads"`
	ImportedLeads int64 `json:"imported_leads"`
	PendingLeads  int64 `json:"pending_leads"`
	UniqueEmails  int64 `json:"unique_emails"`
}

// Job status constants
const (
	JobStatusPending   = "pending"
	JobStatusRunning   = "running"
	JobStatusCompleted = "completed"
	JobStatusFailed    = "failed"
)

// Lead source constants
const (
	LeadSourceInbox   = "inbox"
	LeadSourceSent    = "sent"
	LeadSourceAllMail = "all_mail"
)

// Errors
var (
	ErrLeadNotFound      = errors.New("Lead not found")
	ErrJobNotFound       = errors.New("Extraction job not found")
	ErrIMAPNotConfigured = errors.New("IMAP not configured for this SMTP profile")
	ErrJobAlreadyRunning = errors.New("An extraction job is already running for this profile")
)

// TableName specifies the database tablename for Gorm to use
func (el ExtractedLead) TableName() string {
	return "extracted_leads"
}

// TableName specifies the database tablename for Gorm to use
func (lej LeadExtractionJob) TableName() string {
	return "lead_extraction_jobs"
}

// GetExtractedLeads returns all extracted leads for a given SMTP profile
func GetExtractedLeads(smtpId int64, uid int64) ([]ExtractedLead, error) {
	leads := []ExtractedLead{}
	err := db.Where("smtp_id=? AND user_id=?", smtpId, uid).Order("extracted_at desc").Find(&leads).Error
	if err != nil {
		log.Error(err)
		return leads, err
	}
	return leads, nil
}

// GetExtractedLeadsByUser returns all extracted leads for a user across all SMTP profiles
func GetExtractedLeadsByUser(uid int64) ([]ExtractedLead, error) {
	leads := []ExtractedLead{}
	err := db.Where("user_id=?", uid).Order("extracted_at desc").Find(&leads).Error
	if err != nil {
		log.Error(err)
		return leads, err
	}
	return leads, nil
}

// GetExtractedLead returns a single extracted lead by ID
func GetExtractedLead(id int64, uid int64) (ExtractedLead, error) {
	lead := ExtractedLead{}
	err := db.Where("id=? AND user_id=?", id, uid).First(&lead).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return lead, ErrLeadNotFound
		}
		log.Error(err)
		return lead, err
	}
	return lead, nil
}

// GetUnimportedLeads returns leads that haven't been imported to any group yet
func GetUnimportedLeads(smtpId int64, uid int64) ([]ExtractedLead, error) {
	leads := []ExtractedLead{}
	err := db.Where("smtp_id=? AND user_id=? AND imported_to_group_id=0", smtpId, uid).
		Order("extracted_at desc").Find(&leads).Error
	if err != nil {
		log.Error(err)
		return leads, err
	}
	return leads, nil
}

// PostExtractedLead creates a new extracted lead in the database
func PostExtractedLead(lead *ExtractedLead) error {
	lead.ExtractedAt = time.Now().UTC()
	err := db.Save(lead).Error
	if err != nil {
		log.Error(err)
	}
	return err
}

// PostExtractedLeadBatch creates multiple extracted leads in a single transaction
func PostExtractedLeadBatch(leads []ExtractedLead) error {
	if len(leads) == 0 {
		return nil
	}

	tx := db.Begin()
	for i := range leads {
		leads[i].ExtractedAt = time.Now().UTC()
		if err := tx.Create(&leads[i]).Error; err != nil {
			tx.Rollback()
			log.Error(err)
			return err
		}
	}
	return tx.Commit().Error
}

// UpdateExtractedLeadImport marks a lead as imported to a group
func UpdateExtractedLeadImport(leadId int64, groupId int64) error {
	err := db.Model(&ExtractedLead{}).Where("id=?", leadId).
		Update("imported_to_group_id", groupId).Error
	if err != nil {
		log.Error(err)
	}
	return err
}

// DeleteExtractedLead deletes an extracted lead
func DeleteExtractedLead(id int64, uid int64) error {
	err := db.Where("id=? AND user_id=?", id, uid).Delete(&ExtractedLead{}).Error
	if err != nil {
		log.Error(err)
	}
	return err
}

// DeleteExtractedLeadsBySMTP deletes all extracted leads for an SMTP profile
func DeleteExtractedLeadsBySMTP(smtpId int64, uid int64) error {
	err := db.Where("smtp_id=? AND user_id=?", smtpId, uid).Delete(&ExtractedLead{}).Error
	if err != nil {
		log.Error(err)
	}
	return err
}

// LeadExistsForSMTP checks if a lead with the given email already exists for the SMTP profile
func LeadExistsForSMTP(email string, smtpId int64, uid int64) (bool, error) {
	var count int64
	err := db.Model(&ExtractedLead{}).Where("email=? AND smtp_id=? AND user_id=?", email, smtpId, uid).Count(&count).Error
	if err != nil {
		log.Error(err)
		return false, err
	}
	return count > 0, nil
}

// GetLeadExtractionStats returns statistics about extracted leads for a user
func GetLeadExtractionStats(uid int64) (LeadExtractionStats, error) {
	stats := LeadExtractionStats{}

	// Total leads
	err := db.Model(&ExtractedLead{}).Where("user_id=?", uid).Count(&stats.TotalLeads).Error
	if err != nil {
		log.Error(err)
		return stats, err
	}

	// Imported leads
	err = db.Model(&ExtractedLead{}).Where("user_id=? AND imported_to_group_id > 0", uid).Count(&stats.ImportedLeads).Error
	if err != nil {
		log.Error(err)
		return stats, err
	}

	// Pending leads (not imported)
	stats.PendingLeads = stats.TotalLeads - stats.ImportedLeads

	// Unique emails
	err = db.Model(&ExtractedLead{}).Where("user_id=?", uid).
		Select("COUNT(DISTINCT email)").Row().Scan(&stats.UniqueEmails)
	if err != nil {
		log.Error(err)
		return stats, err
	}

	return stats, nil
}

// ========== Lead Extraction Jobs ==========

// GetLeadExtractionJobs returns all extraction jobs for a given SMTP profile
func GetLeadExtractionJobs(smtpId int64, uid int64) ([]LeadExtractionJob, error) {
	jobs := []LeadExtractionJob{}
	err := db.Where("smtp_id=? AND user_id=?", smtpId, uid).Order("created_at desc").Find(&jobs).Error
	if err != nil {
		log.Error(err)
		return jobs, err
	}
	return jobs, nil
}

// GetLeadExtractionJob returns a single extraction job by ID
func GetLeadExtractionJob(id int64, uid int64) (LeadExtractionJob, error) {
	job := LeadExtractionJob{}
	err := db.Where("id=? AND user_id=?", id, uid).First(&job).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return job, ErrJobNotFound
		}
		log.Error(err)
		return job, err
	}
	return job, nil
}

// GetRunningJobForSMTP checks if there's already a running job for the SMTP profile
func GetRunningJobForSMTP(smtpId int64, uid int64) (*LeadExtractionJob, error) {
	job := LeadExtractionJob{}
	err := db.Where("smtp_id=? AND user_id=? AND status IN (?)", smtpId, uid,
		[]string{JobStatusPending, JobStatusRunning}).First(&job).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		log.Error(err)
		return nil, err
	}
	return &job, nil
}

// PostLeadExtractionJob creates a new extraction job
func PostLeadExtractionJob(job *LeadExtractionJob) error {
	job.Status = JobStatusPending
	job.CreatedAt = time.Now().UTC()
	err := db.Save(job).Error
	if err != nil {
		log.Error(err)
	}
	return err
}

// UpdateLeadExtractionJobStatus updates the status of an extraction job
func UpdateLeadExtractionJobStatus(jobId int64, status string, errorMsg string) error {
	updates := map[string]interface{}{
		"status": status,
	}

	if status == JobStatusRunning {
		updates["started_at"] = time.Now().UTC()
	} else if status == JobStatusCompleted || status == JobStatusFailed {
		updates["completed_at"] = time.Now().UTC()
	}

	if errorMsg != "" {
		updates["error_message"] = errorMsg
	}

	err := db.Model(&LeadExtractionJob{}).Where("id=?", jobId).Updates(updates).Error
	if err != nil {
		log.Error(err)
	}
	return err
}

// UpdateLeadExtractionJobProgress updates the progress of an extraction job
func UpdateLeadExtractionJobProgress(jobId int64, totalEmails, processedEmails, leadsFound int) error {
	err := db.Model(&LeadExtractionJob{}).Where("id=?", jobId).Updates(map[string]interface{}{
		"total_emails":     totalEmails,
		"processed_emails": processedEmails,
		"leads_found":      leadsFound,
	}).Error
	if err != nil {
		log.Error(err)
	}
	return err
}

// DeleteLeadExtractionJob deletes an extraction job
func DeleteLeadExtractionJob(id int64, uid int64) error {
	err := db.Where("id=? AND user_id=?", id, uid).Delete(&LeadExtractionJob{}).Error
	if err != nil {
		log.Error(err)
	}
	return err
}

// ========== Lead Import Functions ==========

// ImportLeadsToGroup imports extracted leads to a target group
func ImportLeadsToGroup(leadIds []int64, groupId int64, uid int64, merge bool) (int, error) {
	if len(leadIds) == 0 {
		return 0, nil
	}

	// Get the group
	group, err := GetGroup(groupId, uid)
	if err != nil {
		return 0, err
	}

	// Get the leads
	leads := []ExtractedLead{}
	err = db.Where("id IN (?) AND user_id=?", leadIds, uid).Find(&leads).Error
	if err != nil {
		log.Error(err)
		return 0, err
	}

	// Build existing email map if merging
	existingEmails := make(map[string]bool)
	if merge {
		for _, t := range group.Targets {
			existingEmails[t.Email] = true
		}
	}

	// Convert leads to targets
	newTargets := []Target{}
	for _, lead := range leads {
		// Skip if already exists and we're merging
		if merge && existingEmails[lead.Email] {
			continue
		}

		// Parse name into first/last
		firstName, lastName := parseLeadName(lead.Name)

		newTargets = append(newTargets, Target{
			BaseRecipient: BaseRecipient{
				Email:     lead.Email,
				FirstName: firstName,
				LastName:  lastName,
			},
		})
	}

	if len(newTargets) == 0 {
		return 0, nil
	}

	// Add targets to group
	group.Targets = append(group.Targets, newTargets...)
	err = PutGroup(&group)
	if err != nil {
		return 0, err
	}

	// Mark leads as imported
	for _, leadId := range leadIds {
		UpdateExtractedLeadImport(leadId, groupId)
	}

	return len(newTargets), nil
}

// ImportLeadsToNewGroup creates a new group and imports leads to it
func ImportLeadsToNewGroup(leadIds []int64, groupName string, uid int64) (int64, int, error) {
	if len(leadIds) == 0 {
		return 0, 0, nil
	}

	// Get the leads
	leads := []ExtractedLead{}
	err := db.Where("id IN (?) AND user_id=?", leadIds, uid).Find(&leads).Error
	if err != nil {
		log.Error(err)
		return 0, 0, err
	}

	// Convert leads to targets
	targets := []Target{}
	for _, lead := range leads {
		firstName, lastName := parseLeadName(lead.Name)
		targets = append(targets, Target{
			BaseRecipient: BaseRecipient{
				Email:     lead.Email,
				FirstName: firstName,
				LastName:  lastName,
			},
		})
	}

	// Create new group
	group := Group{
		Name:    groupName,
		UserId:  uid,
		Targets: targets,
	}

	err = PostGroup(&group)
	if err != nil {
		return 0, 0, err
	}

	// Mark leads as imported
	for _, leadId := range leadIds {
		UpdateExtractedLeadImport(leadId, group.Id)
	}

	return group.Id, len(targets), nil
}

// parseLeadName splits a full name into first and last name
func parseLeadName(name string) (string, string) {
	if name == "" {
		return "", ""
	}

	parts := splitName(name)
	if len(parts) == 0 {
		return "", ""
	} else if len(parts) == 1 {
		return parts[0], ""
	}

	return parts[0], parts[len(parts)-1]
}

// splitName splits a name string into parts
func splitName(name string) []string {
	var parts []string
	current := ""
	for _, r := range name {
		if r == ' ' || r == '\t' {
			if current != "" {
				parts = append(parts, current)
				current = ""
			}
		} else {
			current += string(r)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}
