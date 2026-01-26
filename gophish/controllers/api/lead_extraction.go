package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	ctx "github.com/gophish/gophish/context"
	"github.com/gophish/gophish/leadextractor"
	log "github.com/gophish/gophish/logger"
	"github.com/gophish/gophish/models"
	"github.com/gorilla/mux"
)

// LeadExtractionStats returns statistics about extracted leads for the current user
// @Summary Get lead extraction statistics
// @Tags Lead Extraction
// @Success 200 {object} models.LeadExtractionStats
// @Router /api/leads/stats [get]
func (as *Server) LeadExtractionStats(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		as.getLeadExtractionStats(w, r)
	default:
		JSONResponse(w, models.Response{Success: false, Message: "Method not allowed"}, http.StatusMethodNotAllowed)
	}
}

func (as *Server) getLeadExtractionStats(w http.ResponseWriter, r *http.Request) {
	u := ctx.Get(r, "user").(models.User)
	stats, err := models.GetLeadExtractionStats(u.Id)
	if err != nil {
		log.Error(err)
		JSONResponse(w, models.Response{Success: false, Message: "Error getting lead extraction stats"}, http.StatusInternalServerError)
		return
	}
	JSONResponse(w, stats, http.StatusOK)
}

// ExtractedLeads handles requests for extracted leads
// @Summary Get all extracted leads for a user
// @Tags Lead Extraction
// @Success 200 {array} models.ExtractedLead
// @Router /api/leads/ [get]
func (as *Server) ExtractedLeads(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		as.getExtractedLeads(w, r)
	case http.MethodDelete:
		as.deleteAllExtractedLeads(w, r)
	default:
		JSONResponse(w, models.Response{Success: false, Message: "Method not allowed"}, http.StatusMethodNotAllowed)
	}
}

func (as *Server) getExtractedLeads(w http.ResponseWriter, r *http.Request) {
	u := ctx.Get(r, "user").(models.User)

	// Check for smtp_id query parameter
	smtpIdStr := r.URL.Query().Get("smtp_id")
	if smtpIdStr != "" {
		smtpId, err := strconv.ParseInt(smtpIdStr, 10, 64)
		if err != nil {
			JSONResponse(w, models.Response{Success: false, Message: "Invalid smtp_id"}, http.StatusBadRequest)
			return
		}
		leads, err := models.GetExtractedLeads(smtpId, u.Id)
		if err != nil {
			log.Error(err)
			JSONResponse(w, models.Response{Success: false, Message: "Error getting extracted leads"}, http.StatusInternalServerError)
			return
		}
		JSONResponse(w, leads, http.StatusOK)
		return
	}

	// Get all leads for user
	leads, err := models.GetExtractedLeadsByUser(u.Id)
	if err != nil {
		log.Error(err)
		JSONResponse(w, models.Response{Success: false, Message: "Error getting extracted leads"}, http.StatusInternalServerError)
		return
	}
	JSONResponse(w, leads, http.StatusOK)
}

func (as *Server) deleteAllExtractedLeads(w http.ResponseWriter, r *http.Request) {
	u := ctx.Get(r, "user").(models.User)

	// Check for smtp_id query parameter
	smtpIdStr := r.URL.Query().Get("smtp_id")
	if smtpIdStr == "" {
		JSONResponse(w, models.Response{Success: false, Message: "smtp_id is required"}, http.StatusBadRequest)
		return
	}

	smtpId, err := strconv.ParseInt(smtpIdStr, 10, 64)
	if err != nil {
		JSONResponse(w, models.Response{Success: false, Message: "Invalid smtp_id"}, http.StatusBadRequest)
		return
	}

	err = models.DeleteExtractedLeadsBySMTP(smtpId, u.Id)
	if err != nil {
		log.Error(err)
		JSONResponse(w, models.Response{Success: false, Message: "Error deleting extracted leads"}, http.StatusInternalServerError)
		return
	}

	JSONResponse(w, models.Response{Success: true, Message: "Leads deleted successfully"}, http.StatusOK)
}

// ExtractedLead handles requests for a single extracted lead
// @Summary Get/Delete a single extracted lead
// @Tags Lead Extraction
// @Param id path int true "Lead ID"
// @Success 200 {object} models.ExtractedLead
// @Router /api/leads/{id} [get]
func (as *Server) ExtractedLead(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.ParseInt(vars["id"], 10, 64)
	if err != nil {
		JSONResponse(w, models.Response{Success: false, Message: "Invalid lead ID"}, http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		as.getExtractedLead(w, r, id)
	case http.MethodDelete:
		as.deleteExtractedLead(w, r, id)
	default:
		JSONResponse(w, models.Response{Success: false, Message: "Method not allowed"}, http.StatusMethodNotAllowed)
	}
}

func (as *Server) getExtractedLead(w http.ResponseWriter, r *http.Request, id int64) {
	u := ctx.Get(r, "user").(models.User)
	lead, err := models.GetExtractedLead(id, u.Id)
	if err != nil {
		if err == models.ErrLeadNotFound {
			JSONResponse(w, models.Response{Success: false, Message: "Lead not found"}, http.StatusNotFound)
			return
		}
		log.Error(err)
		JSONResponse(w, models.Response{Success: false, Message: "Error getting lead"}, http.StatusInternalServerError)
		return
	}
	JSONResponse(w, lead, http.StatusOK)
}

func (as *Server) deleteExtractedLead(w http.ResponseWriter, r *http.Request, id int64) {
	u := ctx.Get(r, "user").(models.User)
	err := models.DeleteExtractedLead(id, u.Id)
	if err != nil {
		log.Error(err)
		JSONResponse(w, models.Response{Success: false, Message: "Error deleting lead"}, http.StatusInternalServerError)
		return
	}
	JSONResponse(w, models.Response{Success: true, Message: "Lead deleted successfully"}, http.StatusOK)
}

// LeadExtractionJobs handles requests for lead extraction jobs
// @Summary Get all extraction jobs for an SMTP profile
// @Tags Lead Extraction
// @Param smtp_id query int true "SMTP Profile ID"
// @Success 200 {array} models.LeadExtractionJob
// @Router /api/leads/jobs [get]
func (as *Server) LeadExtractionJobs(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		as.getLeadExtractionJobs(w, r)
	default:
		JSONResponse(w, models.Response{Success: false, Message: "Method not allowed"}, http.StatusMethodNotAllowed)
	}
}

func (as *Server) getLeadExtractionJobs(w http.ResponseWriter, r *http.Request) {
	u := ctx.Get(r, "user").(models.User)

	smtpIdStr := r.URL.Query().Get("smtp_id")
	if smtpIdStr == "" {
		JSONResponse(w, models.Response{Success: false, Message: "smtp_id is required"}, http.StatusBadRequest)
		return
	}

	smtpId, err := strconv.ParseInt(smtpIdStr, 10, 64)
	if err != nil {
		JSONResponse(w, models.Response{Success: false, Message: "Invalid smtp_id"}, http.StatusBadRequest)
		return
	}

	jobs, err := models.GetLeadExtractionJobs(smtpId, u.Id)
	if err != nil {
		log.Error(err)
		JSONResponse(w, models.Response{Success: false, Message: "Error getting extraction jobs"}, http.StatusInternalServerError)
		return
	}
	JSONResponse(w, jobs, http.StatusOK)
}

// LeadExtractionJob handles requests for a single extraction job
// @Summary Get a single extraction job
// @Tags Lead Extraction
// @Param id path int true "Job ID"
// @Success 200 {object} models.LeadExtractionJob
// @Router /api/leads/jobs/{id} [get]
func (as *Server) LeadExtractionJob(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.ParseInt(vars["id"], 10, 64)
	if err != nil {
		JSONResponse(w, models.Response{Success: false, Message: "Invalid job ID"}, http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		as.getLeadExtractionJob(w, r, id)
	case http.MethodDelete:
		as.deleteLeadExtractionJob(w, r, id)
	default:
		JSONResponse(w, models.Response{Success: false, Message: "Method not allowed"}, http.StatusMethodNotAllowed)
	}
}

func (as *Server) getLeadExtractionJob(w http.ResponseWriter, r *http.Request, id int64) {
	u := ctx.Get(r, "user").(models.User)
	job, err := models.GetLeadExtractionJob(id, u.Id)
	if err != nil {
		if err == models.ErrJobNotFound {
			JSONResponse(w, models.Response{Success: false, Message: "Job not found"}, http.StatusNotFound)
			return
		}
		log.Error(err)
		JSONResponse(w, models.Response{Success: false, Message: "Error getting job"}, http.StatusInternalServerError)
		return
	}
	JSONResponse(w, job, http.StatusOK)
}

func (as *Server) deleteLeadExtractionJob(w http.ResponseWriter, r *http.Request, id int64) {
	u := ctx.Get(r, "user").(models.User)
	err := models.DeleteLeadExtractionJob(id, u.Id)
	if err != nil {
		log.Error(err)
		JSONResponse(w, models.Response{Success: false, Message: "Error deleting job"}, http.StatusInternalServerError)
		return
	}
	JSONResponse(w, models.Response{Success: true, Message: "Job deleted successfully"}, http.StatusOK)
}

// StartLeadExtraction starts a new lead extraction job
// @Summary Start a lead extraction job for an SMTP profile
// @Tags Lead Extraction
// @Param smtp_id path int true "SMTP Profile ID"
// @Param request body models.LeadExtractionRequest true "Extraction parameters"
// @Success 200 {object} models.LeadExtractionJob
// @Router /api/smtp/{smtp_id}/extract-leads [post]
func (as *Server) StartLeadExtraction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		JSONResponse(w, models.Response{Success: false, Message: "Method not allowed"}, http.StatusMethodNotAllowed)
		return
	}

	vars := mux.Vars(r)
	smtpId, err := strconv.ParseInt(vars["smtp_id"], 10, 64)
	if err != nil {
		JSONResponse(w, models.Response{Success: false, Message: "Invalid SMTP ID"}, http.StatusBadRequest)
		return
	}

	u := ctx.Get(r, "user").(models.User)

	// Parse request body
	var req models.LeadExtractionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Use defaults if no body provided
		req = models.LeadExtractionRequest{
			Folders:  []string{"[Gmail]/All Mail"},
			DaysBack: 160,
		}
	}

	// Start extraction job
	job, err := leadextractor.StartExtractionJob(smtpId, u.Id, req.Folders, req.DaysBack)
	if err != nil {
		if err == models.ErrIMAPNotConfigured {
			JSONResponse(w, models.Response{Success: false, Message: "IMAP not configured for this SMTP profile. Please add IMAP settings first."}, http.StatusBadRequest)
			return
		}
		if err == models.ErrJobAlreadyRunning {
			JSONResponse(w, models.Response{Success: false, Message: "An extraction job is already running for this profile"}, http.StatusConflict)
			return
		}
		log.Error(err)
		JSONResponse(w, models.Response{Success: false, Message: "Error starting extraction job: " + err.Error()}, http.StatusInternalServerError)
		return
	}

	JSONResponse(w, job, http.StatusOK)
}

// TestIMAPConnection tests the IMAP connection for an SMTP profile
// @Summary Test IMAP connection for an SMTP profile
// @Tags Lead Extraction
// @Param smtp_id path int true "SMTP Profile ID"
// @Success 200 {object} models.Response
// @Router /api/smtp/{smtp_id}/test-imap [post]
func (as *Server) TestIMAPConnection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		JSONResponse(w, models.Response{Success: false, Message: "Method not allowed"}, http.StatusMethodNotAllowed)
		return
	}

	vars := mux.Vars(r)
	smtpId, err := strconv.ParseInt(vars["smtp_id"], 10, 64)
	if err != nil {
		JSONResponse(w, models.Response{Success: false, Message: "Invalid SMTP ID"}, http.StatusBadRequest)
		return
	}

	u := ctx.Get(r, "user").(models.User)

	// Get SMTP profile
	smtp, err := models.GetSMTP(smtpId, u.Id)
	if err != nil {
		JSONResponse(w, models.Response{Success: false, Message: "SMTP profile not found"}, http.StatusNotFound)
		return
	}

	// Test connection
	err = leadextractor.TestIMAPConnection(&smtp)
	if err != nil {
		JSONResponse(w, models.Response{Success: false, Message: err.Error()}, http.StatusBadRequest)
		return
	}

	JSONResponse(w, models.Response{Success: true, Message: "IMAP connection successful"}, http.StatusOK)
}

// ListIMAPFolders lists available IMAP folders for an SMTP profile
// @Summary List IMAP folders for an SMTP profile
// @Tags Lead Extraction
// @Param smtp_id path int true "SMTP Profile ID"
// @Success 200 {array} string
// @Router /api/smtp/{smtp_id}/imap-folders [get]
func (as *Server) ListIMAPFolders(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		JSONResponse(w, models.Response{Success: false, Message: "Method not allowed"}, http.StatusMethodNotAllowed)
		return
	}

	vars := mux.Vars(r)
	smtpId, err := strconv.ParseInt(vars["smtp_id"], 10, 64)
	if err != nil {
		JSONResponse(w, models.Response{Success: false, Message: "Invalid SMTP ID"}, http.StatusBadRequest)
		return
	}

	u := ctx.Get(r, "user").(models.User)

	// Get SMTP profile
	smtp, err := models.GetSMTP(smtpId, u.Id)
	if err != nil {
		JSONResponse(w, models.Response{Success: false, Message: "SMTP profile not found"}, http.StatusNotFound)
		return
	}

	// List folders
	folders, err := leadextractor.ListIMAPFolders(&smtp)
	if err != nil {
		JSONResponse(w, models.Response{Success: false, Message: err.Error()}, http.StatusBadRequest)
		return
	}

	JSONResponse(w, folders, http.StatusOK)
}

// ImportLeadsToGroup imports extracted leads to a target group
// @Summary Import leads to a group
// @Tags Lead Extraction
// @Param request body models.LeadImportRequest true "Import parameters"
// @Success 200 {object} models.Response
// @Router /api/leads/import [post]
func (as *Server) ImportLeadsToGroup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		JSONResponse(w, models.Response{Success: false, Message: "Method not allowed"}, http.StatusMethodNotAllowed)
		return
	}

	u := ctx.Get(r, "user").(models.User)

	// Parse request body
	var req models.LeadImportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		JSONResponse(w, models.Response{Success: false, Message: "Invalid request body"}, http.StatusBadRequest)
		return
	}

	if len(req.LeadIds) == 0 {
		JSONResponse(w, models.Response{Success: false, Message: "No leads specified"}, http.StatusBadRequest)
		return
	}

	var imported int
	var groupId int64
	var err error

	if req.GroupId > 0 {
		// Import to existing group
		imported, err = models.ImportLeadsToGroup(req.LeadIds, req.GroupId, u.Id, req.MergeLeads)
		groupId = req.GroupId
	} else if req.GroupName != "" {
		// Create new group and import
		groupId, imported, err = models.ImportLeadsToNewGroup(req.LeadIds, req.GroupName, u.Id)
	} else {
		JSONResponse(w, models.Response{Success: false, Message: "Either group_id or group_name is required"}, http.StatusBadRequest)
		return
	}

	if err != nil {
		log.Error(err)
		JSONResponse(w, models.Response{Success: false, Message: "Error importing leads: " + err.Error()}, http.StatusInternalServerError)
		return
	}

	JSONResponse(w, map[string]interface{}{
		"success":  true,
		"message":  "Leads imported successfully",
		"imported": imported,
		"group_id": groupId,
	}, http.StatusOK)
}
