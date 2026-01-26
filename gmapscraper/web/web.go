package web

import (
	"bufio"
	"context"
	"embed"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

//go:embed static
var static embed.FS

type Server struct {
	tmpl map[string]*template.Template
	srv  *http.Server
	svc  *Service
}

func New(svc *Service, addr string) (*Server, error) {
	ans := Server{
		svc:  svc,
		tmpl: make(map[string]*template.Template),
		srv: &http.Server{
			Addr:              addr,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       60 * time.Second,
			WriteTimeout:      60 * time.Second,
			IdleTimeout:       120 * time.Second,
			MaxHeaderBytes:    1 << 20,
		},
	}

	staticFS, err := fs.Sub(static, "static")
	if err != nil {
		return nil, err
	}

	fileServer := http.FileServer(http.FS(staticFS))
	mux := http.NewServeMux()

	mux.Handle("/static/", http.StripPrefix("/static/", fileServer))
	mux.HandleFunc("/scrape", ans.scrape)
	mux.HandleFunc("/download", func(w http.ResponseWriter, r *http.Request) {
		r = requestWithID(r)

		ans.download(w, r)
	})
	mux.HandleFunc("/delete", func(w http.ResponseWriter, r *http.Request) {
		r = requestWithID(r)

		ans.delete(w, r)
	})
	mux.HandleFunc("/stop", func(w http.ResponseWriter, r *http.Request) {
		r = requestWithID(r)

		ans.stop(w, r)
	})
	mux.HandleFunc("/jobs", ans.getJobs)
	mux.HandleFunc("/", ans.index)

	// api routes
	mux.HandleFunc("/api/docs", ans.redocHandler)
	mux.HandleFunc("/api/v1/jobs", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			ans.apiScrape(w, r)
		case http.MethodGet:
			ans.apiGetJobs(w, r)
		default:
			ans := apiError{
				Code:    http.StatusMethodNotAllowed,
				Message: "Method not allowed",
			}

			renderJSON(w, http.StatusMethodNotAllowed, ans)
		}
	})

	mux.HandleFunc("/api/v1/jobs/{id}", func(w http.ResponseWriter, r *http.Request) {
		r = requestWithID(r)

		switch r.Method {
		case http.MethodGet:
			ans.apiGetJob(w, r)
		case http.MethodDelete:
			ans.apiDeleteJob(w, r)
		default:
			ans := apiError{
				Code:    http.StatusMethodNotAllowed,
				Message: "Method not allowed",
			}

			renderJSON(w, http.StatusMethodNotAllowed, ans)
		}
	})

	mux.HandleFunc("/api/v1/jobs/{id}/download", func(w http.ResponseWriter, r *http.Request) {
		r = requestWithID(r)

		if r.Method != http.MethodGet {
			ans := apiError{
				Code:    http.StatusMethodNotAllowed,
				Message: "Method not allowed",
			}

			renderJSON(w, http.StatusMethodNotAllowed, ans)

			return
		}

		ans.download(w, r)
	})

	// Extraction routes
	mux.HandleFunc("/extract", ans.extractData)
	mux.HandleFunc("/upload-csv", ans.uploadCSV)
	mux.HandleFunc("/extract-gophish", ans.extractGophish)
	mux.HandleFunc("/upload-gophish", ans.uploadGophish)
	mux.HandleFunc("/upload-gophish-batch", ans.uploadGophishBatch)

	// Geocoding proxy (to avoid CORS issues with Nominatim)
	mux.HandleFunc("/geocode", ans.geocodeProxy)

	handler := securityHeaders(mux)
	ans.srv.Handler = handler

	tmplsKeys := []string{
		"static/templates/index.html",
		"static/templates/job_rows.html",
		"static/templates/job_row.html",
		"static/templates/redoc.html",
	}

	for _, key := range tmplsKeys {
		tmp, err := template.ParseFS(static, key)
		if err != nil {
			return nil, err
		}

		ans.tmpl[key] = tmp
	}

	return &ans, nil
}

func (s *Server) Start(ctx context.Context) error {
	go func() {
		<-ctx.Done()

		err := s.srv.Shutdown(context.Background())
		if err != nil {
			log.Println(err)

			return
		}

		log.Println("server stopped")
	}()

	fmt.Fprintf(os.Stderr, "visit http://localhost%s\n", s.srv.Addr)

	err := s.srv.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		return err
	}

	return nil
}

type formData struct {
	Name       string
	MaxTime    string
	Keywords   []string
	Language   string
	Zoom       int
	FastMode   bool
	Radius     int
	Lat        string
	Lon        string
	Depth      int
	Email      bool
	Proxies    []string
	MaxResults int
	// API Mode fields
	UseAPI   bool
	APIKey   string
	APIExtra bool
	Country  string
}

type ctxKey string

const idCtxKey ctxKey = "id"

func requestWithID(r *http.Request) *http.Request {
	id := r.PathValue("id")
	if id == "" {
		id = r.URL.Query().Get("id")
	}

	parsed, err := uuid.Parse(id)
	if err == nil {
		r = r.WithContext(context.WithValue(r.Context(), idCtxKey, parsed))
	}

	return r
}

func getIDFromRequest(r *http.Request) (uuid.UUID, bool) {
	id, ok := r.Context().Value(idCtxKey).(uuid.UUID)

	return id, ok
}

//nolint:gocritic // this is used in template
func (f formData) ProxiesString() string {
	return strings.Join(f.Proxies, "\n")
}

//nolint:gocritic // this is used in template
func (f formData) KeywordsString() string {
	return strings.Join(f.Keywords, "\n")
}

func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)

		return
	}

	tmpl, ok := s.tmpl["static/templates/index.html"]
	if !ok {
		http.Error(w, "missing tpl", http.StatusInternalServerError)

		return
	}

	data := formData{
		Name:       "",
		MaxTime:    "10m",
		Keywords:   []string{},
		Language:   "en",
		Zoom:       8,  // Lower default zoom for wider state-level searches
		FastMode:   false,
		Radius:     50000, // 50km default radius for better coverage
		Lat:        "0",
		Lon:        "0",
		Depth:      20,   // Increased depth for more results
		Email:      false,
		MaxResults: 100,  // Default to 100 preferred results
		UseAPI:     false,
		APIKey:     "",
		APIExtra:   true,  // Include emails/social by default when using API
		Country:    "us",
	}

	_ = tmpl.Execute(w, data)
}

func (s *Server) scrape(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)

		return
	}

	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	}

	newJob := Job{
		ID:     uuid.New().String(),
		Name:   r.Form.Get("name"),
		Date:   time.Now().UTC(),
		Status: StatusPending,
		Data:   JobData{},
	}

	maxTimeStr := r.Form.Get("maxtime")

	maxTime, err := time.ParseDuration(maxTimeStr)
	if err != nil {
		http.Error(w, "invalid max time", http.StatusUnprocessableEntity)

		return
	}

	if maxTime < time.Minute*3 {
		http.Error(w, "max time must be more than 3m", http.StatusUnprocessableEntity)

		return
	}

	newJob.Data.MaxTime = maxTime

	keywordsStr, ok := r.Form["keywords"]
	if !ok {
		http.Error(w, "missing keywords", http.StatusUnprocessableEntity)

		return
	}

	keywords := strings.Split(keywordsStr[0], "\n")
	for _, k := range keywords {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}

		newJob.Data.Keywords = append(newJob.Data.Keywords, k)
	}

	newJob.Data.Lang = r.Form.Get("lang")

	newJob.Data.Zoom, err = strconv.Atoi(r.Form.Get("zoom"))
	if err != nil {
		http.Error(w, "invalid zoom", http.StatusUnprocessableEntity)

		return
	}

	if r.Form.Get("fastmode") == "on" {
		newJob.Data.FastMode = true
	}

	newJob.Data.Radius, err = strconv.Atoi(r.Form.Get("radius"))
	if err != nil {
		http.Error(w, "invalid radius", http.StatusUnprocessableEntity)

		return
	}

	newJob.Data.Lat = r.Form.Get("latitude")
	newJob.Data.Lon = r.Form.Get("longitude")

	newJob.Data.Depth, err = strconv.Atoi(r.Form.Get("depth"))
	if err != nil {
		http.Error(w, "invalid depth", http.StatusUnprocessableEntity)

		return
	}

	newJob.Data.Email = r.Form.Get("email") == "on"

	maxResultsStr := r.Form.Get("maxresults")
	if maxResultsStr != "" {
		newJob.Data.MaxResults, err = strconv.Atoi(maxResultsStr)
		if err != nil {
			newJob.Data.MaxResults = 0 // 0 = unlimited
		}
	}

	// Auto-adjust depth based on maxResults for better result coverage
	if newJob.Data.MaxResults > 0 && newJob.Data.Depth < newJob.Data.MaxResults/10 {
		newJob.Data.Depth = max(newJob.Data.Depth, newJob.Data.MaxResults/10+5)
	}

	proxies := strings.Split(r.Form.Get("proxies"), "\n")
	if len(proxies) > 0 {
		for _, p := range proxies {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}

			newJob.Data.Proxies = append(newJob.Data.Proxies, p)
		}
	}

	// API Mode settings
	newJob.Data.UseAPI = r.Form.Get("useapi") == "on"
	newJob.Data.APIKey = strings.TrimSpace(r.Form.Get("apikey"))
	newJob.Data.APIExtra = r.Form.Get("apiextra") == "on"
	newJob.Data.Country = r.Form.Get("country")
	if newJob.Data.Country == "" {
		newJob.Data.Country = "us"
	}

	// Validate API key if API mode is enabled
	if newJob.Data.UseAPI && newJob.Data.APIKey == "" {
		http.Error(w, "API key is required when using API mode", http.StatusUnprocessableEntity)
		return
	}

	err = newJob.Validate()
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)

		return
	}

	err = s.svc.Create(r.Context(), &newJob)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	}

	tmpl, ok := s.tmpl["static/templates/job_row.html"]
	if !ok {
		http.Error(w, "missing tpl", http.StatusInternalServerError)

		return
	}

	_ = tmpl.Execute(w, newJob)
}

func (s *Server) getJobs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)

		return
	}

	tmpl, ok := s.tmpl["static/templates/job_rows.html"]
	if !ok {
		http.Error(w, "missing tpl", http.StatusInternalServerError)
		return
	}

	jobs, err := s.svc.All(context.Background())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	}

	_ = tmpl.Execute(w, jobs)
}

func (s *Server) download(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)

		return
	}

	ctx := r.Context()

	id, ok := getIDFromRequest(r)
	if !ok {
		http.Error(w, "Invalid ID", http.StatusUnprocessableEntity)

		return
	}

	filePath, err := s.svc.GetCSV(ctx, id.String())
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	file, err := os.Open(filePath)
	if err != nil {
		http.Error(w, "Failed to open file", http.StatusInternalServerError)
		return
	}
	defer file.Close()

	fileName := filepath.Base(filePath)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", fileName))
	w.Header().Set("Content-Type", "text/csv")

	_, err = io.Copy(w, file)
	if err != nil {
		http.Error(w, "Failed to send file", http.StatusInternalServerError)
		return
	}
}

func (s *Server) delete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)

		return
	}

	deleteID, ok := getIDFromRequest(r)
	if !ok {
		http.Error(w, "Invalid ID", http.StatusUnprocessableEntity)

		return
	}

	err := s.svc.Delete(r.Context(), deleteID.String())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	}

	w.WriteHeader(http.StatusOK)
}

func (s *Server) stop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)

		return
	}

	stopID, ok := getIDFromRequest(r)
	if !ok {
		http.Error(w, "Invalid ID", http.StatusUnprocessableEntity)

		return
	}

	// Get the job first
	job, err := s.svc.Get(r.Context(), stopID.String())
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)

		return
	}

	// Only allow stopping pending or working jobs
	if job.Status != StatusPending && job.Status != StatusWorking {
		http.Error(w, "Job cannot be stopped (not running)", http.StatusUnprocessableEntity)

		return
	}

	// Update job status to stopped
	job.Status = StatusStopped
	err = s.svc.Update(r.Context(), &job)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	}

	// Return the updated job row
	tmpl, ok := s.tmpl["static/templates/job_row.html"]
	if !ok {
		http.Error(w, "missing tpl", http.StatusInternalServerError)

		return
	}

	_ = tmpl.Execute(w, job)
}

type apiError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type apiScrapeRequest struct {
	Name string
	JobData
}

type apiScrapeResponse struct {
	ID string `json:"id"`
}

func (s *Server) redocHandler(w http.ResponseWriter, _ *http.Request) {
	tmpl, ok := s.tmpl["static/templates/redoc.html"]
	if !ok {
		http.Error(w, "missing tpl", http.StatusInternalServerError)

		return
	}

	_ = tmpl.Execute(w, nil)
}

func (s *Server) apiScrape(w http.ResponseWriter, r *http.Request) {
	var req apiScrapeRequest

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		ans := apiError{
			Code:    http.StatusUnprocessableEntity,
			Message: err.Error(),
		}

		renderJSON(w, http.StatusUnprocessableEntity, ans)

		return
	}

	newJob := Job{
		ID:     uuid.New().String(),
		Name:   req.Name,
		Date:   time.Now().UTC(),
		Status: StatusPending,
		Data:   req.JobData,
	}

	// convert to seconds
	newJob.Data.MaxTime *= time.Second

	err = newJob.Validate()
	if err != nil {
		ans := apiError{
			Code:    http.StatusUnprocessableEntity,
			Message: err.Error(),
		}

		renderJSON(w, http.StatusUnprocessableEntity, ans)

		return
	}

	err = s.svc.Create(r.Context(), &newJob)
	if err != nil {
		ans := apiError{
			Code:    http.StatusInternalServerError,
			Message: err.Error(),
		}

		renderJSON(w, http.StatusInternalServerError, ans)

		return
	}

	ans := apiScrapeResponse{
		ID: newJob.ID,
	}

	renderJSON(w, http.StatusCreated, ans)
}

func (s *Server) apiGetJobs(w http.ResponseWriter, r *http.Request) {
	jobs, err := s.svc.All(r.Context())
	if err != nil {
		apiError := apiError{
			Code:    http.StatusInternalServerError,
			Message: err.Error(),
		}

		renderJSON(w, http.StatusInternalServerError, apiError)

		return
	}

	renderJSON(w, http.StatusOK, jobs)
}

func (s *Server) apiGetJob(w http.ResponseWriter, r *http.Request) {
	id, ok := getIDFromRequest(r)
	if !ok {
		apiError := apiError{
			Code:    http.StatusUnprocessableEntity,
			Message: "Invalid ID",
		}

		renderJSON(w, http.StatusUnprocessableEntity, apiError)

		return
	}

	job, err := s.svc.Get(r.Context(), id.String())
	if err != nil {
		apiError := apiError{
			Code:    http.StatusNotFound,
			Message: http.StatusText(http.StatusNotFound),
		}

		renderJSON(w, http.StatusNotFound, apiError)

		return
	}

	renderJSON(w, http.StatusOK, job)
}

func (s *Server) apiDeleteJob(w http.ResponseWriter, r *http.Request) {
	id, ok := getIDFromRequest(r)
	if !ok {
		apiError := apiError{
			Code:    http.StatusUnprocessableEntity,
			Message: "Invalid ID",
		}

		renderJSON(w, http.StatusUnprocessableEntity, apiError)

		return
	}

	err := s.svc.Delete(r.Context(), id.String())
	if err != nil {
		apiError := apiError{
			Code:    http.StatusInternalServerError,
			Message: err.Error(),
		}

		renderJSON(w, http.StatusInternalServerError, apiError)

		return
	}

	w.WriteHeader(http.StatusOK)
}

func renderJSON(w http.ResponseWriter, code int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)

	_ = json.NewEncoder(w).Encode(data)
}

func formatDate(t time.Time) string {
	return t.Format("Jan 02, 2006 15:04:05")
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self' cdn.redoc.ly cdnjs.cloudflare.com cdn.tailwindcss.com cdn.jsdelivr.net 'unsafe-inline' 'unsafe-eval'; "+
				"worker-src 'self' blob:; "+
				"style-src 'self' 'unsafe-inline' fonts.googleapis.com cdn.tailwindcss.com; "+
				"img-src 'self' data: cdn.redoc.ly; "+
				"font-src 'self' fonts.gstatic.com; "+
				"connect-src 'self' nominatim.openstreetmap.org")

		next.ServeHTTP(w, r)
	})
}

// Phone number formats for US
var phoneFormats = map[string]string{
	"standard":    "(XXX) XXX-XXXX",      // (555) 123-4567
	"dashes":      "XXX-XXX-XXXX",        // 555-123-4567
	"dots":        "XXX.XXX.XXXX",        // 555.123.4567
	"spaces":      "XXX XXX XXXX",        // 555 123 4567
	"plain":       "XXXXXXXXXX",          // 5551234567
	"plus1":       "+1 XXX-XXX-XXXX",     // +1 555-123-4567
	"plus1_plain": "+1XXXXXXXXXX",        // +15551234567
	"intl":        "+1 (XXX) XXX-XXXX",   // +1 (555) 123-4567
}

// ExtractRequest is the JSON request body for extraction
type ExtractRequest struct {
	JobIDs []string `json:"job_ids"`
	Type   string   `json:"type"`   // "phones" or "emails"
	Format string   `json:"format"` // phone format key
}

// extractData handles phone/email extraction from selected jobs
func (s *Server) extractData(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ExtractRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.Type == "" {
		http.Error(w, "Missing type field", http.StatusBadRequest)
		return
	}

	if len(req.JobIDs) == 0 {
		http.Error(w, "No jobs selected", http.StatusBadRequest)
		return
	}

	var results []string
	seen := make(map[string]bool) // dedupe

	// Process selected jobs
	for _, jobID := range req.JobIDs {
		filePath, err := s.svc.GetCSV(r.Context(), jobID)
		if err != nil {
			continue
		}

		extracted, err := extractFromCSV(filePath, req.Type)
		if err != nil {
			continue
		}

		for _, item := range extracted {
			if req.Type == "phones" {
				item = formatPhoneNumber(item, req.Format)
			}
			if item != "" && !seen[item] {
				seen[item] = true
				results = append(results, item)
			}
		}
	}

	if len(results) == 0 {
		http.Error(w, "No data found in selected jobs", http.StatusNotFound)
		return
	}

	// Generate output file
	filename := fmt.Sprintf("%s_%d.txt", req.Type, time.Now().Unix())
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	w.Header().Set("Content-Type", "text/plain")

	writer := bufio.NewWriter(w)
	for _, item := range results {
		writer.WriteString(item + "\n")
	}
	writer.Flush()
}

// uploadCSV handles CSV file upload for extraction
func (s *Server) uploadCSV(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	err := r.ParseMultipartForm(32 << 20) // 32MB max
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	file, _, err := r.FormFile("csv_file")
	if err != nil {
		http.Error(w, "Missing csv_file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	extractType := r.FormValue("type")
	phoneFormat := r.FormValue("format")

	if extractType == "" {
		http.Error(w, "Missing type field", http.StatusBadRequest)
		return
	}

	// Save temp file
	tempFile, err := os.CreateTemp("", "upload-*.csv")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()

	_, err = io.Copy(tempFile, file)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	extracted, err := extractFromCSV(tempFile.Name(), extractType)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Dedupe and format
	seen := make(map[string]bool)
	var results []string
	for _, item := range extracted {
		if extractType == "phones" {
			item = formatPhoneNumber(item, phoneFormat)
		}
		if item != "" && !seen[item] {
			seen[item] = true
			results = append(results, item)
		}
	}

	// Generate output file
	filename := fmt.Sprintf("%s_upload_%d.txt", extractType, time.Now().Unix())
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	w.Header().Set("Content-Type", "text/plain")

	writer := bufio.NewWriter(w)
	for _, item := range results {
		writer.WriteString(item + "\n")
	}
	writer.Flush()
}

// extractGophish handles extraction in GoPhish CSV format
func (s *Server) extractGophish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ExtractRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.Type == "" {
		http.Error(w, "Missing type field", http.StatusBadRequest)
		return
	}

	if len(req.JobIDs) == 0 {
		http.Error(w, "No jobs selected", http.StatusBadRequest)
		return
	}

	// GoPhish CSV format: First Name,Last Name,Email,Position
	var records []GophishRecord
	seen := make(map[string]bool) // dedupe by email/phone

	// Process selected jobs
	for _, jobID := range req.JobIDs {
		filePath, err := s.svc.GetCSV(r.Context(), jobID)
		if err != nil {
			continue
		}

		gophishRecords, err := extractGophishFromCSV(filePath, req.Type, req.Format)
		if err != nil {
			continue
		}

		for _, rec := range gophishRecords {
			key := rec.Email // dedupe key
			if key != "" && !seen[key] {
				seen[key] = true
				records = append(records, rec)
			}
		}
	}

	if len(records) == 0 {
		http.Error(w, "No data found in selected jobs", http.StatusNotFound)
		return
	}

	// Generate CSV output
	filename := fmt.Sprintf("gophish_%s_%d.csv", req.Type, time.Now().Unix())
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	w.Header().Set("Content-Type", "text/csv")

	writer := csv.NewWriter(w)
	// Write header
	writer.Write([]string{"First Name", "Last Name", "Email", "Position"})

	// Write records
	for _, rec := range records {
		writer.Write([]string{rec.FirstName, rec.LastName, rec.Email, rec.Position})
	}
	writer.Flush()
}

// GophishRecord represents a single GoPhish CSV row
type GophishRecord struct {
	FirstName string
	LastName  string
	Email     string
	Position  string
}

// uploadGophish handles CSV file upload and extraction in GoPhish format
func (s *Server) uploadGophish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	err := r.ParseMultipartForm(32 << 20) // 32MB max
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	file, _, err := r.FormFile("csv_file")
	if err != nil {
		http.Error(w, "Missing csv_file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	extractType := r.FormValue("type")
	phoneFormat := r.FormValue("format")

	if extractType == "" {
		http.Error(w, "Missing type field", http.StatusBadRequest)
		return
	}

	// Save temp file
	tempFile, err := os.CreateTemp("", "gophish-upload-*.csv")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()

	_, err = io.Copy(tempFile, file)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Extract in GoPhish format
	records, err := extractGophishFromCSV(tempFile.Name(), extractType, phoneFormat)
	if err != nil {
		http.Error(w, "Extraction failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Dedupe
	seen := make(map[string]bool)
	var uniqueRecords []GophishRecord
	for _, rec := range records {
		if rec.Email != "" && !seen[rec.Email] {
			seen[rec.Email] = true
			uniqueRecords = append(uniqueRecords, rec)
		}
	}

	if len(uniqueRecords) == 0 {
		http.Error(w, "No data found in uploaded CSV", http.StatusNotFound)
		return
	}

	// Generate CSV output
	filename := fmt.Sprintf("gophish_%s_upload_%d.csv", extractType, time.Now().Unix())
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	w.Header().Set("Content-Type", "text/csv")

	writer := csv.NewWriter(w)
	// Write header
	writer.Write([]string{"First Name", "Last Name", "Email", "Position"})

	// Write records
	for _, rec := range uniqueRecords {
		writer.Write([]string{rec.FirstName, rec.LastName, rec.Email, rec.Position})
	}
	writer.Flush()
}

// uploadGophishBatch handles multiple CSV file uploads and extraction in GoPhish format
func (s *Server) uploadGophishBatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	err := r.ParseMultipartForm(64 << 20) // 64MB max for multiple files
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	files := r.MultipartForm.File["csv_files"]
	if len(files) == 0 {
		http.Error(w, "No files uploaded", http.StatusBadRequest)
		return
	}

	extractType := r.FormValue("type")
	phoneFormat := r.FormValue("format")

	if extractType == "" {
		http.Error(w, "Missing type field", http.StatusBadRequest)
		return
	}

	// Process all files and collect records
	var allRecords []GophishRecord
	seen := make(map[string]bool) // dedupe across all files

	for _, fileHeader := range files {
		file, err := fileHeader.Open()
		if err != nil {
			continue
		}

		// Save temp file
		tempFile, err := os.CreateTemp("", "gophish-batch-*.csv")
		if err != nil {
			file.Close()
			continue
		}

		_, err = io.Copy(tempFile, file)
		file.Close()
		tempFile.Close()

		if err != nil {
			os.Remove(tempFile.Name())
			continue
		}

		// Extract in GoPhish format
		records, err := extractGophishFromCSV(tempFile.Name(), extractType, phoneFormat)
		os.Remove(tempFile.Name())

		if err != nil {
			continue
		}

		// Add unique records
		for _, rec := range records {
			if rec.Email != "" && !seen[rec.Email] {
				seen[rec.Email] = true
				allRecords = append(allRecords, rec)
			}
		}
	}

	if len(allRecords) == 0 {
		http.Error(w, "No data found in uploaded CSV files", http.StatusNotFound)
		return
	}

	// Generate CSV output
	filename := fmt.Sprintf("gophish_%s_batch_%d.csv", extractType, time.Now().Unix())
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	w.Header().Set("Content-Type", "text/csv")

	writer := csv.NewWriter(w)
	// Write header
	writer.Write([]string{"First Name", "Last Name", "Email", "Position"})

	// Write records
	for _, rec := range allRecords {
		writer.Write([]string{rec.FirstName, rec.LastName, rec.Email, rec.Position})
	}
	writer.Flush()
}

// extractGophishFromCSV reads a CSV file and extracts data in GoPhish format
func extractGophishFromCSV(filePath string, extractType string, phoneFormat string) ([]GophishRecord, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	reader.LazyQuotes = true
	reader.FieldsPerRecord = -1 // variable fields

	// Read header
	header, err := reader.Read()
	if err != nil {
		return nil, err
	}

	// Find column indices
	var titleIdx, categoryIdx, phoneIdx, emailIdx int = -1, -1, -1, -1

	titleNames := []string{"title", "name", "business_name", "company", "business"}
	categoryNames := []string{"category", "type", "business_type", "industry"}
	phoneNames := []string{"phone", "phone_number", "phonenumber", "tel", "telephone", "mobile", "cell"}
	emailNames := []string{"emails", "email", "email_address", "emailaddress", "e-mail", "e_mail"}

	for i, col := range header {
		colLower := strings.ToLower(strings.TrimSpace(col))

		// Check title
		for _, target := range titleNames {
			if colLower == target || strings.Contains(colLower, target) {
				if titleIdx == -1 {
					titleIdx = i
				}
				break
			}
		}

		// Check category
		for _, target := range categoryNames {
			if colLower == target || strings.Contains(colLower, target) {
				if categoryIdx == -1 {
					categoryIdx = i
				}
				break
			}
		}

		// Check phone
		for _, target := range phoneNames {
			if colLower == target || strings.Contains(colLower, target) {
				if phoneIdx == -1 {
					phoneIdx = i
				}
				break
			}
		}

		// Check email
		for _, target := range emailNames {
			if colLower == target || strings.Contains(colLower, target) {
				if emailIdx == -1 {
					emailIdx = i
				}
				break
			}
		}
	}

	// Determine which column to use for Email field based on type
	var targetIdx int
	if extractType == "emails" {
		if emailIdx == -1 {
			return nil, fmt.Errorf("email column not found")
		}
		targetIdx = emailIdx
	} else {
		if phoneIdx == -1 {
			return nil, fmt.Errorf("phone column not found")
		}
		targetIdx = phoneIdx
	}

	var records []GophishRecord
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}

		// Get title (name)
		var title string
		if titleIdx != -1 && titleIdx < len(record) {
			title = strings.TrimSpace(record[titleIdx])
		}

		// Get category (position)
		var category string
		if categoryIdx != -1 && categoryIdx < len(record) {
			category = strings.TrimSpace(record[categoryIdx])
		}

		// Get email or phone for Email column
		if targetIdx >= len(record) {
			continue
		}

		value := strings.TrimSpace(record[targetIdx])
		if value == "" || value == "null" {
			continue
		}

		// Split name into first and last
		firstName, lastName := splitName(title)

		if extractType == "emails" {
			// Handle multiple emails
			emails := strings.Split(value, ",")
			for _, email := range emails {
				email = strings.TrimSpace(email)
				if email != "" && strings.Contains(email, "@") {
					records = append(records, GophishRecord{
						FirstName: firstName,
						LastName:  lastName,
						Email:     email,
						Position:  category,
					})
				}
			}
		} else {
			// Phone - format and use as Email field
			formattedPhone := formatPhoneNumber(value, phoneFormat)
			if formattedPhone != "" {
				records = append(records, GophishRecord{
					FirstName: firstName,
					LastName:  lastName,
					Email:     formattedPhone,
					Position:  category,
				})
			}
		}
	}

	return records, nil
}

// splitName splits a full name into first and last name
func splitName(fullName string) (string, string) {
	fullName = strings.TrimSpace(fullName)
	if fullName == "" {
		return "", ""
	}

	parts := strings.Fields(fullName)
	if len(parts) == 0 {
		return "", ""
	}

	if len(parts) == 1 {
		// Single word - use same for both
		return parts[0], parts[0]
	}

	// First word is first name, rest is last name
	firstName := parts[0]
	lastName := strings.Join(parts[1:], " ")

	return firstName, lastName
}

// extractFromCSV reads a CSV file and extracts phones or emails
func extractFromCSV(filePath string, extractType string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	reader.LazyQuotes = true
	reader.FieldsPerRecord = -1 // variable fields

	// Read header
	header, err := reader.Read()
	if err != nil {
		return nil, err
	}

	// Find column index - support multiple naming conventions
	var colIndex int = -1
	var phoneNames = []string{"phone", "phone_number", "phonenumber", "tel", "telephone", "mobile", "cell"}
	var emailNames = []string{"emails", "email", "email_address", "emailaddress", "e-mail", "e_mail"}

	targetNames := phoneNames
	if extractType == "emails" {
		targetNames = emailNames
	}

	for i, col := range header {
		colLower := strings.ToLower(strings.TrimSpace(col))
		for _, target := range targetNames {
			if colLower == target || strings.Contains(colLower, target) {
				colIndex = i
				break
			}
		}
		if colIndex != -1 {
			break
		}
	}

	if colIndex == -1 {
		return nil, fmt.Errorf("column for %s not found (tried: %v)", extractType, targetNames)
	}

	var results []string
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}

		if colIndex >= len(record) {
			continue
		}

		value := strings.TrimSpace(record[colIndex])
		if value == "" || value == "null" {
			continue
		}

		if extractType == "emails" {
			// Split by comma for multiple emails
			emails := strings.Split(value, ",")
			for _, email := range emails {
				email = strings.TrimSpace(email)
				if email != "" && strings.Contains(email, "@") {
					results = append(results, email)
				}
			}
		} else {
			// Phone - extract digits
			results = append(results, value)
		}
	}

	return results, nil
}

// formatPhoneNumber formats a phone number according to the specified format
func formatPhoneNumber(phone string, format string) string {
	// Extract only digits
	re := regexp.MustCompile(`\d`)
	digits := strings.Join(re.FindAllString(phone, -1), "")

	// Handle country code
	if len(digits) == 11 && strings.HasPrefix(digits, "1") {
		digits = digits[1:] // Remove leading 1
	}

	if len(digits) != 10 {
		return "" // Invalid US number
	}

	area := digits[0:3]
	exchange := digits[3:6]
	subscriber := digits[6:10]

	switch format {
	case "standard":
		return fmt.Sprintf("(%s) %s-%s", area, exchange, subscriber)
	case "dashes":
		return fmt.Sprintf("%s-%s-%s", area, exchange, subscriber)
	case "dots":
		return fmt.Sprintf("%s.%s.%s", area, exchange, subscriber)
	case "spaces":
		return fmt.Sprintf("%s %s %s", area, exchange, subscriber)
	case "plain":
		// Return with dashes to prevent Excel from treating as number
		return fmt.Sprintf("%s-%s-%s", area, exchange, subscriber)
	case "plus1":
		return fmt.Sprintf("+1 %s-%s-%s", area, exchange, subscriber)
	case "plus1_plain":
		return fmt.Sprintf("+1%s%s%s", area, exchange, subscriber)
	case "intl":
		return fmt.Sprintf("+1 (%s) %s-%s", area, exchange, subscriber)
	default:
		return fmt.Sprintf("(%s) %s-%s", area, exchange, subscriber)
	}
}

// isNumericString checks if a string contains only digits (possibly with + prefix)
func isNumericString(s string) bool {
	if s == "" {
		return false
	}
	// Check if it's all digits or starts with + followed by digits
	cleaned := strings.TrimPrefix(s, "+")
	for _, c := range cleaned {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// geocodeProxy proxies geocoding requests to Nominatim to avoid CORS issues
func (s *Server) geocodeProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get query parameters
	query := r.URL.Query().Get("q")
	postalcode := r.URL.Query().Get("postalcode")
	country := r.URL.Query().Get("country")

	if query == "" && postalcode == "" {
		http.Error(w, "Missing query or postalcode parameter", http.StatusBadRequest)
		return
	}

	// Build Nominatim URL
	nominatimURL := "https://nominatim.openstreetmap.org/search?format=json&limit=1"
	if query != "" {
		nominatimURL += "&q=" + url.QueryEscape(query)
	}
	if postalcode != "" {
		nominatimURL += "&postalcode=" + url.QueryEscape(postalcode)
	}
	if country != "" {
		nominatimURL += "&country=" + url.QueryEscape(country)
	}
	nominatimURL += "&countrycodes=us"

	// Create request with proper User-Agent (required by Nominatim)
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", nominatimURL, nil)
	if err != nil {
		http.Error(w, "Failed to create request: "+err.Error(), http.StatusInternalServerError)
		return
	}
	req.Header.Set("User-Agent", "GoogleMapsScraper/1.0 (https://github.com/user/gmapscraper)")

	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Geocoding request failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	w.Header().Set("Content-Type", "application/json")

	// Copy response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Failed to read response: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(resp.StatusCode)
	w.Write(body)
}
