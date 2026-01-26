package core

import (
	"net/http"
)

// LandingPageGenerator generates dynamic, professional landing pages
type LandingPageGenerator struct {
	cfg              *Config
	templateRegistry *TemplateRegistry
	contentGenerator *ContentGenerator
}

// NewLandingPageGenerator creates a new landing page generator
func NewLandingPageGenerator(cfg *Config) *LandingPageGenerator {
	return &LandingPageGenerator{
		cfg:              cfg,
		templateRegistry: NewTemplateRegistry(),
		contentGenerator: NewContentGenerator(),
	}
}

// GenerateLandingPage generates a complete HTML landing page based on visitor fingerprint
func (g *LandingPageGenerator) GenerateLandingPage(req *http.Request) string {
	// Get visitor fingerprint (deterministic based on IP, User-Agent, etc.)
	fingerprint := GetVisitorFingerprintSimple(req)

	// Get domain
	domain := g.cfg.GetBaseDomain()
	if domain == "" {
		domain = req.Host
	}

	// Generate dynamic content based on visitor fingerprint
	content := g.contentGenerator.GenerateContent(domain, fingerprint)

	// Get template for visitor's category
	template := g.templateRegistry.GetTemplate(fingerprint.GetTemplateCategory())

	// Render the page
	return template.RenderFunc(content)
}
