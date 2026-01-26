package core

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLandingPageGenerator(t *testing.T) {
	// Create a mock config
	cfg := &Config{
		general: &GeneralConfig{
			Domain: "example.com",
		},
	}

	generator := NewLandingPageGenerator(cfg)

	// Create mock requests with different "visitors"
	tests := []struct {
		name      string
		ip        string
		userAgent string
	}{
		{"Visitor 1", "192.168.1.1", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
		{"Visitor 2", "192.168.1.2", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"},
		{"Visitor 3", "192.168.1.3", "Mozilla/5.0 (X11; Linux x86_64)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "https://example.com/", nil)
			req.RemoteAddr = tt.ip + ":12345"
			req.Header.Set("User-Agent", tt.userAgent)

			// Generate the landing page
			html := generator.GenerateLandingPage(req)

			// Verify the HTML contains expected elements
			if !strings.Contains(html, "<!DOCTYPE html>") {
				t.Error("Generated HTML should contain DOCTYPE")
			}

			if !strings.Contains(html, "Example") {
				t.Error("Generated HTML should contain company name derived from domain")
			}

			// Verify responsive design elements
			if !strings.Contains(html, "viewport") {
				t.Error("Generated HTML should contain viewport meta tag for responsiveness")
			}

			if !strings.Contains(html, "@media") {
				t.Error("Generated HTML should contain media queries for responsiveness")
			}

			// Verify same visitor gets same content
			html2 := generator.GenerateLandingPage(req)
			if html != html2 {
				t.Error("Same visitor should get identical landing page")
			}

			t.Logf("%s: Generated %d bytes of HTML", tt.name, len(html))
		})
	}
}

func TestVisitorFingerprinting(t *testing.T) {
	// Test that different visitors get different templates
	req1 := httptest.NewRequest("GET", "https://example.com/", nil)
	req1.RemoteAddr = "192.168.1.1:12345"
	req1.Header.Set("User-Agent", "Mozilla/5.0 (Windows)")

	req2 := httptest.NewRequest("GET", "https://example.com/", nil)
	req2.RemoteAddr = "192.168.1.2:12345"
	req2.Header.Set("User-Agent", "Mozilla/5.0 (Mac)")

	fp1 := GetVisitorFingerprintSimple(req1)
	fp2 := GetVisitorFingerprintSimple(req2)

	// Verify fingerprints are different
	if fp1.Hash == fp2.Hash {
		t.Error("Different visitors should have different fingerprints")
	}

	// Verify same visitor gets same fingerprint
	fp1_again := GetVisitorFingerprintSimple(req1)
	if fp1.Hash != fp1_again.Hash {
		t.Error("Same visitor should get same fingerprint")
	}

	t.Logf("Visitor 1 fingerprint: %s (Template: %d, Color: %d)",
		fp1.Hash[:8], fp1.TemplateIndex, fp1.ColorIndex)
	t.Logf("Visitor 2 fingerprint: %s (Template: %d, Color: %d)",
		fp2.Hash[:8], fp2.TemplateIndex, fp2.ColorIndex)
}

func TestTemplateCategories(t *testing.T) {
	// Verify all template categories have content pools
	cg := NewContentGenerator()

	categories := []TemplateCategory{
		TemplateCorporate,
		TemplateTechStartup,
		TemplateFinance,
		TemplateHealthcare,
		TemplateEcommerce,
		TemplateAgency,
		TemplateConsulting,
		TemplateEducation,
		TemplateSecurity,
		TemplateClassic,
	}

	for _, category := range categories {
		pool := cg.pools[category]
		if pool == nil {
			t.Errorf("Content pool missing for category: %s", category.String())
			continue
		}

		if len(pool.Taglines) == 0 {
			t.Errorf("No taglines for category: %s", category.String())
		}

		if len(pool.Services) == 0 {
			t.Errorf("No services for category: %s", category.String())
		}

		if len(pool.Features) == 0 {
			t.Errorf("No features for category: %s", category.String())
		}

		t.Logf("Category %s: %d taglines, %d services, %d features",
			category.String(), len(pool.Taglines), len(pool.Services), len(pool.Features))
	}
}

func TestTemplateRegistry(t *testing.T) {
	// Verify all templates are registered
	tr := NewTemplateRegistry()

	categories := []TemplateCategory{
		TemplateCorporate,
		TemplateTechStartup,
		TemplateFinance,
		TemplateHealthcare,
		TemplateEcommerce,
		TemplateAgency,
		TemplateConsulting,
		TemplateEducation,
		TemplateSecurity,
		TemplateClassic,
	}

	for _, category := range categories {
		template := tr.GetTemplate(category)
		if template == nil {
			t.Errorf("Template missing for category: %s", category.String())
			continue
		}

		if template.RenderFunc == nil {
			t.Errorf("RenderFunc missing for category: %s", category.String())
		}

		t.Logf("Template %s: %s", category.String(), template.Name)
	}
}

func TestColorSchemes(t *testing.T) {
	schemes := GetColorSchemes()

	if len(schemes) < 8 {
		t.Errorf("Expected at least 8 color schemes, got %d", len(schemes))
	}

	for i, scheme := range schemes {
		if scheme.Name == "" {
			t.Errorf("Color scheme %d has no name", i)
		}

		if scheme.Primary == "" {
			t.Errorf("Color scheme %s has no primary color", scheme.Name)
		}

		t.Logf("Color scheme: %s (Primary: %s, Secondary: %s)",
			scheme.Name, scheme.Primary, scheme.Secondary)
	}
}
