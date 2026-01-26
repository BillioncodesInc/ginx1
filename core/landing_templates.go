package core

import (
	"fmt"
	"strings"
)

// LandingTemplate represents a landing page template
type LandingTemplate struct {
	Category    TemplateCategory
	Name        string
	Description string
	RenderFunc  func(*DynamicContent) string
}

// TemplateRegistry holds all available templates
type TemplateRegistry struct {
	templates map[TemplateCategory]*LandingTemplate
}

// NewTemplateRegistry creates a new template registry with all templates
func NewTemplateRegistry() *TemplateRegistry {
	tr := &TemplateRegistry{
		templates: make(map[TemplateCategory]*LandingTemplate),
	}
	tr.registerTemplates()
	return tr
}

// GetTemplate returns a template for a specific category
func (tr *TemplateRegistry) GetTemplate(category TemplateCategory) *LandingTemplate {
	if template, ok := tr.templates[category]; ok {
		return template
	}
	// Fallback to classic
	return tr.templates[TemplateClassic]
}

// registerTemplates initializes all template definitions
func (tr *TemplateRegistry) registerTemplates() {
	tr.templates[TemplateCorporate] = &LandingTemplate{
		Category:    TemplateCorporate,
		Name:        "Corporate Professional",
		Description: "Clean, professional design for enterprise",
		RenderFunc:  renderCorporateTemplate,
	}

	tr.templates[TemplateTechStartup] = &LandingTemplate{
		Category:    TemplateTechStartup,
		Name:        "Tech Startup Modern",
		Description: "Modern gradient design with bold typography",
		RenderFunc:  renderTechStartupTemplate,
	}

	tr.templates[TemplateFinance] = &LandingTemplate{
		Category:    TemplateFinance,
		Name:        "Finance Conservative",
		Description: "Trust-focused design with stability elements",
		RenderFunc:  renderFinanceTemplate,
	}

	tr.templates[TemplateHealthcare] = &LandingTemplate{
		Category:    TemplateHealthcare,
		Name:        "Healthcare Clean",
		Description: "Calming, accessible healthcare design",
		RenderFunc:  renderHealthcareTemplate,
	}

	tr.templates[TemplateEcommerce] = &LandingTemplate{
		Category:    TemplateEcommerce,
		Name:        "E-commerce Product",
		Description: "Product-focused with strong CTAs",
		RenderFunc:  renderEcommerceTemplate,
	}

	tr.templates[TemplateAgency] = &LandingTemplate{
		Category:    TemplateAgency,
		Name:        "Agency Creative",
		Description: "Bold, creative with visual impact",
		RenderFunc:  renderAgencyTemplate,
	}

	tr.templates[TemplateConsulting] = &LandingTemplate{
		Category:    TemplateConsulting,
		Name:        "Consulting Minimal",
		Description: "Elegant, minimal professional design",
		RenderFunc:  renderConsultingTemplate,
	}

	tr.templates[TemplateEducation] = &LandingTemplate{
		Category:    TemplateEducation,
		Name:        "Education Friendly",
		Description: "Friendly, accessible learning design",
		RenderFunc:  renderEducationTemplate,
	}

	tr.templates[TemplateSecurity] = &LandingTemplate{
		Category:    TemplateSecurity,
		Name:        "Security Dark",
		Description: "Technical dark theme for security",
		RenderFunc:  renderSecurityTemplate,
	}

	tr.templates[TemplateClassic] = &LandingTemplate{
		Category:    TemplateClassic,
		Name:        "Classic Traditional",
		Description: "Timeless, traditional business design",
		RenderFunc:  renderClassicTemplate,
	}
}

// Helper function to generate CSS variables from color scheme
func generateCSSVariables(cs ColorScheme) string {
	return fmt.Sprintf(`
		--color-primary: %s;
		--color-secondary: %s;
		--color-accent: %s;
		--color-bg: %s;
		--color-surface: %s;
		--color-text: %s;
		--color-text-muted: %s;
		--color-border: %s;
		--color-success: %s;
		--color-warning: %s;
		--color-error: %s;
	`, cs.Primary, cs.Secondary, cs.Accent, cs.Background, cs.Surface,
		cs.Text, cs.TextMuted, cs.Border, cs.Success, cs.Warning, cs.Error)
}

// Helper function to render services list
func renderServices(services []string, classes string) string {
	var items []string
	for _, service := range services {
		items = append(items, fmt.Sprintf(`<div class="%s">%s</div>`, classes, service))
	}
	return strings.Join(items, "\n")
}

// Helper function to render features
func renderFeatures(features []Feature, cardClass string) string {
	var items []string
	for _, feature := range features {
		items = append(items, fmt.Sprintf(`
			<div class="%s">
				<div class="feature-icon">%s</div>
				<h3 class="feature-title">%s</h3>
				<p class="feature-desc">%s</p>
			</div>
		`, cardClass, feature.Icon, feature.Title, feature.Description))
	}
	return strings.Join(items, "\n")
}

// Helper function to render stats
func renderStats(stats []Stat, itemClass string) string {
	var items []string
	for _, stat := range stats {
		items = append(items, fmt.Sprintf(`
			<div class="%s">
				<div class="stat-value">%s</div>
				<div class="stat-label">%s</div>
			</div>
		`, itemClass, stat.Value, stat.Label))
	}
	return strings.Join(items, "\n")
}

// Helper function to render navigation
func renderNav(items []string) string {
	var navItems []string
	for _, item := range items {
		navItems = append(navItems, fmt.Sprintf(`<a href="#">%s</a>`, item))
	}
	return strings.Join(navItems, "\n")
}

// Helper function to render footer links
func renderFooterLinks(links []string) string {
	var linkItems []string
	for _, link := range links {
		linkItems = append(linkItems, fmt.Sprintf(`<a href="#">%s</a>`, link))
	}
	return strings.Join(linkItems, "\n")
}

// Corporate Template - Professional, clean design for enterprise
func renderCorporateTemplate(content *DynamicContent) string {
	servicesHTML := renderServices(content.Services, "service-item")
	featuresHTML := renderFeatures(content.Features, "feature-card")
	statsHTML := renderStats(content.Stats, "stat-item")
	navHTML := renderNav(content.NavItems)
	footerLinksHTML := renderFooterLinks(content.FooterLinks)

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow">
    <title>%s - %s</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        :root {
            %s
        }

        html {
            font-size: 16px;
            -webkit-font-smoothing: antialiased;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--color-bg);
            color: var(--color-text);
            line-height: 1.6;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 24px;
        }

        /* Header */
        header {
            background: var(--color-surface);
            border-bottom: 1px solid var(--color-border);
            padding: 20px 0;
            position: sticky;
            top: 0;
            z-index: 100;
        }

        .header-inner {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .logo {
            font-size: 24px;
            font-weight: 700;
            color: var(--color-primary);
            text-decoration: none;
        }

        nav {
            display: flex;
            gap: 32px;
        }

        nav a {
            color: var(--color-text-muted);
            text-decoration: none;
            font-weight: 500;
            transition: color 0.2s;
        }

        nav a:hover {
            color: var(--color-primary);
        }

        /* Hero Section */
        .hero {
            padding: 100px 0;
            text-align: center;
        }

        .hero h1 {
            font-size: 48px;
            font-weight: 700;
            line-height: 1.2;
            margin-bottom: 24px;
            color: var(--color-text);
        }

        .tagline {
            font-size: 20px;
            color: var(--color-accent);
            font-weight: 600;
            margin-bottom: 16px;
        }

        .hero p {
            font-size: 18px;
            color: var(--color-text-muted);
            max-width: 700px;
            margin: 0 auto 40px;
        }

        .cta-button {
            display: inline-block;
            background: var(--color-primary);
            color: white;
            padding: 16px 48px;
            border-radius: 8px;
            text-decoration: none;
            font-weight: 600;
            font-size: 16px;
            transition: transform 0.2s, box-shadow 0.2s;
        }

        .cta-button:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(0,0,0,0.15);
        }

        /* Services Grid */
        .services {
            padding: 80px 0;
            background: var(--color-surface);
        }

        .section-title {
            font-size: 36px;
            font-weight: 700;
            text-align: center;
            margin-bottom: 60px;
        }

        .services-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 24px;
        }

        .service-item {
            padding: 24px;
            background: var(--color-bg);
            border: 1px solid var(--color-border);
            border-radius: 8px;
            text-align: center;
            font-weight: 500;
            transition: border-color 0.2s;
        }

        .service-item:hover {
            border-color: var(--color-primary);
        }

        /* Features Section */
        .features {
            padding: 80px 0;
        }

        .features-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 40px;
        }

        .feature-card {
            text-align: center;
        }

        .feature-icon {
            font-size: 48px;
            margin-bottom: 16px;
        }

        .feature-title {
            font-size: 20px;
            font-weight: 600;
            margin-bottom: 12px;
        }

        .feature-desc {
            color: var(--color-text-muted);
            font-size: 15px;
        }

        /* Stats Section */
        .stats {
            padding: 80px 0;
            background: var(--color-primary);
            color: white;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 40px;
            text-align: center;
        }

        .stat-value {
            font-size: 48px;
            font-weight: 700;
            margin-bottom: 8px;
        }

        .stat-label {
            font-size: 16px;
            opacity: 0.9;
        }

        /* Footer */
        footer {
            background: var(--color-surface);
            border-top: 1px solid var(--color-border);
            padding: 40px 0;
        }

        .footer-inner {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .footer-links {
            display: flex;
            gap: 24px;
        }

        .footer-links a {
            color: var(--color-text-muted);
            text-decoration: none;
            font-size: 14px;
        }

        .footer-links a:hover {
            color: var(--color-text);
        }

        @media (max-width: 768px) {
            nav {
                display: none;
            }

            .hero h1 {
                font-size: 32px;
            }

            .services-grid,
            .features-grid,
            .stats-grid {
                grid-template-columns: 1fr;
            }

            .footer-inner {
                flex-direction: column;
                gap: 20px;
                text-align: center;
            }
        }
    </style>
</head>
<body>
    <header>
        <div class="container">
            <div class="header-inner">
                <a href="/" class="logo">%s</a>
                <nav>
                    %s
                </nav>
            </div>
        </div>
    </header>

    <main>
        <section class="hero">
            <div class="container">
                <div class="tagline">%s</div>
                <h1>%s</h1>
                <p>%s</p>
                <a href="#" class="cta-button">%s</a>
            </div>
        </section>

        <section class="services">
            <div class="container">
                <h2 class="section-title">Our Services</h2>
                <div class="services-grid">
                    %s
                </div>
            </div>
        </section>

        <section class="features">
            <div class="container">
                <h2 class="section-title">Why Choose Us</h2>
                <div class="features-grid">
                    %s
                </div>
            </div>
        </section>

        <section class="stats">
            <div class="container">
                <div class="stats-grid">
                    %s
                </div>
            </div>
        </section>
    </main>

    <footer>
        <div class="container">
            <div class="footer-inner">
                <div>&copy; %d %s. All rights reserved.</div>
                <div class="footer-links">
                    %s
                </div>
            </div>
        </div>
    </footer>
</body>
</html>`,
		content.CompanyName, content.Tagline,
		generateCSSVariables(content.ColorScheme),
		content.CompanyName, navHTML,
		content.Tagline, content.Headline, content.Description, content.CTAText,
		servicesHTML, featuresHTML, statsHTML,
		content.Year, content.CompanyName, footerLinksHTML)
}

// Tech Startup Template - Modern gradient design
func renderTechStartupTemplate(content *DynamicContent) string {
	servicesHTML := renderServices(content.Services, "service-card")
	featuresHTML := renderFeatures(content.Features, "feature-item")
	statsHTML := renderStats(content.Stats, "stat-box")
	navHTML := renderNav(content.NavItems)
	footerLinksHTML := renderFooterLinks(content.FooterLinks)

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow">
    <title>%s - %s</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        :root {
            %s
        }

        html {
            font-size: 16px;
        }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--color-bg);
            color: var(--color-text);
            line-height: 1.6;
        }

        .container {
            max-width: 1280px;
            margin: 0 auto;
            padding: 0 32px;
        }

        /* Header with gradient */
        header {
            background: linear-gradient(135deg, var(--color-primary), var(--color-secondary));
            padding: 16px 0;
            box-shadow: 0 4px 20px rgba(0,0,0,0.1);
        }

        .header-inner {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .logo {
            font-size: 28px;
            font-weight: 800;
            color: white;
            text-decoration: none;
            letter-spacing: -1px;
        }

        nav {
            display: flex;
            gap: 40px;
        }

        nav a {
            color: rgba(255,255,255,0.9);
            text-decoration: none;
            font-weight: 600;
            transition: color 0.2s;
        }

        nav a:hover {
            color: white;
        }

        /* Hero with bold typography */
        .hero {
            background: linear-gradient(135deg, var(--color-primary), var(--color-secondary));
            padding: 120px 0;
            color: white;
            text-align: center;
        }

        .hero h1 {
            font-size: 64px;
            font-weight: 900;
            line-height: 1.1;
            margin-bottom: 24px;
            letter-spacing: -2px;
        }

        .tagline {
            font-size: 24px;
            font-weight: 700;
            margin-bottom: 20px;
            opacity: 0.95;
        }

        .hero p {
            font-size: 20px;
            max-width: 700px;
            margin: 0 auto 48px;
            opacity: 0.9;
        }

        .cta-button {
            display: inline-block;
            background: white;
            color: var(--color-primary);
            padding: 18px 48px;
            border-radius: 50px;
            text-decoration: none;
            font-weight: 700;
            font-size: 18px;
            transition: transform 0.2s, box-shadow 0.2s;
            box-shadow: 0 8px 30px rgba(0,0,0,0.2);
        }

        .cta-button:hover {
            transform: translateY(-3px);
            box-shadow: 0 12px 40px rgba(0,0,0,0.3);
        }

        /* Services with cards */
        .services {
            padding: 100px 0;
        }

        .section-title {
            font-size: 42px;
            font-weight: 800;
            text-align: center;
            margin-bottom: 60px;
            letter-spacing: -1px;
        }

        .services-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 32px;
        }

        .service-card {
            padding: 32px;
            background: var(--color-surface);
            border-radius: 16px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.08);
            text-align: center;
            font-weight: 600;
            font-size: 16px;
            transition: transform 0.2s, box-shadow 0.2s;
        }

        .service-card:hover {
            transform: translateY(-4px);
            box-shadow: 0 8px 30px rgba(0,0,0,0.12);
        }

        /* Features */
        .features {
            padding: 100px 0;
            background: var(--color-surface);
        }

        .features-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
            gap: 48px;
        }

        .feature-item {
            text-align: center;
        }

        .feature-icon {
            font-size: 64px;
            margin-bottom: 24px;
            filter: drop-shadow(0 4px 12px rgba(0,0,0,0.1));
        }

        .feature-title {
            font-size: 22px;
            font-weight: 700;
            margin-bottom: 12px;
        }

        .feature-desc {
            color: var(--color-text-muted);
            font-size: 16px;
        }

        /* Stats */
        .stats {
            padding: 100px 0;
            background: linear-gradient(135deg, var(--color-accent), var(--color-secondary));
            color: white;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 48px;
            text-align: center;
        }

        .stat-box {
            padding: 24px;
            background: rgba(255,255,255,0.1);
            border-radius: 16px;
            backdrop-filter: blur(10px);
        }

        .stat-value {
            font-size: 52px;
            font-weight: 900;
            margin-bottom: 8px;
        }

        .stat-label {
            font-size: 16px;
            opacity: 0.9;
        }

        /* Footer */
        footer {
            background: var(--color-surface);
            padding: 48px 0;
        }

        .footer-inner {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .footer-links {
            display: flex;
            gap: 32px;
        }

        .footer-links a {
            color: var(--color-text-muted);
            text-decoration: none;
            font-weight: 600;
        }

        .footer-links a:hover {
            color: var(--color-text);
        }

        @media (max-width: 768px) {
            nav {
                display: none;
            }

            .hero h1 {
                font-size: 40px;
            }

            .services-grid,
            .features-grid {
                grid-template-columns: 1fr;
            }

            .footer-inner {
                flex-direction: column;
                gap: 24px;
                text-align: center;
            }
        }
    </style>
</head>
<body>
    <header>
        <div class="container">
            <div class="header-inner">
                <a href="/" class="logo">%s</a>
                <nav>
                    %s
                </nav>
            </div>
        </div>
    </header>

    <main>
        <section class="hero">
            <div class="container">
                <div class="tagline">%s</div>
                <h1>%s</h1>
                <p>%s</p>
                <a href="#" class="cta-button">%s</a>
            </div>
        </section>

        <section class="services">
            <div class="container">
                <h2 class="section-title">What We Offer</h2>
                <div class="services-grid">
                    %s
                </div>
            </div>
        </section>

        <section class="features">
            <div class="container">
                <h2 class="section-title">Features</h2>
                <div class="features-grid">
                    %s
                </div>
            </div>
        </section>

        <section class="stats">
            <div class="container">
                <div class="stats-grid">
                    %s
                </div>
            </div>
        </section>
    </main>

    <footer>
        <div class="container">
            <div class="footer-inner">
                <div>&copy; %d %s</div>
                <div class="footer-links">
                    %s
                </div>
            </div>
        </div>
    </footer>
</body>
</html>`,
		content.CompanyName, content.Tagline,
		generateCSSVariables(content.ColorScheme),
		content.CompanyName, navHTML,
		content.Tagline, content.Headline, content.Description, content.CTAText,
		servicesHTML, featuresHTML, statsHTML,
		content.Year, content.CompanyName, footerLinksHTML)
}

// Continue with remaining templates in next part...
// (Finance, Healthcare, E-commerce, Agency, Consulting, Education, Security, Classic)

// renderFinanceTemplate - Conservative, trust-focused design
func renderFinanceTemplate(content *DynamicContent) string {
	// Simplified version - similar structure to corporate but with more conservative styling
	return renderCorporateTemplate(content) // Reuse for now, can customize later
}

// renderHealthcareTemplate - Clean, calming design
func renderHealthcareTemplate(content *DynamicContent) string {
	return renderCorporateTemplate(content) // Reuse for now, can customize later
}

// renderEcommerceTemplate - Product-focused design
func renderEcommerceTemplate(content *DynamicContent) string {
	return renderTechStartupTemplate(content) // Reuse for now, can customize later
}

// renderAgencyTemplate - Bold, creative design
func renderAgencyTemplate(content *DynamicContent) string {
	return renderTechStartupTemplate(content) // Reuse for now, can customize later
}

// renderConsultingTemplate - Minimal, elegant design
func renderConsultingTemplate(content *DynamicContent) string {
	return renderCorporateTemplate(content) // Reuse for now, can customize later
}

// renderEducationTemplate - Friendly, accessible design
func renderEducationTemplate(content *DynamicContent) string {
	return renderTechStartupTemplate(content) // Reuse for now, can customize later
}

// renderSecurityTemplate - Dark, technical design
func renderSecurityTemplate(content *DynamicContent) string {
	servicesHTML := renderServices(content.Services, "service-item")
	featuresHTML := renderFeatures(content.Features, "feature-card")
	statsHTML := renderStats(content.Stats, "stat-item")
	navHTML := renderNav(content.NavItems)
	footerLinksHTML := renderFooterLinks(content.FooterLinks)

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow">
    <title>%s - %s</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        :root {
            %s
        }

        html {
            font-size: 16px;
        }

        body {
            font-family: 'Courier New', monospace;
            background: #0a0a0a;
            color: #00ff87;
            line-height: 1.6;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 24px;
        }

        /* Dark header */
        header {
            background: #111;
            border-bottom: 2px solid #00ff87;
            padding: 20px 0;
        }

        .header-inner {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .logo {
            font-size: 24px;
            font-weight: 700;
            color: #00ff87;
            text-decoration: none;
            font-family: monospace;
        }

        nav {
            display: flex;
            gap: 32px;
        }

        nav a {
            color: #888;
            text-decoration: none;
            font-weight: 500;
            transition: color 0.2s;
        }

        nav a:hover {
            color: #00ff87;
        }

        /* Hero */
        .hero {
            padding: 100px 0;
            text-align: center;
            border-bottom: 1px solid #222;
        }

        .hero h1 {
            font-size: 48px;
            font-weight: 700;
            line-height: 1.2;
            margin-bottom: 24px;
            color: #00ff87;
            text-shadow: 0 0 20px rgba(0,255,135,0.5);
        }

        .tagline {
            font-size: 20px;
            color: #60efff;
            font-weight: 600;
            margin-bottom: 16px;
        }

        .hero p {
            font-size: 18px;
            color: #888;
            max-width: 700px;
            margin: 0 auto 40px;
        }

        .cta-button {
            display: inline-block;
            background: #00ff87;
            color: #0a0a0a;
            padding: 16px 48px;
            border-radius: 4px;
            text-decoration: none;
            font-weight: 700;
            font-size: 16px;
            transition: transform 0.2s, box-shadow 0.2s;
            text-transform: uppercase;
        }

        .cta-button:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(0,255,135,0.3);
        }

        /* Services */
        .services {
            padding: 80px 0;
            background: #111;
        }

        .section-title {
            font-size: 36px;
            font-weight: 700;
            text-align: center;
            margin-bottom: 60px;
            color: #00ff87;
        }

        .services-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 24px;
        }

        .service-item {
            padding: 24px;
            background: #1a1a1a;
            border: 1px solid #333;
            border-radius: 4px;
            text-align: center;
            font-weight: 500;
            transition: border-color 0.2s;
            color: #888;
        }

        .service-item:hover {
            border-color: #00ff87;
            color: #00ff87;
        }

        /* Features */
        .features {
            padding: 80px 0;
        }

        .features-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 40px;
        }

        .feature-card {
            text-align: center;
            padding: 32px;
            background: #111;
            border: 1px solid #222;
            border-radius: 4px;
        }

        .feature-icon {
            font-size: 48px;
            margin-bottom: 16px;
        }

        .feature-title {
            font-size: 20px;
            font-weight: 600;
            margin-bottom: 12px;
            color: #00ff87;
        }

        .feature-desc {
            color: #888;
            font-size: 15px;
        }

        /* Stats */
        .stats {
            padding: 80px 0;
            background: #00ff87;
            color: #0a0a0a;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 40px;
            text-align: center;
        }

        .stat-value {
            font-size: 48px;
            font-weight: 700;
            margin-bottom: 8px;
        }

        .stat-label {
            font-size: 16px;
            font-weight: 600;
        }

        /* Footer */
        footer {
            background: #111;
            border-top: 2px solid #00ff87;
            padding: 40px 0;
        }

        .footer-inner {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .footer-links {
            display: flex;
            gap: 24px;
        }

        .footer-links a {
            color: #888;
            text-decoration: none;
            font-size: 14px;
        }

        .footer-links a:hover {
            color: #00ff87;
        }

        @media (max-width: 768px) {
            nav {
                display: none;
            }

            .hero h1 {
                font-size: 32px;
            }

            .services-grid,
            .features-grid,
            .stats-grid {
                grid-template-columns: 1fr;
            }

            .footer-inner {
                flex-direction: column;
                gap: 20px;
                text-align: center;
            }
        }
    </style>
</head>
<body>
    <header>
        <div class="container">
            <div class="header-inner">
                <a href="/" class="logo">%s</a>
                <nav>
                    %s
                </nav>
            </div>
        </div>
    </header>

    <main>
        <section class="hero">
            <div class="container">
                <div class="tagline">%s</div>
                <h1>%s</h1>
                <p>%s</p>
                <a href="#" class="cta-button">%s</a>
            </div>
        </section>

        <section class="services">
            <div class="container">
                <h2 class="section-title">// Services</h2>
                <div class="services-grid">
                    %s
                </div>
            </div>
        </section>

        <section class="features">
            <div class="container">
                <h2 class="section-title">// Capabilities</h2>
                <div class="features-grid">
                    %s
                </div>
            </div>
        </section>

        <section class="stats">
            <div class="container">
                <div class="stats-grid">
                    %s
                </div>
            </div>
        </section>
    </main>

    <footer>
        <div class="container">
            <div class="footer-inner">
                <div>&copy; %d %s. Secured.</div>
                <div class="footer-links">
                    %s
                </div>
            </div>
        </div>
    </footer>
</body>
</html>`,
		content.CompanyName, content.Tagline,
		generateCSSVariables(content.ColorScheme),
		content.CompanyName, navHTML,
		content.Tagline, content.Headline, content.Description, content.CTAText,
		servicesHTML, featuresHTML, statsHTML,
		content.Year, content.CompanyName, footerLinksHTML)
}

// renderClassicTemplate - Traditional, timeless design
func renderClassicTemplate(content *DynamicContent) string {
	return renderCorporateTemplate(content) // Reuse corporate template as fallback
}
