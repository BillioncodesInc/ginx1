package core

import (
	"math/rand"
	"strings"
	"time"
)

// ContentPool holds all dynamic content for landing pages
type ContentPool struct {
	Category     TemplateCategory
	Taglines     []string
	Headlines    []string
	Descriptions []string
	Services     []string
	Features     []Feature
	Stats        []Stat
	Testimonials []Testimonial
	NavItems     []string
	CTAText      []string
	FooterLinks  []string
}

// Feature represents a product/service feature
type Feature struct {
	Icon        string
	Title       string
	Description string
}

// Stat represents a company statistic
type Stat struct {
	Value string
	Label string
}

// Testimonial represents a customer testimonial
type Testimonial struct {
	Quote   string
	Author  string
	Role    string
	Company string
	Avatar  string // Initials or emoji
}

// DynamicContent holds the selected content for a specific visitor
type DynamicContent struct {
	CompanyName string
	Tagline     string
	Headline    string
	Description string
	Services    []string
	Features    []Feature
	Stats       []Stat
	Testimonial *Testimonial
	NavItems    []string
	CTAText     string
	FooterLinks []string
	Year        int
	Category    TemplateCategory
	ColorScheme ColorScheme
}

// ContentGenerator generates dynamic content based on visitor fingerprint
type ContentGenerator struct {
	pools map[TemplateCategory]*ContentPool
}

// NewContentGenerator creates a new content generator with all pools
func NewContentGenerator() *ContentGenerator {
	cg := &ContentGenerator{
		pools: make(map[TemplateCategory]*ContentPool),
	}
	cg.initializePools()
	return cg
}

// GenerateContent creates dynamic content for a visitor
func (cg *ContentGenerator) GenerateContent(domain string, fingerprint *VisitorFingerprint) *DynamicContent {
	category := fingerprint.GetTemplateCategory()
	pool := cg.pools[category]
	if pool == nil {
		pool = cg.pools[TemplateClassic] // Fallback
	}

	// Use deterministic random based on visitor seed
	rng := rand.New(rand.NewSource(fingerprint.ContentSeed))

	// Extract company name from domain
	companyName := extractCompanyNameFromDomain(domain)

	// Select content deterministically
	content := &DynamicContent{
		CompanyName: companyName,
		Tagline:     selectRandom(pool.Taglines, rng),
		Headline:    selectRandom(pool.Headlines, rng),
		Description: selectRandom(pool.Descriptions, rng),
		Services:    selectMultiple(pool.Services, 4, rng),
		Features:    selectFeatures(pool.Features, 3, rng),
		Stats:       selectStats(pool.Stats, 4, rng),
		NavItems:    pool.NavItems,
		CTAText:     selectRandom(pool.CTAText, rng),
		FooterLinks: pool.FooterLinks,
		Year:        time.Now().Year(),
		Category:    category,
		ColorScheme: fingerprint.GetColorScheme(),
	}

	// Add testimonial if available
	if len(pool.Testimonials) > 0 {
		idx := rng.Intn(len(pool.Testimonials))
		content.Testimonial = &pool.Testimonials[idx]
	}

	return content
}

func extractCompanyNameFromDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) >= 2 {
		name := parts[len(parts)-2]
		if len(name) > 0 {
			return strings.ToUpper(name[:1]) + name[1:]
		}
	}
	return "Company"
}

func selectRandom(items []string, rng *rand.Rand) string {
	if len(items) == 0 {
		return ""
	}
	return items[rng.Intn(len(items))]
}

func selectMultiple(items []string, count int, rng *rand.Rand) []string {
	if len(items) <= count {
		return items
	}
	// Shuffle and take first N
	shuffled := make([]string, len(items))
	copy(shuffled, items)
	rng.Shuffle(len(shuffled), func(i, j int) {
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	})
	return shuffled[:count]
}

func selectFeatures(items []Feature, count int, rng *rand.Rand) []Feature {
	if len(items) <= count {
		return items
	}
	shuffled := make([]Feature, len(items))
	copy(shuffled, items)
	rng.Shuffle(len(shuffled), func(i, j int) {
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	})
	return shuffled[:count]
}

func selectStats(items []Stat, count int, rng *rand.Rand) []Stat {
	if len(items) <= count {
		return items
	}
	shuffled := make([]Stat, len(items))
	copy(shuffled, items)
	rng.Shuffle(len(shuffled), func(i, j int) {
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	})
	return shuffled[:count]
}

// initializePools sets up all content pools
func (cg *ContentGenerator) initializePools() {
	// Corporate
	cg.pools[TemplateCorporate] = &ContentPool{
		Category: TemplateCorporate,
		Taglines: []string{
			"Enterprise Excellence",
			"Building Tomorrow's Business",
			"Where Vision Meets Execution",
			"Trusted by Industry Leaders",
		},
		Headlines: []string{
			"Transform Your Business with Enterprise Solutions",
			"Driving Digital Excellence Across Industries",
			"Your Partner in Business Transformation",
			"Enterprise-Grade Solutions for Modern Challenges",
		},
		Descriptions: []string{
			"We deliver comprehensive enterprise solutions that drive efficiency, innovation, and sustainable growth for organizations worldwide.",
			"Our proven methodologies and cutting-edge technology help businesses navigate complexity and achieve their strategic objectives.",
			"Partner with us to unlock new opportunities and build resilient, future-ready operations.",
		},
		Services: []string{
			"Strategic Consulting", "Digital Transformation", "Process Optimization",
			"Change Management", "Risk Assessment", "Compliance Solutions",
			"Enterprise Architecture", "Business Intelligence",
		},
		Features: []Feature{
			{Icon: "🏢", Title: "Enterprise Scale", Description: "Solutions built for organizations of any size"},
			{Icon: "🔒", Title: "Security First", Description: "Bank-grade security and compliance"},
			{Icon: "📊", Title: "Data-Driven", Description: "Insights that drive better decisions"},
			{Icon: "🤝", Title: "Partnership", Description: "Dedicated support and collaboration"},
			{Icon: "⚡", Title: "Agile Delivery", Description: "Fast implementation, lasting results"},
		},
		Stats: []Stat{
			{Value: "500+", Label: "Enterprise Clients"},
			{Value: "99.9%", Label: "Uptime SLA"},
			{Value: "50+", Label: "Countries Served"},
			{Value: "24/7", Label: "Global Support"},
		},
		Testimonials: []Testimonial{
			{Quote: "Transformed our operations completely. Exceptional results.", Author: "Sarah Chen", Role: "COO", Company: "Fortune 500 Company", Avatar: "SC"},
			{Quote: "The partnership exceeded all our expectations.", Author: "Michael Roberts", Role: "CTO", Company: "Global Enterprise", Avatar: "MR"},
		},
		NavItems:    []string{"Solutions", "Industries", "Resources", "About", "Contact"},
		CTAText:     []string{"Get Started", "Request Demo", "Contact Sales", "Learn More"},
		FooterLinks: []string{"Privacy Policy", "Terms of Service", "Security", "Compliance"},
	}

	// Tech Startup
	cg.pools[TemplateTechStartup] = &ContentPool{
		Category: TemplateTechStartup,
		Taglines: []string{
			"Build. Ship. Scale.",
			"The Future is Now",
			"Innovation at Speed",
			"Code the Impossible",
		},
		Headlines: []string{
			"Ship Faster with Modern Infrastructure",
			"The Platform Developers Love",
			"Scale Without Limits",
			"Build the Future Today",
		},
		Descriptions: []string{
			"Modern infrastructure for modern teams. Deploy globally in seconds, scale automatically, and focus on what matters—building great products.",
			"Join thousands of developers who trust our platform to power their most ambitious projects.",
			"From startup to enterprise, we've got the tools you need to succeed.",
		},
		Services: []string{
			"Cloud Platform", "API Gateway", "Serverless Functions",
			"Edge Computing", "CI/CD Pipeline", "Container Orchestration",
			"Real-time Database", "Authentication",
		},
		Features: []Feature{
			{Icon: "🚀", Title: "Deploy in Seconds", Description: "Push to production with zero configuration"},
			{Icon: "🌍", Title: "Global Edge Network", Description: "Low latency everywhere"},
			{Icon: "📈", Title: "Auto-scaling", Description: "Handle any traffic spike automatically"},
			{Icon: "🔧", Title: "Developer Tools", Description: "CLI, SDK, and integrations you love"},
			{Icon: "💡", Title: "AI-Powered", Description: "Smart insights and automation"},
		},
		Stats: []Stat{
			{Value: "10M+", Label: "Deployments"},
			{Value: "<50ms", Label: "Global Latency"},
			{Value: "99.99%", Label: "Uptime"},
			{Value: "100K+", Label: "Developers"},
		},
		Testimonials: []Testimonial{
			{Quote: "Reduced our deployment time from hours to seconds.", Author: "Alex Kim", Role: "Lead Engineer", Company: "TechCorp", Avatar: "AK"},
			{Quote: "The best developer experience I've ever had.", Author: "Jordan Lee", Role: "Founder", Company: "StartupXYZ", Avatar: "JL"},
		},
		NavItems:    []string{"Product", "Docs", "Pricing", "Blog", "Login"},
		CTAText:     []string{"Start Free", "Get Started", "Try Now", "Deploy Free"},
		FooterLinks: []string{"Documentation", "API Reference", "Status", "GitHub"},
	}

	// Finance
	cg.pools[TemplateFinance] = &ContentPool{
		Category: TemplateFinance,
		Taglines: []string{
			"Secure. Reliable. Trusted.",
			"Your Financial Future",
			"Banking Reimagined",
			"Wealth Management Excellence",
		},
		Headlines: []string{
			"Secure Financial Solutions for a Digital World",
			"Banking Infrastructure You Can Trust",
			"Modern Finance, Traditional Values",
			"Your Partner in Financial Success",
		},
		Descriptions: []string{
			"We provide secure, compliant financial technology solutions that help institutions and individuals achieve their financial goals.",
			"Built on decades of expertise with cutting-edge security, our platform delivers the reliability you need.",
			"From payments to wealth management, we power the future of finance.",
		},
		Services: []string{
			"Payment Processing", "Wealth Management", "Risk Analytics",
			"Regulatory Compliance", "Fraud Detection", "Digital Banking",
			"Investment Platform", "Treasury Services",
		},
		Features: []Feature{
			{Icon: "🔐", Title: "Bank-Grade Security", Description: "SOC 2 Type II certified"},
			{Icon: "📋", Title: "Full Compliance", Description: "PCI DSS, GDPR, and more"},
			{Icon: "💳", Title: "Global Payments", Description: "150+ currencies supported"},
			{Icon: "📊", Title: "Real-time Analytics", Description: "Instant insights and reporting"},
			{Icon: "🛡️", Title: "Fraud Protection", Description: "AI-powered threat detection"},
		},
		Stats: []Stat{
			{Value: "$50B+", Label: "Processed Annually"},
			{Value: "0.001%", Label: "Fraud Rate"},
			{Value: "150+", Label: "Countries"},
			{Value: "99.999%", Label: "Availability"},
		},
		Testimonials: []Testimonial{
			{Quote: "The most reliable financial infrastructure we've used.", Author: "David Park", Role: "CFO", Company: "Major Bank", Avatar: "DP"},
			{Quote: "Compliance made simple without sacrificing innovation.", Author: "Lisa Wang", Role: "Head of Risk", Company: "FinTech Leader", Avatar: "LW"},
		},
		NavItems:    []string{"Solutions", "Security", "Compliance", "About", "Contact"},
		CTAText:     []string{"Contact Us", "Request Info", "Schedule Call", "Learn More"},
		FooterLinks: []string{"Privacy", "Terms", "Security", "Regulatory"},
	}

	// Healthcare
	cg.pools[TemplateHealthcare] = &ContentPool{
		Category: TemplateHealthcare,
		Taglines: []string{
			"Care. Connect. Cure.",
			"Healthcare Innovation",
			"Better Health Outcomes",
			"Patient-Centered Technology",
		},
		Headlines: []string{
			"Transforming Healthcare Through Technology",
			"Connected Care for Better Outcomes",
			"The Future of Digital Health",
			"Empowering Healthcare Providers",
		},
		Descriptions: []string{
			"Our healthcare technology solutions connect patients, providers, and systems to deliver better care and improved outcomes.",
			"HIPAA-compliant, secure, and designed with patients in mind—we're building the future of healthcare.",
			"From telehealth to analytics, we provide the tools healthcare needs today.",
		},
		Services: []string{
			"Telehealth Platform", "EHR Integration", "Patient Portal",
			"Clinical Analytics", "Care Coordination", "Remote Monitoring",
			"Health Data Exchange", "Population Health",
		},
		Features: []Feature{
			{Icon: "🏥", Title: "HIPAA Compliant", Description: "Full regulatory compliance"},
			{Icon: "👨‍⚕️", Title: "Provider Tools", Description: "Streamlined clinical workflows"},
			{Icon: "📱", Title: "Patient Access", Description: "Care from anywhere"},
			{Icon: "🔬", Title: "Clinical Insights", Description: "Data-driven care decisions"},
			{Icon: "🤝", Title: "Interoperability", Description: "Connect any system"},
		},
		Stats: []Stat{
			{Value: "10M+", Label: "Patients Served"},
			{Value: "5000+", Label: "Healthcare Providers"},
			{Value: "99.9%", Label: "Uptime"},
			{Value: "HIPAA", Label: "Certified"},
		},
		Testimonials: []Testimonial{
			{Quote: "Improved our patient satisfaction scores by 40%.", Author: "Dr. Emily Chen", Role: "CMO", Company: "Regional Health System", Avatar: "EC"},
			{Quote: "Finally, technology that works for clinicians.", Author: "James Miller", Role: "CIO", Company: "Hospital Network", Avatar: "JM"},
		},
		NavItems:    []string{"Solutions", "For Providers", "For Patients", "Resources", "Contact"},
		CTAText:     []string{"Request Demo", "Contact Us", "Learn More", "Get Started"},
		FooterLinks: []string{"Privacy", "HIPAA", "Terms", "Security"},
	}

	// E-commerce
	cg.pools[TemplateEcommerce] = &ContentPool{
		Category: TemplateEcommerce,
		Taglines: []string{
			"Sell Everywhere",
			"Commerce Without Limits",
			"Your Store, Your Way",
			"Grow Your Business",
		},
		Headlines: []string{
			"The Complete Commerce Platform",
			"Sell More, Stress Less",
			"Build Your Online Empire",
			"Commerce Made Simple",
		},
		Descriptions: []string{
			"Everything you need to start, run, and grow your online business. From storefront to fulfillment, we've got you covered.",
			"Join millions of merchants who trust our platform to power their success.",
			"Beautiful stores, powerful tools, unlimited potential.",
		},
		Services: []string{
			"Online Storefront", "Payment Processing", "Inventory Management",
			"Shipping & Fulfillment", "Marketing Tools", "Analytics Dashboard",
			"Multi-channel Selling", "Customer Management",
		},
		Features: []Feature{
			{Icon: "🛒", Title: "Beautiful Stores", Description: "Stunning themes, no coding required"},
			{Icon: "💰", Title: "Accept Payments", Description: "100+ payment methods"},
			{Icon: "📦", Title: "Easy Shipping", Description: "Integrated fulfillment"},
			{Icon: "📈", Title: "Grow Sales", Description: "Built-in marketing tools"},
			{Icon: "🌐", Title: "Sell Anywhere", Description: "Web, mobile, social, marketplaces"},
		},
		Stats: []Stat{
			{Value: "$100B+", Label: "GMV Processed"},
			{Value: "2M+", Label: "Merchants"},
			{Value: "175+", Label: "Countries"},
			{Value: "24/7", Label: "Support"},
		},
		Testimonials: []Testimonial{
			{Quote: "Grew from $0 to $1M in our first year.", Author: "Maria Santos", Role: "Founder", Company: "Fashion Brand", Avatar: "MS"},
			{Quote: "The easiest platform to manage our global sales.", Author: "Tom Wilson", Role: "CEO", Company: "DTC Brand", Avatar: "TW"},
		},
		NavItems:    []string{"Features", "Pricing", "Examples", "Resources", "Login"},
		CTAText:     []string{"Start Free Trial", "Get Started", "Try Free", "Start Selling"},
		FooterLinks: []string{"Privacy", "Terms", "Help Center", "API"},
	}

	// Agency
	cg.pools[TemplateAgency] = &ContentPool{
		Category: TemplateAgency,
		Taglines: []string{
			"Create. Inspire. Deliver.",
			"Ideas That Move",
			"Bold Creative Solutions",
			"Design That Performs",
		},
		Headlines: []string{
			"Creative Solutions That Drive Results",
			"Where Strategy Meets Creativity",
			"Brands That Stand Out",
			"Design-Led Digital Experiences",
		},
		Descriptions: []string{
			"We're a full-service creative agency helping brands tell their stories and connect with audiences in meaningful ways.",
			"From strategy to execution, we craft experiences that inspire action and drive measurable results.",
			"Let's create something extraordinary together.",
		},
		Services: []string{
			"Brand Strategy", "Visual Identity", "Digital Design",
			"Content Creation", "Social Media", "Video Production",
			"Web Development", "Campaign Management",
		},
		Features: []Feature{
			{Icon: "🎨", Title: "Creative Excellence", Description: "Award-winning design team"},
			{Icon: "📱", Title: "Digital First", Description: "Modern, responsive experiences"},
			{Icon: "📊", Title: "Data-Driven", Description: "Strategy backed by insights"},
			{Icon: "🚀", Title: "Fast Delivery", Description: "Agile process, quick turnaround"},
			{Icon: "🤝", Title: "Partnership", Description: "We're an extension of your team"},
		},
		Stats: []Stat{
			{Value: "200+", Label: "Brands Served"},
			{Value: "50+", Label: "Awards Won"},
			{Value: "15+", Label: "Years Experience"},
			{Value: "98%", Label: "Client Retention"},
		},
		Testimonials: []Testimonial{
			{Quote: "They transformed our brand completely. Incredible work.", Author: "Rachel Green", Role: "CMO", Company: "Consumer Brand", Avatar: "RG"},
			{Quote: "Creative partners who truly understand business.", Author: "Mark Johnson", Role: "VP Marketing", Company: "Tech Company", Avatar: "MJ"},
		},
		NavItems:    []string{"Work", "Services", "About", "Insights", "Contact"},
		CTAText:     []string{"Start a Project", "Let's Talk", "Get in Touch", "Work With Us"},
		FooterLinks: []string{"Privacy", "Terms", "Careers", "Press"},
	}

	// Consulting
	cg.pools[TemplateConsulting] = &ContentPool{
		Category: TemplateConsulting,
		Taglines: []string{
			"Insight. Strategy. Results.",
			"Expertise That Delivers",
			"Your Strategic Partner",
			"Excellence in Advisory",
		},
		Headlines: []string{
			"Strategic Advisory for Complex Challenges",
			"Expertise That Drives Transformation",
			"Trusted Advisors to Industry Leaders",
			"Solving Tomorrow's Problems Today",
		},
		Descriptions: []string{
			"We partner with executives and boards to solve their most complex strategic and operational challenges.",
			"Our team of experts brings deep industry knowledge and proven methodologies to every engagement.",
			"From strategy to implementation, we deliver measurable impact.",
		},
		Services: []string{
			"Strategy Consulting", "Operations Excellence", "M&A Advisory",
			"Digital Strategy", "Organizational Design", "Performance Improvement",
			"Due Diligence", "Transformation Programs",
		},
		Features: []Feature{
			{Icon: "🎯", Title: "Strategic Focus", Description: "C-suite advisory expertise"},
			{Icon: "📈", Title: "Measurable Impact", Description: "Results you can quantify"},
			{Icon: "🌍", Title: "Global Reach", Description: "Expertise across markets"},
			{Icon: "🔍", Title: "Deep Analysis", Description: "Data-driven recommendations"},
			{Icon: "⚡", Title: "Rapid Execution", Description: "From insight to action"},
		},
		Stats: []Stat{
			{Value: "1000+", Label: "Engagements"},
			{Value: "Fortune 500", Label: "Clients"},
			{Value: "30+", Label: "Industries"},
			{Value: "95%", Label: "Repeat Clients"},
		},
		Testimonials: []Testimonial{
			{Quote: "Delivered insights that shaped our 5-year strategy.", Author: "Robert Chen", Role: "CEO", Company: "Global Corporation", Avatar: "RC"},
			{Quote: "The most impactful consulting engagement we've had.", Author: "Amanda Foster", Role: "Board Member", Company: "Public Company", Avatar: "AF"},
		},
		NavItems:    []string{"Expertise", "Industries", "Insights", "Careers", "Contact"},
		CTAText:     []string{"Contact Us", "Schedule Consultation", "Learn More", "Get in Touch"},
		FooterLinks: []string{"Privacy", "Terms", "Careers", "Alumni"},
	}

	// Education
	cg.pools[TemplateEducation] = &ContentPool{
		Category: TemplateEducation,
		Taglines: []string{
			"Learn. Grow. Succeed.",
			"Education for Everyone",
			"Knowledge Without Limits",
			"Your Learning Journey",
		},
		Headlines: []string{
			"Transform Your Future Through Learning",
			"Education That Works for You",
			"Unlock Your Potential",
			"Learn from the Best, Anywhere",
		},
		Descriptions: []string{
			"Access world-class education from anywhere. Our platform connects learners with expert instructors and cutting-edge content.",
			"Whether you're starting your career or advancing it, we have the courses and tools you need to succeed.",
			"Join millions of learners achieving their goals every day.",
		},
		Services: []string{
			"Online Courses", "Professional Certificates", "Degree Programs",
			"Corporate Training", "Skill Assessments", "Learning Paths",
			"Live Sessions", "Mentorship",
		},
		Features: []Feature{
			{Icon: "📚", Title: "Expert Content", Description: "Courses from industry leaders"},
			{Icon: "🎓", Title: "Recognized Credentials", Description: "Certificates that matter"},
			{Icon: "📱", Title: "Learn Anywhere", Description: "Mobile-first experience"},
			{Icon: "👥", Title: "Community", Description: "Connect with fellow learners"},
			{Icon: "📊", Title: "Track Progress", Description: "Personalized learning analytics"},
		},
		Stats: []Stat{
			{Value: "50M+", Label: "Learners"},
			{Value: "10K+", Label: "Courses"},
			{Value: "500+", Label: "Partners"},
			{Value: "4.8★", Label: "Average Rating"},
		},
		Testimonials: []Testimonial{
			{Quote: "Changed my career completely. Best investment I made.", Author: "Jennifer Liu", Role: "Software Engineer", Company: "Tech Giant", Avatar: "JL"},
			{Quote: "The flexibility to learn on my schedule was game-changing.", Author: "Carlos Martinez", Role: "Product Manager", Company: "Startup", Avatar: "CM"},
		},
		NavItems:    []string{"Courses", "Programs", "For Business", "Resources", "Login"},
		CTAText:     []string{"Start Learning", "Explore Courses", "Get Started", "Join Free"},
		FooterLinks: []string{"Privacy", "Terms", "Help", "Accessibility"},
	}

	// Security
	cg.pools[TemplateSecurity] = &ContentPool{
		Category: TemplateSecurity,
		Taglines: []string{
			"Defend. Detect. Respond.",
			"Security Without Compromise",
			"Trust Through Protection",
			"Cyber Resilience",
		},
		Headlines: []string{
			"Enterprise Security for the Modern Threat Landscape",
			"Protect What Matters Most",
			"Zero Trust Security Platform",
			"Stay Ahead of Threats",
		},
		Descriptions: []string{
			"Comprehensive cybersecurity solutions that protect your organization from evolving threats while enabling business growth.",
			"Our platform combines AI-powered detection, automated response, and expert services to keep you secure.",
			"Trusted by security teams at the world's most demanding organizations.",
		},
		Services: []string{
			"Threat Detection", "Incident Response", "Vulnerability Management",
			"Identity Security", "Cloud Security", "Endpoint Protection",
			"Security Operations", "Compliance Automation",
		},
		Features: []Feature{
			{Icon: "🛡️", Title: "AI-Powered Detection", Description: "Catch threats others miss"},
			{Icon: "⚡", Title: "Automated Response", Description: "Contain threats in seconds"},
			{Icon: "🔍", Title: "Full Visibility", Description: "See everything, everywhere"},
			{Icon: "🤖", Title: "24/7 SOC", Description: "Expert analysts always on"},
			{Icon: "📋", Title: "Compliance Ready", Description: "Meet any regulatory requirement"},
		},
		Stats: []Stat{
			{Value: "1B+", Label: "Events Analyzed Daily"},
			{Value: "<1min", Label: "Mean Time to Detect"},
			{Value: "99.9%", Label: "Threat Accuracy"},
			{Value: "0", Label: "Breaches"},
		},
		Testimonials: []Testimonial{
			{Quote: "Reduced our security incidents by 90% in the first year.", Author: "Chris Anderson", Role: "CISO", Company: "Enterprise Corp", Avatar: "CA"},
			{Quote: "The only security platform our team actually trusts.", Author: "Sarah Kim", Role: "Security Director", Company: "Financial Services", Avatar: "SK"},
		},
		NavItems:    []string{"Platform", "Solutions", "Resources", "Company", "Contact"},
		CTAText:     []string{"Request Demo", "Get Assessment", "Contact Us", "Start Trial"},
		FooterLinks: []string{"Privacy", "Security", "Compliance", "Trust Center"},
	}

	// Classic
	cg.pools[TemplateClassic] = &ContentPool{
		Category: TemplateClassic,
		Taglines: []string{
			"Excellence in Every Detail",
			"Trusted Since Day One",
			"Quality You Can Count On",
			"Building Lasting Relationships",
		},
		Headlines: []string{
			"Professional Solutions for Your Business",
			"Experience the Difference",
			"Your Success is Our Mission",
			"Dedicated to Excellence",
		},
		Descriptions: []string{
			"We provide professional services and solutions designed to help your business thrive in today's competitive landscape.",
			"With years of experience and a commitment to quality, we deliver results that exceed expectations.",
			"Partner with us and experience the difference that dedication and expertise can make.",
		},
		Services: []string{
			"Professional Services", "Business Solutions", "Technical Support",
			"Consulting", "Implementation", "Training",
			"Managed Services", "Custom Development",
		},
		Features: []Feature{
			{Icon: "✓", Title: "Proven Track Record", Description: "Years of successful delivery"},
			{Icon: "🤝", Title: "Client Focus", Description: "Your success is our priority"},
			{Icon: "⭐", Title: "Quality Assured", Description: "Excellence in every project"},
			{Icon: "📞", Title: "Responsive Support", Description: "Always here when you need us"},
			{Icon: "🔄", Title: "Continuous Improvement", Description: "Always getting better"},
		},
		Stats: []Stat{
			{Value: "1000+", Label: "Clients Served"},
			{Value: "15+", Label: "Years Experience"},
			{Value: "98%", Label: "Satisfaction Rate"},
			{Value: "24/7", Label: "Support"},
		},
		Testimonials: []Testimonial{
			{Quote: "A reliable partner we've trusted for years.", Author: "John Smith", Role: "Director", Company: "Business Inc", Avatar: "JS"},
			{Quote: "Professional, responsive, and always delivers.", Author: "Mary Johnson", Role: "Manager", Company: "Corp Ltd", Avatar: "MJ"},
		},
		NavItems:    []string{"Services", "About", "Resources", "Contact"},
		CTAText:     []string{"Contact Us", "Learn More", "Get Started", "Request Info"},
		FooterLinks: []string{"Privacy Policy", "Terms of Service", "Contact"},
	}
}
