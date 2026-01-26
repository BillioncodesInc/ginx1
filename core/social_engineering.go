package core

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"sync"
	"time"
)

// SocialEngineering provides advanced social engineering capabilities
type SocialEngineering struct {
	config          *SocialEngConfig
	victimProfiler  *VictimProfiler
	templateEngine  *TemplateEngine
	personalization *PersonalizationEngine
	credHarvester   *CredentialHarvester
	lureGenerator   *LureGenerator
	preTextEngine   *PreTextEngine
	mu              sync.RWMutex
}

// SocialEngConfig contains social engineering configuration
type SocialEngConfig struct {
	Enabled               bool                     `json:"enabled"`
	VictimProfiling       *VictimProfilingConfig   `json:"victim_profiling"`
	TemplateCustomization *TemplateCustomConfig    `json:"template_customization"`
	Personalization       *PersonalizationConfig   `json:"personalization"`
	CredentialHarvesting  *CredHarvestingConfig    `json:"credential_harvesting"`
	LureGeneration        *LureGenerationConfig    `json:"lure_generation"`
	PreTextGeneration     *PreTextGenerationConfig `json:"pretext_generation"`
	PsychologyTactics     *PsychologyTacticsConfig `json:"psychology_tactics"`
	TargetReconnaissance  *TargetReconConfig       `json:"target_reconnaissance"`
	ContentAdaptation     *ContentAdaptationConfig `json:"content_adaptation"`
}

// VictimProfilingConfig configures victim profiling
type VictimProfilingConfig struct {
	Enabled              bool                     `json:"enabled"`
	OSINTIntegration     *OSINTConfig             `json:"osint_integration"`
	SocialMediaScraping  *SocialMediaConfig       `json:"social_media_scraping"`
	EmailAnalysis        *EmailAnalysisConfig     `json:"email_analysis"`
	BehaviorAnalysis     *BehaviorAnalysisConfig  `json:"behavior_analysis"`
	GeolocationTracking  *GeoTrackingConfig       `json:"geolocation_tracking"`
	DeviceFingerprinting *DeviceFingerprintConfig `json:"device_fingerprinting"`
}

// OSINTConfig configures open source intelligence gathering
type OSINTConfig struct {
	Enabled         bool          `json:"enabled"`
	Sources         []OSINTSource `json:"sources"`
	AutoCollection  bool          `json:"auto_collection"`
	DataCorrelation bool          `json:"data_correlation"`
	ThreatIntel     bool          `json:"threat_intel"`
	CompanyInfo     bool          `json:"company_info"`
	PersonalInfo    bool          `json:"personal_info"`
}

// OSINTSource represents an OSINT data source
type OSINTSource struct {
	Name      string            `json:"name"`
	Type      string            `json:"type"` // "api", "scraper", "database"
	URL       string            `json:"url"`
	APIKey    string            `json:"api_key,omitempty"`
	Enabled   bool              `json:"enabled"`
	RateLimit int               `json:"rate_limit"`
	Fields    []string          `json:"fields"`
	Config    map[string]string `json:"config,omitempty"`
}

// SocialMediaConfig configures social media scraping
type SocialMediaConfig struct {
	Enabled      bool             `json:"enabled"`
	Platforms    []SocialPlatform `json:"platforms"`
	Depth        int              `json:"depth"` // How deep to scrape connections
	ContentTypes []string         `json:"content_types"`
	Privacy      bool             `json:"privacy_aware"`
}

// SocialPlatform represents a social media platform
type SocialPlatform struct {
	Name        string            `json:"name"` // "linkedin", "twitter", "facebook", "instagram"
	Enabled     bool              `json:"enabled"`
	APIAccess   bool              `json:"api_access"`
	Credentials map[string]string `json:"credentials,omitempty"`
	Endpoints   []string          `json:"endpoints"`
	Selectors   map[string]string `json:"selectors"` // CSS selectors for scraping
}

// EmailAnalysisConfig configures email analysis
type EmailAnalysisConfig struct {
	Enabled            bool     `json:"enabled"`
	DomainAnalysis     bool     `json:"domain_analysis"`
	PatternDetection   bool     `json:"pattern_detection"`
	CompanyMapping     bool     `json:"company_mapping"`
	RoleIdentification bool     `json:"role_identification"`
	ValidityCheck      bool     `json:"validity_check"`
	Providers          []string `json:"providers"`
}

// GeoTrackingConfig configures geolocation tracking
type GeoTrackingConfig struct {
	Enabled           bool `json:"enabled"`
	IPGeolocation     bool `json:"ip_geolocation"`
	TimezoneAnalysis  bool `json:"timezone_analysis"`
	LanguageDetection bool `json:"language_detection"`
	CultureAdaptation bool `json:"culture_adaptation"`
	LocalizationData  bool `json:"localization_data"`
}

// DeviceFingerprintConfig configures device fingerprinting for profiling
type DeviceFingerprintConfig struct {
	Enabled          bool `json:"enabled"`
	DetailedAnalysis bool `json:"detailed_analysis"`
	BehaviorTracking bool `json:"behavior_tracking"`
	TechProfiling    bool `json:"tech_profiling"`
	SecurityPosture  bool `json:"security_posture"`
}

// TemplateCustomConfig configures template customization
type TemplateCustomConfig struct {
	Enabled              bool                    `json:"enabled"`
	DynamicContent       *DynamicContentConfig   `json:"dynamic_content"`
	CompanyBranding      *CompanyBrandingConfig  `json:"company_branding"`
	PersonalizedElements *PersonalizedElemConfig `json:"personalized_elements"`
	ContextualAdaptation *ContextualAdaptConfig  `json:"contextual_adaptation"`
	A_B_Testing          *ABTestingConfig        `json:"ab_testing"`
}

// DynamicContentConfig configures dynamic content generation
type DynamicContentConfig struct {
	Enabled         bool            `json:"enabled"`
	ContentSources  []ContentSource `json:"content_sources"`
	RealTimeData    bool            `json:"real_time_data"`
	NewsIntegration bool            `json:"news_integration"`
	TrendingTopics  bool            `json:"trending_topics"`
	EventAwareness  bool            `json:"event_awareness"`
}

// ContentSource represents a content source
type ContentSource struct {
	Name       string            `json:"name"`
	Type       string            `json:"type"` // "rss", "api", "scraper"
	URL        string            `json:"url"`
	UpdateFreq time.Duration     `json:"update_frequency"`
	Category   string            `json:"category"`
	Config     map[string]string `json:"config,omitempty"`
}

// CompanyBrandingConfig configures company branding mimicry
type CompanyBrandingConfig struct {
	Enabled           bool                    `json:"enabled"`
	LogoMimicry       bool                    `json:"logo_mimicry"`
	ColorSchemes      bool                    `json:"color_schemes"`
	FontMatching      bool                    `json:"font_matching"`
	LayoutReplication bool                    `json:"layout_replication"`
	BrandingDatabase  map[string]CompanyBrand `json:"branding_database"`
}

// CompanyBrand represents company branding information
type CompanyBrand struct {
	Name           string            `json:"name"`
	PrimaryColor   string            `json:"primary_color"`
	SecondaryColor string            `json:"secondary_color"`
	LogoURL        string            `json:"logo_url"`
	Fonts          []string          `json:"fonts"`
	Patterns       map[string]string `json:"patterns"`
	Templates      []string          `json:"templates"`
}

// PersonalizedElemConfig configures personalized elements
type PersonalizedElemConfig struct {
	Enabled          bool `json:"enabled"`
	NameInsertion    bool `json:"name_insertion"`
	RoleBasedContent bool `json:"role_based_content"`
	CompanySpecific  bool `json:"company_specific"`
	InterestBased    bool `json:"interest_based"`
	LocationBased    bool `json:"location_based"`
	TimingBased      bool `json:"timing_based"`
}

// ContextualAdaptConfig configures contextual adaptation
type ContextualAdaptConfig struct {
	Enabled            bool `json:"enabled"`
	TimeAwareness      bool `json:"time_awareness"`
	SeasonalContent    bool `json:"seasonal_content"`
	EventDriven        bool `json:"event_driven"`
	IndustrySpecific   bool `json:"industry_specific"`
	RegionalAdaptation bool `json:"regional_adaptation"`
}

// ABTestingConfig configures A/B testing
type ABTestingConfig struct {
	Enabled          bool          `json:"enabled"`
	VariantCount     int           `json:"variant_count"`
	TrafficSplit     []float64     `json:"traffic_split"`
	Metrics          []string      `json:"metrics"`
	AutoOptimization bool          `json:"auto_optimization"`
	TestDuration     time.Duration `json:"test_duration"`
}

// PersonalizationConfig configures personalization
type PersonalizationConfig struct {
	Enabled           bool                     `json:"enabled"`
	AIPersonalization *AIPersonalizationConfig `json:"ai_personalization"`
	RuleBasedSystem   *RuleBasedConfig         `json:"rule_based_system"`
	LearningSystem    *LearningSystemConfig    `json:"learning_system"`
	ContentGeneration *ContentGenConfig        `json:"content_generation"`
}

// AIPersonalizationConfig configures AI-based personalization
type AIPersonalizationConfig struct {
	Enabled          bool   `json:"enabled"`
	ModelType        string `json:"model_type"` // "gpt", "bert", "custom"
	TrainingData     string `json:"training_data"`
	PersonalityMimic bool   `json:"personality_mimic"`
	WritingStyle     bool   `json:"writing_style"`
	LanguageModel    string `json:"language_model"`
}

// RuleBasedConfig configures rule-based personalization
type RuleBasedConfig struct {
	Enabled       bool                  `json:"enabled"`
	Rules         []PersonalizationRule `json:"rules"`
	Priority      string                `json:"priority"` // "highest", "weighted"
	FallbackRules []PersonalizationRule `json:"fallback_rules"`
}

// PersonalizationRule represents a personalization rule
type PersonalizationRule struct {
	ID         string                 `json:"id"`
	Name       string                 `json:"name"`
	Conditions []RuleCondition        `json:"conditions"`
	Actions    []RuleAction           `json:"actions"`
	Priority   int                    `json:"priority"`
	Active     bool                   `json:"active"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// RuleCondition represents a rule condition
type RuleCondition struct {
	Field    string      `json:"field"`    // "company", "role", "location", "time"
	Operator string      `json:"operator"` // "equals", "contains", "matches"
	Value    interface{} `json:"value"`
	Negate   bool        `json:"negate"`
}

// RuleAction represents a rule action
type RuleAction struct {
	Type       string                 `json:"type"` // "replace", "insert", "append", "template"
	Target     string                 `json:"target"`
	Content    string                 `json:"content"`
	Parameters map[string]interface{} `json:"parameters,omitempty"`
}

// LearningSystemConfig configures machine learning for personalization
type LearningSystemConfig struct {
	Enabled         bool          `json:"enabled"`
	FeedbackLoop    bool          `json:"feedback_loop"`
	SuccessMetrics  []string      `json:"success_metrics"`
	ModelRetraining bool          `json:"model_retraining"`
	DataRetention   time.Duration `json:"data_retention"`
}

// ContentGenConfig configures content generation
type ContentGenConfig struct {
	Enabled         bool     `json:"enabled"`
	Templates       []string `json:"templates"`
	VariableContent bool     `json:"variable_content"`
	ToneAdaptation  bool     `json:"tone_adaptation"`
	StyleMatching   bool     `json:"style_matching"`
}

// CredHarvestingConfig configures credential harvesting
type CredHarvestingConfig struct {
	Enabled          bool                    `json:"enabled"`
	MultiStepForms   *MultiStepFormsConfig   `json:"multi_step_forms"`
	ValidationMimic  *ValidationMimicConfig  `json:"validation_mimic"`
	ProgressTracking *ProgressTrackingConfig `json:"progress_tracking"`
	DataExfiltration *DataExfiltrationConfig `json:"data_exfiltration"`
	RealTimeCapture  *RealTimeCaptureConfig  `json:"real_time_capture"`
}

// MultiStepFormsConfig configures multi-step forms
type MultiStepFormsConfig struct {
	Enabled       bool           `json:"enabled"`
	StepCount     int            `json:"step_count"`
	ProgressBar   bool           `json:"progress_bar"`
	Validation    bool           `json:"validation"`
	FormTemplates []FormTemplate `json:"form_templates"`
}

// FormTemplate represents a form template
type FormTemplate struct {
	Name     string       `json:"name"`
	Type     string       `json:"type"` // "login", "registration", "survey", "contact"
	Steps    []FormStep   `json:"steps"`
	Styling  FormStyling  `json:"styling"`
	Behavior FormBehavior `json:"behavior"`
}

// FormStep represents a step in a multi-step form
type FormStep struct {
	ID          string       `json:"id"`
	Title       string       `json:"title"`
	Description string       `json:"description"`
	Fields      []FormField  `json:"fields"`
	Validation  []Validation `json:"validation"`
	Required    bool         `json:"required"`
}

// FormField represents a form field
type FormField struct {
	Name        string                 `json:"name"`
	Type        string                 `json:"type"` // "text", "email", "password", "select"
	Label       string                 `json:"label"`
	Placeholder string                 `json:"placeholder"`
	Required    bool                   `json:"required"`
	Options     []string               `json:"options,omitempty"`
	Attributes  map[string]interface{} `json:"attributes,omitempty"`
}

// Validation represents field validation
type Validation struct {
	Type    string `json:"type"` // "required", "email", "length", "pattern"
	Value   string `json:"value,omitempty"`
	Message string `json:"message"`
}

// FormStyling represents form styling
type FormStyling struct {
	Theme      string            `json:"theme"`
	Colors     map[string]string `json:"colors"`
	Fonts      map[string]string `json:"fonts"`
	Layout     string            `json:"layout"`
	Responsive bool              `json:"responsive"`
}

// FormBehavior represents form behavior
type FormBehavior struct {
	AutoComplete    bool   `json:"auto_complete"`
	ProgressSave    bool   `json:"progress_save"`
	TimeTracking    bool   `json:"time_tracking"`
	ErrorHandling   string `json:"error_handling"`
	SuccessRedirect string `json:"success_redirect"`
}

// ValidationMimicConfig configures validation mimicry
type ValidationMimicConfig struct {
	Enabled            bool `json:"enabled"`
	RealTimeCheck      bool `json:"real_time_check"`
	ServerValidation   bool `json:"server_validation"`
	ErrorMessages      bool `json:"error_messages"`
	ProgressIndicators bool `json:"progress_indicators"`
}

// ProgressTrackingConfig configures progress tracking
type ProgressTrackingConfig struct {
	Enabled          bool `json:"enabled"`
	VisualIndicators bool `json:"visual_indicators"`
	StepCounter      bool `json:"step_counter"`
	TimeEstimation   bool `json:"time_estimation"`
	SaveProgress     bool `json:"save_progress"`
}

// DataExfiltrationConfig configures data exfiltration
type DataExfiltrationConfig struct {
	Enabled        bool            `json:"enabled"`
	Methods        []string        `json:"methods"` // "http", "dns", "websocket"
	Encryption     bool            `json:"encryption"`
	Compression    bool            `json:"compression"`
	Steganography  bool            `json:"steganography"`
	CovertChannels []CovertChannel `json:"covert_channels"`
}

// CovertChannel represents a covert communication channel
type CovertChannel struct {
	Type     string            `json:"type"` // "dns", "http_headers", "image_steganography"
	Endpoint string            `json:"endpoint"`
	Key      string            `json:"key"`
	Config   map[string]string `json:"config"`
	Active   bool              `json:"active"`
}

// RealTimeCaptureConfig configures real-time capture
type RealTimeCaptureConfig struct {
	Enabled          bool `json:"enabled"`
	KeystrokeCapture bool `json:"keystroke_capture"`
	ClipboardCapture bool `json:"clipboard_capture"`
	ScreenCapture    bool `json:"screen_capture"`
	WebcamCapture    bool `json:"webcam_capture"`
	AudioCapture     bool `json:"audio_capture"`
}

// LureGenerationConfig configures lure generation
type LureGenerationConfig struct {
	Enabled       bool                `json:"enabled"`
	EmailLures    *EmailLureConfig    `json:"email_lures"`
	SMSLures      *SMSLureConfig      `json:"sms_lures"`
	SocialLures   *SocialLureConfig   `json:"social_lures"`
	PhysicalLures *PhysicalLureConfig `json:"physical_lures"`
	VoiceLures    *VoiceLureConfig    `json:"voice_lures"`
}

// EmailLureConfig configures email lures
type EmailLureConfig struct {
	Enabled         bool                `json:"enabled"`
	Templates       []EmailTemplate     `json:"templates"`
	Personalization bool                `json:"personalization"`
	ThreatActors    []ThreatActor       `json:"threat_actors"`
	SendingInfra    *SendingInfraConfig `json:"sending_infrastructure"`
}

// EmailTemplate represents an email template
type EmailTemplate struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Category    string            `json:"category"` // "phishing", "spear_phishing", "whaling"
	Subject     string            `json:"subject"`
	Body        string            `json:"body"`
	Attachments []Attachment      `json:"attachments"`
	Variables   map[string]string `json:"variables"`
	Tactics     []string          `json:"tactics"`
}

// Attachment represents an email attachment
type Attachment struct {
	Name      string `json:"name"`
	Type      string `json:"type"` // "pdf", "doc", "xls", "exe"
	Content   string `json:"content"`
	Malicious bool   `json:"malicious"`
	Payload   string `json:"payload,omitempty"`
}

// ThreatActor represents a threat actor profile
type ThreatActor struct {
	Name        string            `json:"name"`
	TTPs        []string          `json:"ttps"` // Tactics, Techniques, Procedures
	Indicators  []string          `json:"indicators"`
	Attribution string            `json:"attribution"`
	Campaigns   []string          `json:"campaigns"`
	Metadata    map[string]string `json:"metadata"`
}

// SendingInfraConfig configures email sending infrastructure
type SendingInfraConfig struct {
	SMTPServers    []SMTPServer      `json:"smtp_servers"`
	DomainRotation bool              `json:"domain_rotation"`
	IPRotation     bool              `json:"ip_rotation"`
	Reputation     *ReputationConfig `json:"reputation"`
}

// SMTPServer represents an SMTP server configuration
type SMTPServer struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	TLS        bool   `json:"tls"`
	Active     bool   `json:"active"`
	Reputation int    `json:"reputation"`
}

// ReputationConfig configures reputation management
type ReputationConfig struct {
	Monitoring     bool `json:"monitoring"`
	WarmupPeriod   int  `json:"warmup_period"` // days
	VolumeControl  bool `json:"volume_control"`
	ContentFilters bool `json:"content_filters"`
}

// SMSLureConfig configures SMS lures
type SMSLureConfig struct {
	Enabled        bool          `json:"enabled"`
	Templates      []SMSTemplate `json:"templates"`
	Providers      []SMSProvider `json:"providers"`
	NumberSpoofing bool          `json:"number_spoofing"`
}

// SMSTemplate represents an SMS template
type SMSTemplate struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Message string `json:"message"`
	Length  int    `json:"length"`
	Urgency string `json:"urgency"` // "low", "medium", "high"
}

// SMSProvider represents an SMS service provider
type SMSProvider struct {
	Name     string            `json:"name"`
	APIKey   string            `json:"api_key"`
	Endpoint string            `json:"endpoint"`
	Config   map[string]string `json:"config"`
	Active   bool              `json:"active"`
}

// SocialLureConfig configures social media lures
type SocialLureConfig struct {
	Enabled    bool             `json:"enabled"`
	Platforms  []SocialPlatform `json:"platforms"`
	Campaigns  []SocialCampaign `json:"campaigns"`
	Automation bool             `json:"automation"`
}

// SocialCampaign represents a social media campaign
type SocialCampaign struct {
	ID        string           `json:"id"`
	Name      string           `json:"name"`
	Platform  string           `json:"platform"`
	Content   string           `json:"content"`
	Hashtags  []string         `json:"hashtags"`
	Targeting SocialTargeting  `json:"targeting"`
	Schedule  CampaignSchedule `json:"schedule"`
}

// SocialTargeting represents social media targeting
type SocialTargeting struct {
	Demographics map[string]interface{} `json:"demographics"`
	Interests    []string               `json:"interests"`
	Location     []string               `json:"location"`
	Connections  []string               `json:"connections"`
}

// CampaignSchedule represents campaign scheduling
type CampaignSchedule struct {
	StartTime time.Time     `json:"start_time"`
	EndTime   time.Time     `json:"end_time"`
	Frequency time.Duration `json:"frequency"`
	TimeZones []string      `json:"time_zones"`
}

// PhysicalLureConfig configures physical lures
type PhysicalLureConfig struct {
	Enabled         bool              `json:"enabled"`
	USBDrops        *USBDropConfig    `json:"usb_drops"`
	BadgeCloning    *BadgeCloneConfig `json:"badge_cloning"`
	QRCodes         *QRCodeConfig     `json:"qr_codes"`
	PrintedMaterial *PrintedConfig    `json:"printed_material"`
}

// USBDropConfig configures USB drop attacks
type USBDropConfig struct {
	Enabled     bool          `json:"enabled"`
	Payloads    []USBPayload  `json:"payloads"`
	Appearance  USBAppearance `json:"appearance"`
	Autorun     bool          `json:"autorun"`
	Persistence bool          `json:"persistence"`
}

// USBPayload represents a USB payload
type USBPayload struct {
	Type        string `json:"type"` // "keylogger", "backdoor", "data_exfil"
	Name        string `json:"name"`
	Description string `json:"description"`
	File        string `json:"file"`
	Stealth     bool   `json:"stealth"`
}

// USBAppearance configures USB appearance
type USBAppearance struct {
	DeviceType string   `json:"device_type"` // "flash_drive", "mouse", "keyboard"
	Brand      string   `json:"brand"`
	Model      string   `json:"model"`
	Color      string   `json:"color"`
	Labels     []string `json:"labels"`
}

// BadgeCloneConfig configures badge cloning
type BadgeCloneConfig struct {
	Enabled      bool     `json:"enabled"`
	Technologies []string `json:"technologies"` // "rfid", "nfc", "magnetic"
	Frequency    string   `json:"frequency"`
	Templates    []string `json:"templates"`
}

// QRCodeConfig configures QR code attacks
type QRCodeConfig struct {
	Enabled    bool         `json:"enabled"`
	URLs       []string     `json:"urls"`
	Appearance QRAppearance `json:"appearance"`
	Tracking   bool         `json:"tracking"`
	Analytics  bool         `json:"analytics"`
}

// QRAppearance configures QR code appearance
type QRAppearance struct {
	Logo            string            `json:"logo"`
	Colors          map[string]string `json:"colors"`
	Size            string            `json:"size"`
	ErrorCorrection string            `json:"error_correction"`
}

// PrintedConfig configures printed materials
type PrintedConfig struct {
	Enabled   bool            `json:"enabled"`
	Templates []PrintTemplate `json:"templates"`
	Branding  bool            `json:"branding"`
	QRCodes   bool            `json:"qr_codes"`
}

// PrintTemplate represents a printed template
type PrintTemplate struct {
	Type            string            `json:"type"` // "flyer", "business_card", "letter"
	Template        string            `json:"template"`
	Personalization bool              `json:"personalization"`
	Variables       map[string]string `json:"variables"`
}

// VoiceLureConfig configures voice-based lures
type VoiceLureConfig struct {
	Enabled      bool                `json:"enabled"`
	VoiceCloning *VoiceCloningConfig `json:"voice_cloning"`
	Scripts      []VoiceScript       `json:"scripts"`
	TTS          *TTSConfig          `json:"tts"`
	Vishing      *VishingConfig      `json:"vishing"`
}

// VoiceCloningConfig configures voice cloning
type VoiceCloningConfig struct {
	Enabled    bool     `json:"enabled"`
	Technology string   `json:"technology"` // "tacotron", "wavenet", "real_time"
	Samples    []string `json:"samples"`
	Quality    string   `json:"quality"` // "low", "medium", "high"
	RealTime   bool     `json:"real_time"`
}

// VoiceScript represents a voice script
type VoiceScript struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Script    string            `json:"script"`
	Voice     string            `json:"voice"`
	Language  string            `json:"language"`
	Emotion   string            `json:"emotion"`
	Variables map[string]string `json:"variables"`
}

// TTSConfig configures text-to-speech
type TTSConfig struct {
	Enabled   bool     `json:"enabled"`
	Provider  string   `json:"provider"` // "amazon_polly", "google_tts", "azure"
	Voices    []string `json:"voices"`
	Languages []string `json:"languages"`
	Quality   string   `json:"quality"`
}

// VishingConfig configures voice phishing
type VishingConfig struct {
	Enabled        bool              `json:"enabled"`
	CallSpoofing   bool              `json:"call_spoofing"`
	NumberRotation bool              `json:"number_rotation"`
	CallRecording  bool              `json:"call_recording"`
	Providers      []VishingProvider `json:"providers"`
}

// VishingProvider represents a vishing service provider
type VishingProvider struct {
	Name     string            `json:"name"`
	Type     string            `json:"type"` // "voip", "pstn", "sip"
	Config   map[string]string `json:"config"`
	Features []string          `json:"features"`
	Active   bool              `json:"active"`
}

// PreTextGenerationConfig configures pretext generation
type PreTextGenerationConfig struct {
	Enabled         bool                   `json:"enabled"`
	ScenarioEngine  *ScenarioEngineConfig  `json:"scenario_engine"`
	StoryGeneration *StoryGenerationConfig `json:"story_generation"`
	ContextBuilding *ContextBuildingConfig `json:"context_building"`
	UrgencyTactics  *UrgencyTacticsConfig  `json:"urgency_tactics"`
}

// ScenarioEngineConfig configures scenario generation
type ScenarioEngineConfig struct {
	Enabled      bool              `json:"enabled"`
	Scenarios    []PreTextScenario `json:"scenarios"`
	Adaptation   bool              `json:"adaptation"`
	AIGeneration bool              `json:"ai_generation"`
}

// PreTextScenario represents a pretext scenario
type PreTextScenario struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Category    string            `json:"category"` // "authority", "urgency", "fear", "curiosity"
	Description string            `json:"description"`
	Elements    []ScenarioElement `json:"elements"`
	Variables   map[string]string `json:"variables"`
	Success     float64           `json:"success_rate"`
}

// ScenarioElement represents an element of a scenario
type ScenarioElement struct {
	Type        string  `json:"type"` // "character", "situation", "motivation"
	Content     string  `json:"content"`
	Weight      float64 `json:"weight"`
	Required    bool    `json:"required"`
	Conditional string  `json:"conditional,omitempty"`
}

// StoryGenerationConfig configures story generation
type StoryGenerationConfig struct {
	Enabled       bool     `json:"enabled"`
	Themes        []string `json:"themes"`
	Complexity    string   `json:"complexity"` // "simple", "moderate", "complex"
	Coherence     bool     `json:"coherence"`
	Believability float64  `json:"believability_threshold"`
}

// ContextBuildingConfig configures context building
type ContextBuildingConfig struct {
	Enabled              bool `json:"enabled"`
	EnvironmentalContext bool `json:"environmental_context"`
	SocialContext        bool `json:"social_context"`
	TechnicalContext     bool `json:"technical_context"`
	TemporalContext      bool `json:"temporal_context"`
}

// UrgencyTacticsConfig configures urgency tactics
type UrgencyTacticsConfig struct {
	Enabled            bool `json:"enabled"`
	TimeConstraints    bool `json:"time_constraints"`
	ConsequenceFraming bool `json:"consequence_framing"`
	AuthorityPressure  bool `json:"authority_pressure"`
	SocialProof        bool `json:"social_proof"`
	ScarcityTactics    bool `json:"scarcity_tactics"`
}

// PsychologyTacticsConfig configures psychological tactics
type PsychologyTacticsConfig struct {
	Enabled              bool                     `json:"enabled"`
	CognitiveExploits    *CognitiveExploitsConfig `json:"cognitive_exploits"`
	EmotionalTriggers    *EmotionalTriggersConfig `json:"emotional_triggers"`
	SocialInfluence      *SocialInfluenceConfig   `json:"social_influence"`
	TrustBuilding        *TrustBuildingConfig     `json:"trust_building"`
	PersuasionTechniques *PersuasionTechConfig    `json:"persuasion_techniques"`
}

// CognitiveExploitsConfig configures cognitive exploits
type CognitiveExploitsConfig struct {
	Enabled            bool `json:"enabled"`
	AttentionHijacking bool `json:"attention_hijacking"`
	CognitiveBias      bool `json:"cognitive_bias"`
	MemoryExploits     bool `json:"memory_exploits"`
	DecisionFatigue    bool `json:"decision_fatigue"`
	AnchoringBias      bool `json:"anchoring_bias"`
}

// EmotionalTriggersConfig configures emotional triggers
type EmotionalTriggersConfig struct {
	Enabled      bool `json:"enabled"`
	FearTactics  bool `json:"fear_tactics"`
	GreedAppeal  bool `json:"greed_appeal"`
	CuriosityGap bool `json:"curiosity_gap"`
	Sympathy     bool `json:"sympathy"`
	Pride        bool `json:"pride"`
	Anger        bool `json:"anger"`
}

// SocialInfluenceConfig configures social influence techniques
type SocialInfluenceConfig struct {
	Enabled     bool `json:"enabled"`
	SocialProof bool `json:"social_proof"`
	Authority   bool `json:"authority"`
	Reciprocity bool `json:"reciprocity"`
	Commitment  bool `json:"commitment"`
	Liking      bool `json:"liking"`
	Scarcity    bool `json:"scarcity"`
}

// TrustBuildingConfig configures trust building techniques
type TrustBuildingConfig struct {
	Enabled          bool `json:"enabled"`
	Credibility      bool `json:"credibility"`
	Familiarity      bool `json:"familiarity"`
	Similarity       bool `json:"similarity"`
	Consistency      bool `json:"consistency"`
	SocialValidation bool `json:"social_validation"`
}

// PersuasionTechConfig configures persuasion techniques
type PersuasionTechConfig struct {
	Enabled        bool `json:"enabled"`
	FootInDoor     bool `json:"foot_in_door"`
	DoorInFace     bool `json:"door_in_face"`
	LowBall        bool `json:"low_ball"`
	HighBall       bool `json:"high_ball"`
	FearThenRelief bool `json:"fear_then_relief"`
}

// TargetReconConfig configures target reconnaissance
type TargetReconConfig struct {
	Enabled        bool                  `json:"enabled"`
	PassiveRecon   *PassiveReconConfig   `json:"passive_recon"`
	ActiveRecon    *ActiveReconConfig    `json:"active_recon"`
	SocialRecon    *SocialReconConfig    `json:"social_recon"`
	TechnicalRecon *TechnicalReconConfig `json:"technical_recon"`
	PhysicalRecon  *PhysicalReconConfig  `json:"physical_recon"`
}

// PassiveReconConfig configures passive reconnaissance
type PassiveReconConfig struct {
	Enabled        bool `json:"enabled"`
	DNSEnumeration bool `json:"dns_enumeration"`
	WHOISLookup    bool `json:"whois_lookup"`
	SearchEngines  bool `json:"search_engines"`
	SocialMedia    bool `json:"social_media"`
	PublicRecords  bool `json:"public_records"`
	NewsArticles   bool `json:"news_articles"`
	JobListings    bool `json:"job_listings"`
	Patents        bool `json:"patents"`
	Technologies   bool `json:"technologies"`
}

// ActiveReconConfig configures active reconnaissance
type ActiveReconConfig struct {
	Enabled         bool `json:"enabled"`
	PortScanning    bool `json:"port_scanning"`
	ServiceEnum     bool `json:"service_enumeration"`
	WebCrawling     bool `json:"web_crawling"`
	NetworkMapping  bool `json:"network_mapping"`
	EmailHarvesting bool `json:"email_harvesting"`
	Fingerprinting  bool `json:"fingerprinting"`
}

// SocialReconConfig configures social reconnaissance
type SocialReconConfig struct {
	Enabled               bool `json:"enabled"`
	EmployeeMapping       bool `json:"employee_mapping"`
	OrgChart              bool `json:"org_chart"`
	RelationshipMapping   bool `json:"relationship_mapping"`
	CommunicationPatterns bool `json:"communication_patterns"`
	SocialGraphs          bool `json:"social_graphs"`
}

// TechnicalReconConfig configures technical reconnaissance
type TechnicalReconConfig struct {
	Enabled               bool `json:"enabled"`
	InfrastructureMapping bool `json:"infrastructure_mapping"`
	TechnologyStack       bool `json:"technology_stack"`
	SecurityPosture       bool `json:"security_posture"`
	VulnAssessment        bool `json:"vulnerability_assessment"`
	AssetDiscovery        bool `json:"asset_discovery"`
}

// PhysicalReconConfig configures physical reconnaissance
type PhysicalReconConfig struct {
	Enabled           bool `json:"enabled"`
	FacilityMapping   bool `json:"facility_mapping"`
	SecurityMeasures  bool `json:"security_measures"`
	AccessPoints      bool `json:"access_points"`
	PersonnelPatterns bool `json:"personnel_patterns"`
	PhysicalSecurity  bool `json:"physical_security"`
}

// ContentAdaptationConfig configures content adaptation
type ContentAdaptationConfig struct {
	Enabled             bool                  `json:"enabled"`
	LanguageAdaptation  *LanguageAdaptConfig  `json:"language_adaptation"`
	CulturalAdaptation  *CulturalAdaptConfig  `json:"cultural_adaptation"`
	TechnicalAdaptation *TechnicalAdaptConfig `json:"technical_adaptation"`
	TemporalAdaptation  *TemporalAdaptConfig  `json:"temporal_adaptation"`
}

// LanguageAdaptConfig configures language adaptation
type LanguageAdaptConfig struct {
	Enabled          bool               `json:"enabled"`
	MultiLanguage    bool               `json:"multi_language"`
	Translation      *TranslationConfig `json:"translation"`
	Localization     bool               `json:"localization"`
	RegionalDialects bool               `json:"regional_dialects"`
}

// TranslationConfig configures translation
type TranslationConfig struct {
	Provider     string   `json:"provider"` // "google", "azure", "aws"
	Languages    []string `json:"languages"`
	Quality      string   `json:"quality"` // "fast", "balanced", "accurate"
	HumanReview  bool     `json:"human_review"`
	ContextAware bool     `json:"context_aware"`
}

// CulturalAdaptConfig configures cultural adaptation
type CulturalAdaptConfig struct {
	Enabled                 bool `json:"enabled"`
	CulturalNorms           bool `json:"cultural_norms"`
	BusinessEtiquette       bool `json:"business_etiquette"`
	LocalCustoms            bool `json:"local_customs"`
	ReligiousConsiderations bool `json:"religious_considerations"`
	RegionalPreferences     bool `json:"regional_preferences"`
}

// TechnicalAdaptConfig configures technical adaptation
type TechnicalAdaptConfig struct {
	Enabled              bool `json:"enabled"`
	DeviceOptimization   bool `json:"device_optimization"`
	BrowserCompatibility bool `json:"browser_compatibility"`
	NetworkAdaptation    bool `json:"network_adaptation"`
	PlatformSpecific     bool `json:"platform_specific"`
}

// TemporalAdaptConfig configures temporal adaptation
type TemporalAdaptConfig struct {
	Enabled         bool `json:"enabled"`
	TimeZoneAware   bool `json:"timezone_aware"`
	BusinessHours   bool `json:"business_hours"`
	SeasonalContent bool `json:"seasonal_content"`
	EventBased      bool `json:"event_based"`
}

// Implementation classes
type VictimProfiler struct {
	config *VictimProfilingConfig
	mu     sync.RWMutex
}

type TemplateEngine struct {
	config    *TemplateCustomConfig
	templates map[string]interface{}
	mu        sync.RWMutex
}

type PersonalizationEngine struct {
	config *PersonalizationConfig
	rules  []PersonalizationRule
	mu     sync.RWMutex
}

type CredentialHarvester struct {
	config *CredHarvestingConfig
	forms  []FormTemplate
	mu     sync.RWMutex
}

type LureGenerator struct {
	config *LureGenerationConfig
	lures  map[string]interface{}
	mu     sync.RWMutex
}

type PreTextEngine struct {
	config    *PreTextGenerationConfig
	scenarios []PreTextScenario
	mu        sync.RWMutex
}

// VictimProfile represents a victim profile
type VictimProfile struct {
	ID              string                        `json:"id"`
	Email           string                        `json:"email"`
	Name            string                        `json:"name"`
	Company         string                        `json:"company"`
	Role            string                        `json:"role"`
	Department      string                        `json:"department"`
	Location        *LocationInfo                 `json:"location"`
	SocialMedia     map[string]SocialMediaProfile `json:"social_media"`
	TechProfile     *TechnicalProfile             `json:"tech_profile"`
	BehaviorProfile *BehaviorProfile              `json:"behavior_profile"`
	Interests       []string                      `json:"interests"`
	Connections     []Connection                  `json:"connections"`
	Vulnerabilities []Vulnerability               `json:"vulnerabilities"`
	RiskScore       int                           `json:"risk_score"`
	LastUpdated     time.Time                     `json:"last_updated"`
	Metadata        map[string]interface{}        `json:"metadata"`
}

// LocationInfo contains location information
type LocationInfo struct {
	Country     string     `json:"country"`
	State       string     `json:"state"`
	City        string     `json:"city"`
	TimeZone    string     `json:"timezone"`
	Coordinates [2]float64 `json:"coordinates"`
	IP          string     `json:"ip"`
}

// SocialMediaProfile represents a social media profile
type SocialMediaProfile struct {
	Platform  string    `json:"platform"`
	Username  string    `json:"username"`
	URL       string    `json:"url"`
	Followers int       `json:"followers"`
	Following int       `json:"following"`
	Posts     int       `json:"posts"`
	LastPost  time.Time `json:"last_post"`
	Privacy   string    `json:"privacy"`  // "public", "private", "limited"
	Activity  string    `json:"activity"` // "active", "inactive", "occasional"
}

// TechnicalProfile contains technical information
type TechnicalProfile struct {
	OS            string   `json:"os"`
	Browser       string   `json:"browser"`
	Devices       []string `json:"devices"`
	TechSkills    []string `json:"tech_skills"`
	SecurityAware bool     `json:"security_aware"`
	TechSavvy     string   `json:"tech_savvy"` // "low", "medium", "high"
}

// BehaviorProfile contains behavioral information
type BehaviorProfile struct {
	OnlineActivity     *OnlineActivity `json:"online_activity"`
	CommunicationStyle *CommStyle      `json:"communication_style"`
	DecisionMaking     *DecisionMaking `json:"decision_making"`
	RiskTolerance      string          `json:"risk_tolerance"` // "low", "medium", "high"
	TrustFactors       []string        `json:"trust_factors"`
}

// OnlineActivity represents online activity patterns
type OnlineActivity struct {
	ActiveHours      []int    `json:"active_hours"`
	Frequency        string   `json:"frequency"` // "daily", "weekly", "occasional"
	Platforms        []string `json:"platforms"`
	ContentTypes     []string `json:"content_types"`
	InteractionStyle string   `json:"interaction_style"`
}

// CommStyle represents communication style
type CommStyle struct {
	Formality    string   `json:"formality"`     // "formal", "informal", "mixed"
	Tone         string   `json:"tone"`          // "professional", "casual", "friendly"
	ResponseTime string   `json:"response_time"` // "immediate", "fast", "slow"
	Vocabulary   []string `json:"vocabulary"`
	WritingStyle string   `json:"writing_style"`
}

// DecisionMaking represents decision making patterns
type DecisionMaking struct {
	Speed            string   `json:"speed"` // "fast", "deliberate", "slow"
	InfluenceFactors []string `json:"influence_factors"`
	Authority        string   `json:"authority"`     // "independent", "seeks_approval", "follows_others"
	RiskApproach     string   `json:"risk_approach"` // "conservative", "balanced", "aggressive"
}

// Connection represents a connection/relationship
type Connection struct {
	Type         string    `json:"type"` // "colleague", "friend", "family", "professional"
	Name         string    `json:"name"`
	Email        string    `json:"email,omitempty"`
	Company      string    `json:"company,omitempty"`
	Relationship string    `json:"relationship"`
	Strength     string    `json:"strength"` // "weak", "medium", "strong"
	LastContact  time.Time `json:"last_contact"`
}

// Vulnerability represents a vulnerability or weakness
type Vulnerability struct {
	Type        string    `json:"type"` // "technical", "social", "physical", "organizational"
	Category    string    `json:"category"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"` // "low", "medium", "high", "critical"
	Exploitable bool      `json:"exploitable"`
	Discovered  time.Time `json:"discovered"`
}

// NewSocialEngineering creates a new social engineering instance
func NewSocialEngineering(config *SocialEngConfig) *SocialEngineering {
	if config == nil {
		config = getDefaultSocialEngConfig()
	}

	se := &SocialEngineering{
		config:          config,
		victimProfiler:  NewVictimProfiler(config.VictimProfiling),
		templateEngine:  NewTemplateEngine(config.TemplateCustomization),
		personalization: NewPersonalizationEngine(config.Personalization),
		credHarvester:   NewCredentialHarvester(config.CredentialHarvesting),
		lureGenerator:   NewLureGenerator(config.LureGeneration),
		preTextEngine:   NewPreTextEngine(config.PreTextGeneration),
	}

	return se
}

// ProfileVictim creates a victim profile
func (se *SocialEngineering) ProfileVictim(email string) (*VictimProfile, error) {
	if !se.config.Enabled || !se.config.VictimProfiling.Enabled {
		return nil, fmt.Errorf("victim profiling is disabled")
	}

	return se.victimProfiler.CreateProfile(email)
}

// GeneratePersonalizedContent generates personalized content
func (se *SocialEngineering) GeneratePersonalizedContent(profile *VictimProfile, template string) (string, error) {
	if !se.config.Enabled || !se.config.Personalization.Enabled {
		return "", fmt.Errorf("personalization is disabled")
	}

	return se.personalization.GenerateContent(profile, template)
}

// CreateLure creates a social engineering lure
func (se *SocialEngineering) CreateLure(profile *VictimProfile, lureType string) (interface{}, error) {
	if !se.config.Enabled || !se.config.LureGeneration.Enabled {
		return nil, fmt.Errorf("lure generation is disabled")
	}

	return se.lureGenerator.CreateLure(profile, lureType)
}

// GeneratePretext generates a pretext scenario
func (se *SocialEngineering) GeneratePretext(profile *VictimProfile, scenario string) (*PreTextScenario, error) {
	if !se.config.Enabled || !se.config.PreTextGeneration.Enabled {
		return nil, fmt.Errorf("pretext generation is disabled")
	}

	return se.preTextEngine.GenerateScenario(profile, scenario)
}

// Implementation stubs - would be fully implemented in production
func NewVictimProfiler(config *VictimProfilingConfig) *VictimProfiler {
	return &VictimProfiler{config: config}
}

func (vp *VictimProfiler) CreateProfile(email string) (*VictimProfile, error) {
	// Implementation would gather OSINT data, social media info, etc.
	profile := &VictimProfile{
		ID:          generateRandomID(),
		Email:       email,
		Name:        "Unknown",
		RiskScore:   50,
		LastUpdated: time.Now(),
		Metadata:    make(map[string]interface{}),
	}
	return profile, nil
}

func NewTemplateEngine(config *TemplateCustomConfig) *TemplateEngine {
	return &TemplateEngine{
		config:    config,
		templates: make(map[string]interface{}),
	}
}

func NewPersonalizationEngine(config *PersonalizationConfig) *PersonalizationEngine {
	return &PersonalizationEngine{
		config: config,
		rules:  []PersonalizationRule{},
	}
}

func (pe *PersonalizationEngine) GenerateContent(profile *VictimProfile, template string) (string, error) {
	// Implementation would apply personalization rules and AI generation
	return fmt.Sprintf("Personalized content for %s", profile.Name), nil
}

func NewCredentialHarvester(config *CredHarvestingConfig) *CredentialHarvester {
	return &CredentialHarvester{
		config: config,
		forms:  []FormTemplate{},
	}
}

func NewLureGenerator(config *LureGenerationConfig) *LureGenerator {
	return &LureGenerator{
		config: config,
		lures:  make(map[string]interface{}),
	}
}

func (lg *LureGenerator) CreateLure(profile *VictimProfile, lureType string) (interface{}, error) {
	// Implementation would create appropriate lure based on type and profile
	return map[string]string{
		"type":    lureType,
		"target":  profile.Email,
		"content": "Generated lure content",
	}, nil
}

func NewPreTextEngine(config *PreTextGenerationConfig) *PreTextEngine {
	return &PreTextEngine{
		config:    config,
		scenarios: []PreTextScenario{},
	}
}

func (pte *PreTextEngine) GenerateScenario(profile *VictimProfile, scenario string) (*PreTextScenario, error) {
	// Implementation would generate contextual pretext scenarios
	return &PreTextScenario{
		ID:          generateRandomID(),
		Name:        "Generated Scenario",
		Category:    scenario,
		Description: "Generated pretext scenario",
		Elements:    []ScenarioElement{},
		Variables:   make(map[string]string),
		Success:     0.75,
	}, nil
}

// Helper functions
func generateRandomID() string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 16)
	for i := range b {
		num, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		b[i] = chars[num.Int64()]
	}
	return string(b)
}

func getDefaultSocialEngConfig() *SocialEngConfig {
	return &SocialEngConfig{
		Enabled: true,
		VictimProfiling: &VictimProfilingConfig{
			Enabled:              true,
			OSINTIntegration:     &OSINTConfig{Enabled: false},
			SocialMediaScraping:  &SocialMediaConfig{Enabled: false},
			EmailAnalysis:        &EmailAnalysisConfig{Enabled: true},
			GeolocationTracking:  &GeoTrackingConfig{Enabled: true},
			DeviceFingerprinting: &DeviceFingerprintConfig{Enabled: true},
		},
		TemplateCustomization: &TemplateCustomConfig{
			Enabled:              true,
			DynamicContent:       &DynamicContentConfig{Enabled: true},
			CompanyBranding:      &CompanyBrandingConfig{Enabled: true},
			PersonalizedElements: &PersonalizedElemConfig{Enabled: true},
			ContextualAdaptation: &ContextualAdaptConfig{Enabled: true},
			A_B_Testing:          &ABTestingConfig{Enabled: false},
		},
		Personalization: &PersonalizationConfig{
			Enabled:           true,
			AIPersonalization: &AIPersonalizationConfig{Enabled: false},
			RuleBasedSystem:   &RuleBasedConfig{Enabled: true},
			LearningSystem:    &LearningSystemConfig{Enabled: false},
			ContentGeneration: &ContentGenConfig{Enabled: true},
		},
		CredentialHarvesting: &CredHarvestingConfig{
			Enabled:          true,
			MultiStepForms:   &MultiStepFormsConfig{Enabled: true},
			ValidationMimic:  &ValidationMimicConfig{Enabled: true},
			ProgressTracking: &ProgressTrackingConfig{Enabled: true},
			DataExfiltration: &DataExfiltrationConfig{Enabled: true},
			RealTimeCapture:  &RealTimeCaptureConfig{Enabled: false},
		},
		LureGeneration: &LureGenerationConfig{
			Enabled:       true,
			EmailLures:    &EmailLureConfig{Enabled: true},
			SMSLures:      &SMSLureConfig{Enabled: false},
			SocialLures:   &SocialLureConfig{Enabled: false},
			PhysicalLures: &PhysicalLureConfig{Enabled: false},
			VoiceLures:    &VoiceLureConfig{Enabled: false},
		},
		PreTextGeneration: &PreTextGenerationConfig{
			Enabled:         true,
			ScenarioEngine:  &ScenarioEngineConfig{Enabled: true},
			StoryGeneration: &StoryGenerationConfig{Enabled: true},
			ContextBuilding: &ContextBuildingConfig{Enabled: true},
			UrgencyTactics:  &UrgencyTacticsConfig{Enabled: true},
		},
		PsychologyTactics: &PsychologyTacticsConfig{
			Enabled:              true,
			CognitiveExploits:    &CognitiveExploitsConfig{Enabled: true},
			EmotionalTriggers:    &EmotionalTriggersConfig{Enabled: true},
			SocialInfluence:      &SocialInfluenceConfig{Enabled: true},
			TrustBuilding:        &TrustBuildingConfig{Enabled: true},
			PersuasionTechniques: &PersuasionTechConfig{Enabled: true},
		},
		TargetReconnaissance: &TargetReconConfig{
			Enabled:        true,
			PassiveRecon:   &PassiveReconConfig{Enabled: true},
			ActiveRecon:    &ActiveReconConfig{Enabled: false},
			SocialRecon:    &SocialReconConfig{Enabled: true},
			TechnicalRecon: &TechnicalReconConfig{Enabled: false},
			PhysicalRecon:  &PhysicalReconConfig{Enabled: false},
		},
		ContentAdaptation: &ContentAdaptationConfig{
			Enabled:             true,
			LanguageAdaptation:  &LanguageAdaptConfig{Enabled: true},
			CulturalAdaptation:  &CulturalAdaptConfig{Enabled: true},
			TechnicalAdaptation: &TechnicalAdaptConfig{Enabled: true},
			TemporalAdaptation:  &TemporalAdaptConfig{Enabled: true},
		},
	}
}
