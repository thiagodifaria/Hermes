package valueobjects

import (
	"errors"
	"regexp"
	"strings"
)

// Email represents a validated email address value object
type Email struct {
	value string
}

// Email validation errors
var (
	ErrEmptyEmail        = errors.New("email cannot be empty")
	ErrInvalidEmailFormat = errors.New("invalid email format")
	ErrEmailTooLong      = errors.New("email address is too long")
	ErrInvalidDomain     = errors.New("invalid email domain")
)

// Email validation constants
const (
	MaxEmailLength = 254 // RFC 5321 limit
	MinEmailLength = 6   // "a@b.co" minimum reasonable length
)

// Email regex pattern (more comprehensive than simple pattern)
var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

// Forbidden email domains for security
var forbiddenDomains = map[string]bool{
	"10minutemail.com":  true,
	"guerrillamail.com": true,
	"mailinator.com":    true,
	"tempmail.org":      true,
	"throwaway.email":   true,
}

// NewEmail creates a new Email value object with validation
func NewEmail(email string) (Email, error) {
	// Trim whitespace
	email = strings.TrimSpace(email)
	
	// Check if empty
	if email == "" {
		return Email{}, ErrEmptyEmail
	}
	
	// Check length
	if len(email) < MinEmailLength {
		return Email{}, ErrInvalidEmailFormat
	}
	if len(email) > MaxEmailLength {
		return Email{}, ErrEmailTooLong
	}
	
	// Convert to lowercase for consistency
	email = strings.ToLower(email)
	
	// Validate format
	if !emailRegex.MatchString(email) {
		return Email{}, ErrInvalidEmailFormat
	}
	
	// Additional validations
	if err := validateEmailStructure(email); err != nil {
		return Email{}, err
	}
	
	// Check for forbidden domains
	domain := extractDomain(email)
	if forbiddenDomains[domain] {
		return Email{}, ErrInvalidDomain
	}
	
	return Email{value: email}, nil
}

// MustNewEmail creates a new Email value object and panics on validation error
// Use only when you're certain the email is valid (e.g., from trusted sources)
func MustNewEmail(email string) Email {
	emailVO, err := NewEmail(email)
	if err != nil {
		panic(err)
	}
	return emailVO
}

// String returns the string representation of the email
func (e Email) String() string {
	return e.value
}

// Value returns the email value
func (e Email) Value() string {
	return e.value
}

// Domain returns the domain part of the email
func (e Email) Domain() string {
	return extractDomain(e.value)
}

// LocalPart returns the local part of the email (before @)
func (e Email) LocalPart() string {
	parts := strings.Split(e.value, "@")
	if len(parts) != 2 {
		return ""
	}
	return parts[0]
}

// IsEmpty checks if the email is empty
func (e Email) IsEmpty() bool {
	return e.value == ""
}

// Equals checks if two emails are equal
func (e Email) Equals(other Email) bool {
	return e.value == other.value
}

// IsFromDomain checks if the email is from a specific domain
func (e Email) IsFromDomain(domain string) bool {
	return strings.EqualFold(e.Domain(), domain)
}

// IsPersonal checks if the email appears to be a personal email
// (heuristic based on common personal email providers)
func (e Email) IsPersonal() bool {
	personalDomains := []string{
		"gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
		"icloud.com", "protonmail.com", "aol.com", "live.com",
	}
	
	domain := e.Domain()
	for _, personalDomain := range personalDomains {
		if strings.EqualFold(domain, personalDomain) {
			return true
		}
	}
	return false
}

// IsCorporate checks if the email appears to be a corporate email
func (e Email) IsCorporate() bool {
	return !e.IsPersonal()
}

// MaskEmail returns a masked version of the email for display purposes
// Example: john.doe@example.com -> j***@example.com
func (e Email) MaskEmail() string {
	localPart := e.LocalPart()
	domain := e.Domain()
	
	if len(localPart) <= 1 {
		return "*@" + domain
	}
	
	masked := string(localPart[0]) + strings.Repeat("*", len(localPart)-1)
	return masked + "@" + domain
}

// GetProvider returns the email provider name
func (e Email) GetProvider() string {
	domain := e.Domain()
	
	// Map of domains to provider names
	providers := map[string]string{
		"gmail.com":      "Google",
		"googlemail.com": "Google",
		"yahoo.com":      "Yahoo",
		"hotmail.com":    "Microsoft",
		"outlook.com":    "Microsoft",
		"live.com":       "Microsoft",
		"icloud.com":     "Apple",
		"me.com":         "Apple",
		"mac.com":        "Apple",
		"protonmail.com": "ProtonMail",
		"aol.com":        "AOL",
	}
	
	if provider, exists := providers[domain]; exists {
		return provider
	}
	
	return "Other"
}

// ToJSON returns JSON representation for serialization
func (e Email) ToJSON() map[string]interface{} {
	return map[string]interface{}{
		"value":    e.value,
		"domain":   e.Domain(),
		"provider": e.GetProvider(),
		"masked":   e.MaskEmail(),
	}
}

// validateEmailStructure performs additional structural validation
func validateEmailStructure(email string) error {
	// Split into local and domain parts
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return ErrInvalidEmailFormat
	}
	
	localPart := parts[0]
	domain := parts[1]
	
	// Validate local part
	if len(localPart) == 0 || len(localPart) > 64 {
		return ErrInvalidEmailFormat
	}
	
	// Local part cannot start or end with a dot
	if strings.HasPrefix(localPart, ".") || strings.HasSuffix(localPart, ".") {
		return ErrInvalidEmailFormat
	}
	
	// Local part cannot have consecutive dots
	if strings.Contains(localPart, "..") {
		return ErrInvalidEmailFormat
	}
	
	// Validate domain part
	if len(domain) == 0 || len(domain) > 253 {
		return ErrInvalidDomain
	}
	
	// Domain cannot start or end with a dot or hyphen
	if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") ||
		strings.HasPrefix(domain, "-") || strings.HasSuffix(domain, "-") {
		return ErrInvalidDomain
	}
	
	// Domain must have at least one dot
	if !strings.Contains(domain, ".") {
		return ErrInvalidDomain
	}
	
	// Validate domain labels
	labels := strings.Split(domain, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return ErrInvalidDomain
		}
		
		// Labels cannot start or end with hyphen
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return ErrInvalidDomain
		}
	}
	
	// Top-level domain must be at least 2 characters
	if len(labels[len(labels)-1]) < 2 {
		return ErrInvalidDomain
	}
	
	return nil
}

// extractDomain extracts the domain part from an email address
func extractDomain(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return ""
	}
	return parts[1]
}

// IsValidEmailDomain checks if a domain is valid for email
func IsValidEmailDomain(domain string) bool {
	if domain == "" {
		return false
	}
	
	// Basic format check
	if !regexp.MustCompile(`^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`).MatchString(domain) {
		return false
	}
	
	// Check forbidden domains
	if forbiddenDomains[strings.ToLower(domain)] {
		return false
	}
	
	return true
}

// NormalizeEmail normalizes an email address for comparison
func NormalizeEmail(email string) string {
	email = strings.TrimSpace(strings.ToLower(email))
	
	// Gmail-specific normalization: remove dots and plus addressing
	if strings.HasSuffix(email, "@gmail.com") || strings.HasSuffix(email, "@googlemail.com") {
		parts := strings.Split(email, "@")
		if len(parts) == 2 {
			localPart := parts[0]
			domain := "gmail.com" // Normalize googlemail.com to gmail.com
			
			// Remove dots
			localPart = strings.ReplaceAll(localPart, ".", "")
			
			// Remove plus addressing (everything after +)
			if plusIndex := strings.Index(localPart, "+"); plusIndex != -1 {
				localPart = localPart[:plusIndex]
			}
			
			email = localPart + "@" + domain
		}
	}
	
	return email
}

// BulkValidateEmails validates multiple emails and returns results
func BulkValidateEmails(emails []string) map[string]error {
	results := make(map[string]error)
	
	for _, email := range emails {
		_, err := NewEmail(email)
		results[email] = err
	}
	
	return results
}

// ExtractEmailsFromText extracts email addresses from a text string
func ExtractEmailsFromText(text string) []string {
	// More permissive regex for extraction
	extractRegex := regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	matches := extractRegex.FindAllString(text, -1)
	
	// Validate and deduplicate
	emailMap := make(map[string]bool)
	var validEmails []string
	
	for _, match := range matches {
		if _, err := NewEmail(match); err == nil {
			normalized := NormalizeEmail(match)
			if !emailMap[normalized] {
				emailMap[normalized] = true
				validEmails = append(validEmails, match)
			}
		}
	}
	
	return validEmails
}