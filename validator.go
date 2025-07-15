// File: shared/validator.go
package shared

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

// Validator handles email validation logic.
type Validator struct {
	emailRegex *regexp.Regexp
}

// NewValidator creates a new validator instance.
func NewValidator() *Validator {
	// RFC 5322 compliant email regex (simplified version)
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

	return &Validator{
		emailRegex: emailRegex,
	}
}

// ValidateEmail validates an email address and returns the result.
func (v *Validator) ValidateEmail(email string) *Result {
	result := &Result{
		Email:    email,
		Metadata: make(map[string]interface{}),
	}

	// Step 1: Basic format validation
	if !v.emailRegex.MatchString(email) {
		result.Status = "invalid"
		result.Reason = "invalid email format"
		return result
	}

	// Step 2: Extract domain
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		result.Status = "invalid"
		result.Reason = "invalid email format"
		return result
	}

	domain := parts[1]
	localPart := parts[0]

	// Step 3: Basic local part validation
	if len(localPart) == 0 || len(localPart) > 64 {
		result.Status = "invalid"
		result.Reason = "invalid local part length"
		return result
	}

	// Step 4: Domain validation
	if len(domain) == 0 || len(domain) > 253 {
		result.Status = "invalid"
		result.Reason = "invalid domain length"
		return result
	}

	// Step 5: DNS validation
	validationDetails := v.validateDomain(domain)
	for k, v := range validationDetails.metadata {
		result.Metadata[k] = v
	}

	if !validationDetails.valid {
		result.Status = "invalid"
		result.Reason = validationDetails.reason
		return result
	}

	// If all checks pass
	result.Status = "valid"
	result.Reason = "email appears valid"

	return result
}

// domainValidationResult holds domain validation results
type domainValidationResult struct {
	valid    bool
	reason   string
	metadata map[string]interface{}
}

// validateDomain performs DNS-based domain validation
func (v *Validator) validateDomain(domain string) domainValidationResult {
	metadata := make(map[string]interface{})

	// Check if domain resolves
	_, err := net.LookupHost(domain)
	if err != nil {
		return domainValidationResult{
			valid:    false,
			reason:   "domain does not resolve",
			metadata: metadata,
		}
	}
	metadata["domain_resolves"] = true

	// Check for MX records
	mxRecords, err := net.LookupMX(domain)
	if err != nil {
		return domainValidationResult{
			valid:    false,
			reason:   "no MX records found",
			metadata: metadata,
		}
	}

	if len(mxRecords) == 0 {
		return domainValidationResult{
			valid:    false,
			reason:   "no MX records found",
			metadata: metadata,
		}
	}

	// Store MX record information
	var mxHosts []string
	for _, mx := range mxRecords {
		mxHosts = append(mxHosts, fmt.Sprintf("%s (priority: %d)", mx.Host, mx.Pref))
	}
	metadata["mx_records"] = mxHosts
	metadata["mx_count"] = len(mxRecords)

	// Additional checks for suspicious patterns
	suspiciousPatterns := []string{
		"temp", "temporary", "disposable", "throwaway", "fake",
		"test", "example", "invalid", "localhost",
	}

	for _, pattern := range suspiciousPatterns {
		if strings.Contains(strings.ToLower(domain), pattern) {
			return domainValidationResult{
				valid:    false,
				reason:   fmt.Sprintf("domain contains suspicious pattern: %s", pattern),
				metadata: metadata,
			}
		}
	}

	// Check for common disposable email domains
	disposableDomains := []string{
		"10minutemail.com", "guerrillamail.com", "mailinator.com",
		"tempmail.org", "throwaway.email", "yopmail.com",
		"temp-mail.org", "getairmail.com", "sharklasers.com",
	}

	for _, disposable := range disposableDomains {
		if strings.ToLower(domain) == disposable {
			return domainValidationResult{
				valid:    false,
				reason:   "disposable email domain detected",
				metadata: metadata,
			}
		}
	}

	// All checks passed
	return domainValidationResult{
		valid:    true,
		reason:   "domain validation passed",
		metadata: metadata,
	}
}

// ValidateBatch validates multiple emails and returns results
func (v *Validator) ValidateBatch(emails []string) []*Result {
	results := make([]*Result, len(emails))

	for i, email := range emails {
		results[i] = v.ValidateEmail(email)
	}

	return results
}

// GetValidatorStats returns statistics about the validator
func (v *Validator) GetValidatorStats() map[string]interface{} {
	return map[string]interface{}{
		"validator_type": "basic",
		"features": []string{
			"format_validation",
			"domain_resolution",
			"mx_record_check",
			"disposable_domain_detection",
		},
		"version": "1.0.0",
	}
}
