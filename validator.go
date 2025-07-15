package shared

import (
	"log"
	"strings"
	"time"
)

// Validator holds the configuration for the validation process.
type Validator struct {
	config ValidatorConfig
}

// NewValidator creates a new Validator instance with default settings.
func NewValidator() *Validator {
	// In a real application, these lists would be loaded from a configuration file or database.
	config := ValidatorConfig{
		DisposableDomains: map[string]bool{
			"mailinator.com":    true,
			"guerrillamail.com": true,
			"tempmail.org":      true,
			"10minutemail.com":  true,
		},
		RoleBasedAccounts: map[string]bool{
			"admin":      true,
			"support":    true,
			"info":       true,
			"contact":    true,
			"sales":      true,
			"marketing":  true,
			"noreply":    true,
			"no-reply":   true,
			"webmaster":  true,
			"postmaster": true,
		},
		SMTPTimeout: 10 * time.Second,
		MaxRetries:  3,
	}
	return &Validator{config: config}
}

// NewValidatorWithConfig creates a new Validator instance with custom configuration.
func NewValidatorWithConfig(config ValidatorConfig) *Validator {
	return &Validator{config: config}
}

// ValidateEmail performs the full email validation process.
func (v *Validator) ValidateEmail(email string) Result {
	result := Result{
		Email:     email,
		Timestamp: time.Now(),
	}

	// Step 1: Syntax Check
	if !IsValidSyntax(email) {
		result.Status = StatusInvalid
		result.Reason = "Invalid email syntax"
		return result
	}

	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		result.Status = StatusInvalid
		result.Reason = "Invalid email format"
		return result
	}

	localPart, domain := parts[0], parts[1]

	// Step 2: Disposable Domain Check
	if IsDisposable(domain, v.config.DisposableDomains) {
		result.Status = StatusInvalid
		result.Reason = "Disposable email domain"
		return result
	}

	// Step 3: Role-Based Account Check
	if IsRoleBased(localPart, v.config.RoleBasedAccounts) {
		result.Status = StatusRisky
		result.Reason = "Role-based account"
		return result
	}

	// Step 4: Domain/DNS Check
	mxRecords, err := CheckMX(domain)
	if err != nil {
		result.Status = StatusInvalid
		result.Reason = err.Error()
		return result
	}

	// Step 5: SMTP Mailbox Check
	smtpResult := CheckSMTP(email, mxRecords, v.config.SMTPTimeout)
	log.Printf("SMTP check for %s completed with status: %s, reason: %s",
		email, smtpResult.Status, smtpResult.Reason)

	result.Status = smtpResult.Status
	result.Reason = smtpResult.Reason
	return result
}

// GetConfig returns the current validator configuration.
func (v *Validator) GetConfig() ValidatorConfig {
	return v.config
}
