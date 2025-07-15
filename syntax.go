package shared

import (
	"regexp"
	"strings"
)

// A more comprehensive regex for email syntax validation.
var emailRegex = regexp.MustCompile(`^(?i)[a-z0-9!#$%&'*+\/=?^_\x60{|}~-]+(?:\.[a-z0-9!#$%&'*+\/=?^_\x60{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`)

// IsValidSyntax checks the basic format of the email address.
func IsValidSyntax(email string) bool {
	if len(email) == 0 || len(email) > 254 {
		return false
	}

	// Check for basic format
	if !emailRegex.MatchString(email) {
		return false
	}

	// Additional checks
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}

	localPart := parts[0]
	domain := parts[1]

	// Local part length check (RFC 5321)
	if len(localPart) > 64 {
		return false
	}

	// Domain length check
	if len(domain) > 253 {
		return false
	}

	// Check for consecutive dots
	if strings.Contains(email, "..") {
		return false
	}

	// Check if local part starts or ends with dot
	if strings.HasPrefix(localPart, ".") || strings.HasSuffix(localPart, ".") {
		return false
	}

	return true
}

// IsDisposable checks if the domain is a known disposable email provider.
func IsDisposable(domain string, disposableDomains map[string]bool) bool {
	domain = strings.ToLower(domain)
	return disposableDomains[domain]
}

// IsRoleBased checks if the local part of the email is a role-based account.
func IsRoleBased(localPart string, roleBasedAccounts map[string]bool) bool {
	localPart = strings.ToLower(localPart)
	return roleBasedAccounts[localPart]
}
