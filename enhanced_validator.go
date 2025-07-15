// File: shared/enhanced_validator.go
package shared

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

// EnhancedValidator extends the basic validator with IP reputation checking
type EnhancedValidator struct {
	basicValidator *Validator
	abuseIPDB      *AbuseIPDBClient
	ipCache        map[string]*IPReputationResult
	cacheMutex     sync.RWMutex
	cacheExpiry    time.Duration
}

// NewEnhancedValidator creates a new enhanced validator with AbuseIPDB integration
func NewEnhancedValidator(abuseIPDBKey string) *EnhancedValidator {
	return &EnhancedValidator{
		basicValidator: NewValidator(),
		abuseIPDB:      NewAbuseIPDBClient(abuseIPDBKey),
		ipCache:        make(map[string]*IPReputationResult),
		cacheExpiry:    time.Hour * 24, // Cache results for 24 hours
	}
}

// ValidateEmailWithReputation performs email validation including IP reputation checks
func (v *EnhancedValidator) ValidateEmailWithReputation(email string) *Result {
	// Start with basic validation
	result := v.basicValidator.ValidateEmail(email)

	// If basic validation failed, no need to check IP reputation
	if result.Status != "valid" {
		return result
	}

	// Extract domain from email
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		result.Status = "invalid"
		result.Reason = "invalid email format"
		return result
	}
	domain := parts[1]

	// Get mail server IPs for the domain
	ips, err := GetMailServerIPs(domain)
	if err != nil {
		log.Printf("Failed to get mail server IPs for domain %s: %v", domain, err)
		// Don't fail the validation, just log the error
		result.Metadata["ip_reputation_error"] = fmt.Sprintf("Failed to lookup mail servers: %v", err)
		return result
	}

	if len(ips) == 0 {
		result.Status = "suspicious"
		result.Reason = "no mail servers found for domain"
		return result
	}

	// Check reputation for each IP
	var reputationResults []IPReputationResult
	highRiskFound := false

	for _, ip := range ips {
		ipResult := v.checkIPReputationWithCache(ip)
		reputationResults = append(reputationResults, *ipResult)

		// Consider high risk if abuse confidence > 75% or many reports
		if ipResult.AbuseConfidenceScore > 75 || ipResult.TotalReports > 50 {
			highRiskFound = true
		}
	}

	// Update result based on IP reputation
	if highRiskFound {
		result.Status = "suspicious"
		result.Reason = "mail server IP has poor reputation"
	}

	// Add reputation data to metadata
	if result.Metadata == nil {
		result.Metadata = make(map[string]interface{})
	}
	result.Metadata["ip_reputation"] = reputationResults
	result.Metadata["mail_server_ips"] = ips

	return result
}

// checkIPReputationWithCache checks IP reputation with caching
func (v *EnhancedValidator) checkIPReputationWithCache(ip string) *IPReputationResult {
	v.cacheMutex.RLock()
	if cached, exists := v.ipCache[ip]; exists {
		// Check if cache entry is still valid
		if time.Since(cached.CheckedAt) < v.cacheExpiry {
			v.cacheMutex.RUnlock()
			return cached
		}
	}
	v.cacheMutex.RUnlock()

	// Cache miss or expired, fetch from API
	result, err := v.abuseIPDB.CheckIP(ip)
	if err != nil {
		log.Printf("Error checking IP reputation for %s: %v", ip, err)
		return &IPReputationResult{
			IPAddress: ip,
			Error:     fmt.Sprintf("API error: %v", err),
			CheckedAt: time.Now(),
		}
	}

	// Update cache
	v.cacheMutex.Lock()
	v.ipCache[ip] = result
	v.cacheMutex.Unlock()

	return result
}

// ValidateEmail provides backward compatibility with basic validation
func (v *EnhancedValidator) ValidateEmail(email string) *Result {
	return v.ValidateEmailWithReputation(email)
}

// ClearExpiredCache removes expired entries from the IP cache
func (v *EnhancedValidator) ClearExpiredCache() {
	v.cacheMutex.Lock()
	defer v.cacheMutex.Unlock()

	now := time.Now()
	for ip, result := range v.ipCache {
		if now.Sub(result.CheckedAt) > v.cacheExpiry {
			delete(v.ipCache, ip)
		}
	}
}

// GetCacheStats returns statistics about the IP reputation cache
func (v *EnhancedValidator) GetCacheStats() map[string]interface{} {
	v.cacheMutex.RLock()
	defer v.cacheMutex.RUnlock()

	return map[string]interface{}{
		"cached_entries": len(v.ipCache),
		"cache_expiry":   v.cacheExpiry.String(),
	}
}
