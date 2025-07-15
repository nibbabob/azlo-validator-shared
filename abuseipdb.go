// File: shared/abuseipdb.go
package shared

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// AbuseIPDBClient handles interactions with the AbuseIPDB API
type AbuseIPDBClient struct {
	apiKey     string
	httpClient *http.Client
	baseURL    string
}

// AbuseIPDBResponse represents the response from AbuseIPDB API
type AbuseIPDBResponse struct {
	Data struct {
		IPAddress            string    `json:"ipAddress"`
		IsPublic             bool      `json:"isPublic"`
		IPVersion            int       `json:"ipVersion"`
		IsWhitelisted        bool      `json:"isWhitelisted"`
		AbuseConfidenceScore int       `json:"abuseConfidenceScore"`
		CountryCode          string    `json:"countryCode"`
		CountryName          string    `json:"countryName"`
		UsageType            string    `json:"usageType"`
		ISP                  string    `json:"isp"`
		Domain               string    `json:"domain"`
		TotalReports         int       `json:"totalReports"`
		NumDistinctUsers     int       `json:"numDistinctUsers"`
		LastReportedAt       time.Time `json:"lastReportedAt"`
	} `json:"data"`
}

// IPReputationResult contains the result of IP reputation check
type IPReputationResult struct {
	IPAddress            string    `json:"ip_address"`
	IsWhitelisted        bool      `json:"is_whitelisted"`
	AbuseConfidenceScore int       `json:"abuse_confidence_score"`
	TotalReports         int       `json:"total_reports"`
	CountryCode          string    `json:"country_code"`
	ISP                  string    `json:"isp"`
	Domain               string    `json:"domain"`
	LastReportedAt       time.Time `json:"last_reported_at,omitempty"`
	CheckedAt            time.Time `json:"checked_at"`
	Error                string    `json:"error,omitempty"`
}

// NewAbuseIPDBClient creates a new AbuseIPDB client
func NewAbuseIPDBClient(apiKey string) *AbuseIPDBClient {
	return &AbuseIPDBClient{
		apiKey:  apiKey,
		baseURL: "https://api.abuseipdb.com/api/v2",
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// CheckIP checks the reputation of an IP address using AbuseIPDB
func (c *AbuseIPDBClient) CheckIP(ipAddress string) (*IPReputationResult, error) {
	// Validate IP address
	if net.ParseIP(ipAddress) == nil {
		return &IPReputationResult{
			IPAddress: ipAddress,
			Error:     "invalid IP address format",
			CheckedAt: time.Now(),
		}, nil
	}

	// Create the request
	url := fmt.Sprintf("%s/check", c.baseURL)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Key", c.apiKey)
	req.Header.Set("Accept", "application/json")

	// Set query parameters
	q := req.URL.Query()
	q.Add("ipAddress", ipAddress)
	q.Add("maxAgeInDays", "90")
	q.Add("verbose", "")
	req.URL.RawQuery = q.Encode()

	// Make the request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return &IPReputationResult{
			IPAddress: ipAddress,
			Error:     fmt.Sprintf("HTTP request failed: %v", err),
			CheckedAt: time.Now(),
		}, nil
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return &IPReputationResult{
			IPAddress: ipAddress,
			Error:     fmt.Sprintf("failed to read response: %v", err),
			CheckedAt: time.Now(),
		}, nil
	}

	// Handle HTTP errors
	if resp.StatusCode != http.StatusOK {
		return &IPReputationResult{
			IPAddress: ipAddress,
			Error:     fmt.Sprintf("API error: %d - %s", resp.StatusCode, string(body)),
			CheckedAt: time.Now(),
		}, nil
	}

	// Parse JSON response
	var abuseResp AbuseIPDBResponse
	if err := json.Unmarshal(body, &abuseResp); err != nil {
		return &IPReputationResult{
			IPAddress: ipAddress,
			Error:     fmt.Sprintf("failed to parse response: %v", err),
			CheckedAt: time.Now(),
		}, nil
	}

	// Convert to our result format
	result := &IPReputationResult{
		IPAddress:            abuseResp.Data.IPAddress,
		IsWhitelisted:        abuseResp.Data.IsWhitelisted,
		AbuseConfidenceScore: abuseResp.Data.AbuseConfidenceScore,
		TotalReports:         abuseResp.Data.TotalReports,
		CountryCode:          abuseResp.Data.CountryCode,
		ISP:                  abuseResp.Data.ISP,
		Domain:               abuseResp.Data.Domain,
		LastReportedAt:       abuseResp.Data.LastReportedAt,
		CheckedAt:            time.Now(),
	}

	return result, nil
}

// GetMailServerIPs extracts IP addresses for mail servers of a domain
func GetMailServerIPs(domain string) ([]string, error) {
	// Get MX records
	mxRecords, err := net.LookupMX(domain)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup MX records: %w", err)
	}

	var ips []string
	seenIPs := make(map[string]bool)

	for _, mx := range mxRecords {
		// Remove trailing dot from MX hostname
		hostname := strings.TrimSuffix(mx.Host, ".")

		// Lookup A records for the MX hostname
		addrs, err := net.LookupHost(hostname)
		if err != nil {
			continue // Skip this MX if we can't resolve it
		}

		for _, addr := range addrs {
			// Only add unique IPs
			if !seenIPs[addr] {
				ips = append(ips, addr)
				seenIPs[addr] = true
			}
		}
	}

	return ips, nil
}
