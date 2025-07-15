package shared

import (
	"errors"
	"net"
	"sort"
	"strings"
)

// CheckMX verifies that a domain has valid MX records.
func CheckMX(domain string) ([]*net.MX, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))

	mxRecords, err := net.LookupMX(domain)
	if err != nil {
		// Differentiate between a non-existent domain and other lookup errors.
		if dnsErr, ok := err.(*net.DNSError); ok {
			if dnsErr.IsNotFound {
				return nil, errors.New("domain does not exist")
			}
			if dnsErr.IsTimeout {
				return nil, errors.New("DNS lookup timeout")
			}
		}
		return nil, errors.New("failed to lookup MX records")
	}

	if len(mxRecords) == 0 {
		return nil, errors.New("no MX records found for the domain")
	}

	// Sort MX records by priority (lower priority number = higher priority)
	sort.Slice(mxRecords, func(i, j int) bool {
		return mxRecords[i].Pref < mxRecords[j].Pref
	})

	return mxRecords, nil
}

// CheckA verifies that a domain has valid A records (fallback if no MX).
func CheckA(domain string) ([]net.IP, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))

	ips, err := net.LookupIP(domain)
	if err != nil {
		if dnsErr, ok := err.(*net.DNSError); ok {
			if dnsErr.IsNotFound {
				return nil, errors.New("domain does not exist")
			}
			if dnsErr.IsTimeout {
				return nil, errors.New("DNS lookup timeout")
			}
		}
		return nil, errors.New("failed to lookup A records")
	}

	if len(ips) == 0 {
		return nil, errors.New("no A records found for the domain")
	}

	return ips, nil
}

// ValidateDomain performs comprehensive domain validation.
func ValidateDomain(domain string) error {
	// First try MX records
	_, err := CheckMX(domain)
	if err == nil {
		return nil // MX records found, domain is valid for email
	}

	// If no MX records, check for A records as fallback
	_, aErr := CheckA(domain)
	if aErr != nil {
		return err // Return the original MX error
	}

	// Domain has A records but no MX, still potentially valid for email
	return nil
}
