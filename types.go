// File: shared/types.go
package shared

import (
	"time"
)

// Status constants for email validation results
type Status string

const (
	StatusValid   Status = "valid"
	StatusInvalid Status = "invalid"
	StatusRisky   Status = "risky"
	StatusUnknown Status = "unknown"
)

// String returns the string representation of the status
func (s Status) String() string {
	return string(s)
}

// ValidationJob represents an email validation job.
type ValidationJob struct {
	JobID     string    `json:"job_id"`
	Email     string    `json:"email"`
	Timestamp time.Time `json:"timestamp"`
}

// Result represents the result of an email validation.
type Result struct {
	JobID    string                 `json:"job_id"`
	Email    string                 `json:"email"`
	Status   string                 `json:"status"` // "valid", "invalid", "risky", "unknown"
	Reason   string                 `json:"reason"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// BatchRequest represents a batch validation request.
type BatchRequest struct {
	Emails []string `json:"emails"`
}

// BatchResponse represents a batch validation response.
type BatchResponse struct {
	JobID   string   `json:"job_id"`
	Emails  []string `json:"emails"`
	Status  string   `json:"status"`
	Message string   `json:"message"`
}

// Queue interface defines the operations for job queuing.
type Queue interface {
	PublishJob(job ValidationJob) error
	ConsumeJobs() (<-chan ValidationJob, error)
	PublishResult(result Result) error
	ConsumeResults() (<-chan Result, error)
	Close() error
}
