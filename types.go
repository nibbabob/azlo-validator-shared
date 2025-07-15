package shared

import "time"

// Status represents the outcome of the validation.
type Status string

const (
	StatusValid      Status = "VALID"
	StatusInvalid    Status = "INVALID"
	StatusRisky      Status = "RISKY"
	StatusPending    Status = "PENDING"
	StatusProcessing Status = "PROCESSING"
	StatusError      Status = "ERROR"
)

// Result holds the complete validation result.
type Result struct {
	JobID     string    `json:"job_id"`
	Email     string    `json:"email"`
	Status    Status    `json:"status"`
	Reason    string    `json:"reason"`
	Timestamp time.Time `json:"timestamp"`
}

// ValidationJob represents a job to be processed by workers.
type ValidationJob struct {
	JobID     string    `json:"job_id"`
	Email     string    `json:"email"`
	Timestamp time.Time `json:"timestamp"`
}

// BatchRequest represents a batch validation request.
type BatchRequest struct {
	Emails []string `json:"emails"`
}

// BatchResponse represents the response for batch validation.
type BatchResponse struct {
	JobID   string   `json:"job_id"`
	Emails  []string `json:"emails"`
	Status  string   `json:"status"`
	Message string   `json:"message,omitempty"`
}

// Queue interface for job queue operations.
type Queue interface {
	PublishJob(job ValidationJob) error
	ConsumeJobs() (<-chan ValidationJob, error)
	PublishResult(result Result) error
	ConsumeResults() (<-chan Result, error)
	Close() error
}

// ValidatorConfig holds configuration for email validation.
type ValidatorConfig struct {
	DisposableDomains map[string]bool
	RoleBasedAccounts map[string]bool
	SMTPTimeout       time.Duration
	MaxRetries        int
}
