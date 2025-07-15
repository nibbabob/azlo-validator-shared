package shared

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"
)

const (
	smtpPort   = 25
	heloDomain = "my-validator-service.com"
	fromEmail  = "verify@my-validator-service.com"
)

// SMTP command templates
const (
	cmdHelo     = "HELO %s"
	cmdMailFrom = "MAIL FROM:<%s>"
	cmdRcptTo   = "RCPT TO:<%s>"
	cmdQuit     = "QUIT"
)

// SMTPResult represents the result of SMTP validation.
type SMTPResult struct {
	Status Status
	Reason string
	Code   int
}

// CheckSMTP performs the mailbox verification using SMTP.
func CheckSMTP(email string, servers []*net.MX, timeout time.Duration) SMTPResult {
	if len(servers) == 0 {
		return SMTPResult{
			Status: StatusInvalid,
			Reason: "No SMTP servers found for the domain",
			Code:   0,
		}
	}

	// Try each MX server in priority order
	for _, server := range servers {
		result := checkSMTPServer(email, server.Host, timeout)

		// If we get a definitive answer (valid or invalid), return it
		if result.Status == StatusValid || result.Status == StatusInvalid {
			return result
		}

		// If risky/error, try next server
		continue
	}

	// All servers failed or returned risky status
	return SMTPResult{
		Status: StatusRisky,
		Reason: "All SMTP servers returned uncertain results",
		Code:   0,
	}
}

// checkSMTPServer checks a single SMTP server.
func checkSMTPServer(email, serverHost string, timeout time.Duration) SMTPResult {
	serverAddr := net.JoinHostPort(serverHost, fmt.Sprintf("%d", smtpPort))

	conn, err := net.DialTimeout("tcp", serverAddr, timeout)
	if err != nil {
		return SMTPResult{
			Status: StatusRisky,
			Reason: fmt.Sprintf("Could not connect to SMTP server %s", serverHost),
			Code:   0,
		}
	}
	defer conn.Close()

	// Set read/write deadlines
	deadline := time.Now().Add(timeout)
	conn.SetDeadline(deadline)

	reader := bufio.NewReader(conn)

	// Read the welcome message from the server
	code, msg := readResponse(reader)
	if code < 200 || code >= 300 {
		return SMTPResult{
			Status: StatusRisky,
			Reason: fmt.Sprintf("Server greeting failed: %d %s", code, msg),
			Code:   code,
		}
	}

	// Send HELO command
	if err := send(conn, fmt.Sprintf(cmdHelo, heloDomain)); err != nil {
		return SMTPResult{
			Status: StatusRisky,
			Reason: "HELO command failed",
			Code:   0,
		}
	}
	code, msg = readResponse(reader)
	if code < 200 || code >= 300 {
		return SMTPResult{
			Status: StatusRisky,
			Reason: fmt.Sprintf("HELO command rejected: %d %s", code, msg),
			Code:   code,
		}
	}

	// Send MAIL FROM command
	if err := send(conn, fmt.Sprintf(cmdMailFrom, fromEmail)); err != nil {
		return SMTPResult{
			Status: StatusRisky,
			Reason: "MAIL FROM command failed",
			Code:   0,
		}
	}
	code, msg = readResponse(reader)
	if code < 200 || code >= 300 {
		return SMTPResult{
			Status: StatusRisky,
			Reason: fmt.Sprintf("MAIL FROM command rejected: %d %s", code, msg),
			Code:   code,
		}
	}

	// Send RCPT TO command and analyze the response
	if err := send(conn, fmt.Sprintf(cmdRcptTo, email)); err != nil {
		return SMTPResult{
			Status: StatusRisky,
			Reason: "RCPT TO command failed",
			Code:   0,
		}
	}
	code, msg = readResponse(reader)

	// Gracefully disconnect from the server
	send(conn, cmdQuit)

	return analyzeSMTPResponse(email, code, msg)
}

// analyzeSMTPResponse interprets the SMTP response code to determine the validation status.
func analyzeSMTPResponse(email string, code int, msg string) SMTPResult {
	switch {
	case code >= 200 && code <= 299:
		return SMTPResult{
			Status: StatusValid,
			Reason: "Mailbox confirmed",
			Code:   code,
		}
	case code == 550 || code == 551 || code == 553:
		return SMTPResult{
			Status: StatusInvalid,
			Reason: "Mailbox does not exist",
			Code:   code,
		}
	case code == 552:
		return SMTPResult{
			Status: StatusRisky,
			Reason: "Mailbox full or over quota",
			Code:   code,
		}
	case code >= 500:
		return SMTPResult{
			Status: StatusRisky,
			Reason: fmt.Sprintf("Server rejected the request: %d %s", code, msg),
			Code:   code,
		}
	case code >= 400:
		return SMTPResult{
			Status: StatusRisky,
			Reason: "Greylisted or temporary server issue",
			Code:   code,
		}
	default:
		return SMTPResult{
			Status: StatusRisky,
			Reason: fmt.Sprintf("Unknown SMTP response: %d %s", code, msg),
			Code:   code,
		}
	}
}

// send writes a message to the SMTP connection.
func send(conn net.Conn, msg string) error {
	_, err := conn.Write([]byte(msg + "\r\n"))
	return err
}

// readResponse reads a line from the SMTP connection.
func readResponse(r *bufio.Reader) (int, string) {
	line, _, err := r.ReadLine()
	if err != nil {
		return 0, ""
	}

	responseLine := string(line)
	if len(responseLine) < 3 {
		return 0, responseLine
	}

	var code int
	_, err = fmt.Sscanf(responseLine, "%d", &code)
	if err != nil {
		return 0, responseLine
	}

	// Extract message part (everything after the code and space)
	if len(responseLine) > 4 {
		return code, strings.TrimSpace(responseLine[4:])
	}

	return code, ""
}
