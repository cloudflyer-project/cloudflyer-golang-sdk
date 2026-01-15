package cfsolver

import "fmt"

// APIError is returned when an API request fails.
type APIError struct {
	Message    string
	StatusCode int
}

func NewAPIError(message string, statusCode int) *APIError {
	return &APIError{
		Message:    message,
		StatusCode: statusCode,
	}
}

func (e *APIError) Error() string {
	return fmt.Sprintf("API error (status %d): %s", e.StatusCode, e.Message)
}

// ChallengeError is returned when challenge solving fails.
type ChallengeError struct {
	Message string
}

func NewChallengeError(message string) *ChallengeError {
	return &ChallengeError{
		Message: message,
	}
}

func (e *ChallengeError) Error() string {
	return fmt.Sprintf("challenge error: %s", e.Message)
}

// TimeoutError is returned when an operation times out.
type TimeoutError struct {
	Message string
}

func NewTimeoutError(message string) *TimeoutError {
	return &TimeoutError{
		Message: message,
	}
}

func (e *TimeoutError) Error() string {
	return fmt.Sprintf("timeout: %s", e.Message)
}

// ConnectionError is returned when connection to service fails.
type ConnectionError struct {
	Message string
	Cause   error
}

func NewConnectionError(message string, cause error) *ConnectionError {
	return &ConnectionError{
		Message: message,
		Cause:   cause,
	}
}

func (e *ConnectionError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("connection error: %s: %v", e.Message, e.Cause)
	}
	return fmt.Sprintf("connection error: %s", e.Message)
}

func (e *ConnectionError) Unwrap() error {
	return e.Cause
}

// ProxyError is returned when proxy operation fails.
type ProxyError struct {
	Message string
	Cause   error
}

func NewProxyError(message string, cause error) *ProxyError {
	return &ProxyError{
		Message: message,
		Cause:   cause,
	}
}

func (e *ProxyError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("proxy error: %s: %v", e.Message, e.Cause)
	}
	return fmt.Sprintf("proxy error: %s", e.Message)
}

func (e *ProxyError) Unwrap() error {
	return e.Cause
}
