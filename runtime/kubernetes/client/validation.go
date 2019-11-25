package client

import (
	"fmt"
	"regexp"
)

const (
	dns1035LabelFmt    string = "[a-z]([-a-z0-9]*[a-z0-9])?"
	dns1035LabelErrMsg string = "a DNS-1035 label must consist of lower case alphanumeric characters or '-', start with an alphabetic character, and end with an alphanumeric character"

	// DNS1035LabelMaxLength is a label's max length in DNS (RFC 1035)
	DNS1035LabelMaxLength int = 63
)

var (
	// service name validation regexp
	dns1035LabelRegexp = regexp.MustCompile("^" + dns1035LabelFmt + "$")
)

// ValidateServiceName validates kubernetes service name
// https://github.com/kubernetes/kubernetes/blob/master/pkg/apis/core/validation/validation.go#L223-L226
func ValidateServiceName(name string) error {
	if len(name) > DNS1035LabelMaxLength {
		return fmt.Errorf("%s", MaxLenError(DNS1035LabelMaxLength))
	}
	if !dns1035LabelRegexp.MatchString(name) {
		return fmt.Errorf("%s", RegexError(dns1035LabelErrMsg, dns1035LabelFmt, "my-name", "abc-123"))
	}
	return nil
}

const (
	dns1123LabelFmt          string = "[a-z0-9]([-a-z0-9]*[a-z0-9])?"
	dns1123SubdomainFmt      string = dns1123LabelFmt + "(\\." + dns1123LabelFmt + ")*"
	dns1123SubdomainErrorMsg string = "a DNS-1123 subdomain must consist of lower case alphanumeric characters, '-' or '.', and must start and end with an alphanumeric character"

	// DNS1123SubdomainMaxLength is a subdomain's max length in DNS (RFC 1123)
	DNS1123SubdomainMaxLength int = 253
)

var (
	dns1123SubdomainRegexp = regexp.MustCompile("^" + dns1123SubdomainFmt + "$")
)

// ValidateDeploymentName validates kubernetes deployment name
// https://github.com/kubernetes/kubernetes/blob/master/pkg/apis/apps/validation/validation.go#L381-L382
func ValidateDeploymentName(name string) error {
	if len(name) > DNS1123SubdomainMaxLength {
		return fmt.Errorf("%s", MaxLenError(DNS1123SubdomainMaxLength))
	}
	if !dns1123SubdomainRegexp.MatchString(name) {
		return fmt.Errorf("%s", RegexError(dns1123SubdomainErrorMsg, dns1123SubdomainFmt, "example.com"))
	}
	return nil
}

// RegexError returns a string explanation of a regex validation failure.
func RegexError(msg string, fmt string, examples ...string) string {
	if len(examples) == 0 {
		return msg + " (regex used for validation is '" + fmt + "')"
	}
	msg += " (e.g. "
	for i := range examples {
		if i > 0 {
			msg += " or "
		}
		msg += "'" + examples[i] + "', "
	}
	msg += "regex used for validation is '" + fmt + "')"
	return msg
}

// MaxLenError returns a string explanation of a "string too long" validation
// failure.
func MaxLenError(length int) string {
	return fmt.Sprintf("must be no more than %d characters", length)
}
