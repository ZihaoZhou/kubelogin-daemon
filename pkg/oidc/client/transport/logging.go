package transport

import (
	"net/http"
	"net/http/httputil"
	"regexp"

	"github.com/ZihaoZhou/kubelogin-daemon/pkg/infrastructure/logger"
)

const (
	levelDumpHeaders = 2
	levelDumpBody    = 3
)

// SEC-2: Patterns that match sensitive values in HTTP dumps.
// Redact Authorization headers and JWT-like tokens in request/response bodies.
var sensitivePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(Authorization:\s*)(Bearer\s+)\S+`),
	regexp.MustCompile(`(?i)("(?:id_token|access_token|refresh_token)":\s*")[^"]+(")`),
	regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}[A-Za-z0-9._-]*`),
}

// redactSensitive replaces tokens and credentials in HTTP dump output.
func redactSensitive(data []byte) []byte {
	result := data
	result = sensitivePatterns[0].ReplaceAll(result, []byte("${1}${2}[REDACTED]"))
	result = sensitivePatterns[1].ReplaceAll(result, []byte("${1}[REDACTED]${2}"))
	result = sensitivePatterns[2].ReplaceAll(result, []byte("[REDACTED-JWT]"))
	return result
}

type WithLogging struct {
	Base   http.RoundTripper
	Logger logger.Interface
}

func (t *WithLogging) RoundTrip(req *http.Request) (*http.Response, error) {
	if !t.Logger.IsEnabled(levelDumpHeaders) {
		return t.Base.RoundTrip(req)
	}

	reqDump, err := httputil.DumpRequestOut(req, t.Logger.IsEnabled(levelDumpBody))
	if err != nil {
		t.Logger.V(levelDumpHeaders).Infof("could not dump the request: %s", err)
		return t.Base.RoundTrip(req)
	}
	t.Logger.V(levelDumpHeaders).Infof("%s", string(redactSensitive(reqDump)))
	resp, err := t.Base.RoundTrip(req)
	if err != nil {
		return resp, err
	}
	respDump, err := httputil.DumpResponse(resp, t.Logger.IsEnabled(levelDumpBody))
	if err != nil {
		t.Logger.V(levelDumpHeaders).Infof("could not dump the response: %s", err)
		return resp, err
	}
	t.Logger.V(levelDumpHeaders).Infof("%s", string(redactSensitive(respDump)))
	return resp, err
}
