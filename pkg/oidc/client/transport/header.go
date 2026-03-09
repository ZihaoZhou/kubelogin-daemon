package transport

import "net/http"

// WithHeader is a RoundTripper that adds custom headers to each request.
//
// Token retrievel fails when an auth code has been retrieved using Azure AD
// Single Page Application due to the missing "Origin" header for CORS
// validation.
// https://github.com/ZihaoZhou/kubelogin-daemon/issues/1048
type WithHeader struct {
	Base           http.RoundTripper
	RequestHeaders map[string]string
}

func (t *WithHeader) RoundTrip(req *http.Request) (*http.Response, error) {
	// SEC-MED-3: Clone the request before modifying headers.
	// RoundTrip must not modify the original request (http.RoundTripper contract).
	r := req.Clone(req.Context())
	for key, value := range t.RequestHeaders {
		r.Header.Set(key, value)
	}
	return t.Base.RoundTrip(r)
}
