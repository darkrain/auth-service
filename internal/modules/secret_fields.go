package modules

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/gin-gonic/gin"
)

// Generated account routes answer an update with the row they wrote. For the
// password and two-factor modules that row is the bcrypt hash and the
// encrypted TOTP secret: a session token was enough to read them, and the
// hash can be cracked offline. These columns never leave the service.
var secretResponseFields = map[string]struct{}{
	"password":                    {},
	"two_factor_secret":           {},
	"two_factor_secret_encrypted": {},
	"code_hash":                   {},
	"token":                       {},
}

// secretFilteredPaths are the generator routes that read or write users,
// sessions and contact verification rows on behalf of the account owner.
var secretFilteredPaths = []string{"/auth/account_", "/auth/contact_verifications"}

// StripSecretFields removes secretResponseFields from every JSON response of
// the generated account routes, whatever action or fallback produced it.
func StripSecretFields() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !secretFilteredPath(c.Request.URL.Path) {
			c.Next()
			return
		}
		original := c.Writer
		writer := &bufferedWriter{ResponseWriter: original}
		c.Writer = writer
		c.Next()
		c.Writer = original
		body := writer.body.Bytes()
		if len(body) > 0 && strings.Contains(original.Header().Get("Content-Type"), "json") {
			body = stripSecretJSON(body)
		}
		if len(body) > 0 {
			original.Header().Del("Content-Length")
			_, _ = original.Write(body)
		} else {
			original.WriteHeaderNow()
		}
	}
}

func secretFilteredPath(path string) bool {
	for _, prefix := range secretFilteredPaths {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func stripSecretJSON(body []byte) []byte {
	var value interface{}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return body
	}
	if !stripSecretValue(value) {
		return body
	}
	cleaned, err := json.Marshal(value)
	if err != nil {
		return body
	}
	return cleaned
}

// stripSecretValue deletes secret keys at any depth and reports a change.
func stripSecretValue(value interface{}) bool {
	changed := false
	switch typed := value.(type) {
	case map[string]interface{}:
		for key, nested := range typed {
			if _, secret := secretResponseFields[strings.ToLower(key)]; secret {
				delete(typed, key)
				changed = true
				continue
			}
			if stripSecretValue(nested) {
				changed = true
			}
		}
	case []interface{}:
		for _, nested := range typed {
			if stripSecretValue(nested) {
				changed = true
			}
		}
	}
	return changed
}

// bufferedWriter keeps the body until the handler chain finishes. Written
// reports a buffered body as written, so the generator does not append a
// second answer after a hook has already answered.
type bufferedWriter struct {
	gin.ResponseWriter
	body bytes.Buffer
}

func (w *bufferedWriter) Write(data []byte) (int, error) { return w.body.Write(data) }

func (w *bufferedWriter) WriteString(data string) (int, error) { return w.body.WriteString(data) }

func (w *bufferedWriter) Written() bool { return w.body.Len() > 0 || w.ResponseWriter.Written() }

func (w *bufferedWriter) Size() int {
	if w.body.Len() > 0 {
		return w.body.Len()
	}
	return w.ResponseWriter.Size()
}

func (w *bufferedWriter) WriteHeaderNow() {}
