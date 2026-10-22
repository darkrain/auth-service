package middleware

import (
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// AccessLogger can keep only non-routine requests in the application log.
// External requests remain in the reverse proxy's full access log. The default
// is the original Gin logger; the filter never changes handler execution.
func AccessLogger(writer io.Writer, filtered bool) gin.HandlerFunc {
	if !filtered {
		return gin.LoggerWithWriter(writer)
	}
	return gin.LoggerWithConfig(gin.LoggerConfig{Output: writer, Formatter: func(p gin.LogFormatterParams) string {
		if (p.Method == http.MethodGet || p.Method == http.MethodHead) &&
			p.StatusCode >= 200 && p.StatusCode < 300 && p.Latency < time.Second && p.ErrorMessage == "" {
			return ""
		}
		return fmt.Sprintf("[GIN] %v | %3d | %13v | %15s | %-7s %#v\n%s",
			p.TimeStamp.Format("2006/01/02 - 15:04:05"), p.StatusCode, p.Latency, p.ClientIP, p.Method, p.Path, p.ErrorMessage)
	}})
}
