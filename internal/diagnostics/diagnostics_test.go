package diagnostics

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

type brokenWriter struct{ err error }

func (w brokenWriter) Write(p []byte) (int, error) { return 1, w.err }

func TestObserverPreservesResponseAndLogs(t *testing.T) {
	o := &Observer{}
	var log bytes.Buffer
	r := gin.New()
	r.Use(gin.LoggerWithWriter(o.LogWriter(&log)), o.Handler())
	r.GET("/me", func(c *gin.Context) { c.JSON(http.StatusAccepted, gin.H{"id": 42}) })
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/me", nil))
	if w.Code != http.StatusAccepted || w.Body.String() != `{"id":42}` {
		t.Fatal(w.Code, w.Body.String())
	}
	if !bytes.Contains(log.Bytes(), []byte("/me")) {
		t.Fatal("request log lost")
	}
	if o.handler.count.Load() != 1 || o.logWrite.count.Load() != 1 {
		t.Fatal("missing timing")
	}
	stats := httptest.NewRecorder()
	o.stats(stats, httptest.NewRequest("GET", "/stats", nil))
	var values map[string]map[string]uint64
	if err := json.Unmarshal(stats.Body.Bytes(), &values); err != nil {
		t.Fatal(err)
	}
	if len(values) != 2 || len(values["handler"]) != 3 || len(values["log_write"]) != 3 {
		t.Fatal("unexpected metrics", values)
	}
}

func TestLogWriterPreservesPartialWriteError(t *testing.T) {
	want := errors.New("write failed")
	o := &Observer{}
	n, err := o.LogWriter(brokenWriter{want}).Write([]byte("log"))
	if n != 1 || err != want || o.logWrite.count.Load() != 1 {
		t.Fatal(n, err)
	}
}
