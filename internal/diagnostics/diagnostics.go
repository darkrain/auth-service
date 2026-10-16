// Package diagnostics provides explicitly enabled, loopback-only stand metrics.
package diagnostics

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/pprof"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
)

type duration struct{ count, total, max atomic.Uint64 }

func (d *duration) add(elapsed time.Duration) {
	n := uint64(elapsed)
	d.count.Add(1)
	d.total.Add(n)
	for old := d.max.Load(); n > old && !d.max.CompareAndSwap(old, n); old = d.max.Load() {
	}
}

func (d *duration) snapshot() map[string]uint64 {
	return map[string]uint64{"count": d.count.Load(), "total_ns": d.total.Load(), "max_ns": d.max.Load()}
}

type Observer struct{ handler, logWrite duration }

func Start() (*Observer, func(), error) {
	listener, err := net.Listen("tcp", "127.0.0.1:6063")
	if err != nil {
		return nil, nil, err
	}
	o := &Observer{}
	mux := http.NewServeMux()
	mux.HandleFunc("/stats", o.stats)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	for _, name := range []string{"heap", "allocs", "goroutine"} {
		mux.Handle("/debug/pprof/"+name, pprof.Handler(name))
	}
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 3 * time.Second}
	go func() { _ = server.Serve(listener) }()
	return o, func() { _ = server.Close() }, nil
}

func (o *Observer) stats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"handler": o.handler.snapshot(), "log_write": o.logWrite.snapshot()})
}

// Handler runs after Gin's request logger, excluding the logger's final write.
func (o *Observer) Handler() gin.HandlerFunc {
	return func(c *gin.Context) { start := time.Now(); c.Next(); o.handler.add(time.Since(start)) }
}

func (o *Observer) LogWriter(writer io.Writer) io.Writer { return observedWriter{writer, &o.logWrite} }

type observedWriter struct {
	writer   io.Writer
	duration *duration
}

func (w observedWriter) Write(data []byte) (int, error) {
	start := time.Now()
	n, err := w.writer.Write(data)
	w.duration.add(time.Since(start))
	return n, err
}
