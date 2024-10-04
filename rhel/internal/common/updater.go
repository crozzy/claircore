package common

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	oc "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/quay/zlog"
	"golang.org/x/time/rate"
	oras "oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/file"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote"
)

// Interval is how often we attempt to update the mapping file.
var interval = rate.Every(24 * time.Hour)

// Updater returns a value that's periodically updated.
type Updater struct {
	url          string
	typ          reflect.Type
	value        atomic.Value
	reqRate      *rate.Limiter
	mu           sync.RWMutex // protects lastModified
	lastModified string
}

// NewUpdater returns an Updater holding a value of the type passed as "init",
// periodically updated from the endpoint "url."
//
// To omit an initial value, use a typed nil pointer.
func NewUpdater(url string, init interface{}) *Updater {
	u := Updater{
		url:     url,
		typ:     reflect.TypeOf(init).Elem(),
		reqRate: rate.NewLimiter(interval, 1),
	}
	u.value.Store(init)
	// If we were provided an initial value, pull the first token.
	if !reflect.ValueOf(init).IsNil() {
		u.reqRate.Allow()
	}
	return &u
}

// Get returns a pointer to the current copy of the value. The Get call may be
// hijacked to update the value from the configured endpoint.
func (u *Updater) Get(ctx context.Context, c *http.Client) (interface{}, error) {
	ctx = zlog.ContextWithValues(ctx,
		"component", "rhel/internal/common/Updater.Get")
	var err error
	if u.url != "" && u.reqRate.Allow() {
		zlog.Debug(ctx).Msg("got unlucky, updating mapping file")
		err = u.Fetch(ctx, c)
		if err != nil {
			zlog.Error(ctx).
				Err(err).
				Msg("error updating mapping file")
		}
	}

	return u.value.Load(), err
}

// Fetch attempts to perform an atomic update of the mapping file.
//
// Fetch is safe to call concurrently.
func (u *Updater) Fetch(ctx context.Context, c *http.Client) error {
	ctx = zlog.ContextWithValues(ctx,
		"component", "rhel/internal/common/Updater.Fetch",
		"url", u.url)
	zlog.Debug(ctx).Msg("attempting fetch of mapping file")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.url, nil)
	if err != nil {
		return err
	}
	u.mu.RLock()
	if u.lastModified != "" {
		req.Header.Set("if-modified-since", u.lastModified)
	}
	u.mu.RUnlock()

	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotModified:
		zlog.Debug(ctx).
			Str("since", u.lastModified).
			Msg("response not modified; no update necessary")
		return nil
	default:
		return fmt.Errorf("received status code %d querying mapping url", resp.StatusCode)
	}

	v := reflect.New(u.typ).Interface()
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		return fmt.Errorf("failed to decode mapping file: %w", err)
	}

	u.mu.Lock()
	u.lastModified = resp.Header.Get("last-modified")
	u.mu.Unlock()
	// atomic store of mapping file
	u.value.Store(v)
	zlog.Debug(ctx).Msg("atomic update of local mapping file complete")
	return nil
}

func FetchArtifact(ctx context.Context, imageName string) (string, error) {
	ctx = zlog.ContextWithValues(ctx,
		"component", "rhel/internal/common/Updater.Fetch",
		"image", imageName)

	ref, err := registry.ParseReference(imageName)
	if err != nil {
		return "", err
	}
	reg, err := remote.NewRegistry(ref.Registry)
	if err != nil {
		return "", err
	}

	src, err := reg.Repository(ctx, ref.Repository)
	if err != nil {
		return "", err
	}
	td := os.TempDir()
	dst, err := file.New(td)
	if err != nil {
		return "", err
	}
	desc, err := oras.Copy(ctx, src, ref.Reference, dst, ref.Reference, oras.DefaultCopyOptions)
	if err != nil {
		return "", err
	}
	r, err := dst.Fetch(ctx, desc)
	if err != nil {
		return "", err
	}
	b, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}
	var man oc.Manifest
	json.Unmarshal(b, &man)
	if len(man.Layers) != 1 {
		return "", fmt.Errorf("irregular number of layers, expected 1 got %d", len(man.Layers))
	}
	l := man.Layers[0]
	fn := l.Annotations["org.opencontainers.image.title"]
	return filepath.Join(td, fn), nil
}
