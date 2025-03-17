package rhel

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"reflect"

	"github.com/quay/claircore/rhel/rhcc"
	"github.com/quay/claircore/updater/driver/v1"

	"github.com/quay/zlog"
)

type mappingFile2 struct {
	Data map[string]interface{}
}

type UpdaterFactory struct{}

func (uf *UpdaterFactory) Name() string {
	// TODO(crozzy): Make important?
	return "rhel-file-updater-factory"
}

func (uf *UpdaterFactory) Create(ctx context.Context, cm driver.ConfigUnmarshaler) ([]driver.Updater, error) {
	mf := &mappingFile2{}
	return []driver.Updater{
		NewIndexerUpdater("repo-to-cpe", DefaultRepo2CPEMappingURL, mf),
		NewIndexerUpdater("container-name-to-repo", rhcc.DefaultName2ReposMappingURL, mf),
	}, nil
}

type genericFileUpdater struct {
	namespace    string
	url          string
	lastModified string
	typ          reflect.Type
	client       *http.Client
}

type IndexerUpdaterConfig struct {
	URL string
}

var _ driver.Updater = (*genericFileUpdater)(nil)

func NewIndexerUpdater(namespace string, url string, init interface{}) *genericFileUpdater {
	return &genericFileUpdater{
		url:       url,
		typ:       reflect.TypeOf(init).Elem(),
		namespace: namespace,
	}
}

func (u *genericFileUpdater) Name() string {
	return u.namespace + "-updater"
}
func (u *genericFileUpdater) Configure(ctx context.Context, cf driver.ConfigUnmarshaler, c *http.Client) error {
	var cfg IndexerUpdaterConfig
	if err := cf(&cfg); err != nil {
		return err
	}
	if cfg.URL != "" {
		u.url = cfg.URL
		zlog.Info(ctx).
			Str("component", "rhel/genericFileUpdater.Configure").
			Str("updater", u.Name()).
			Msg("configured url")
	}
	u.client = c
	return nil
}

func (u *genericFileUpdater) Fetch(ctx context.Context, zw *zip.Writer, f driver.Fingerprint, c *http.Client) (driver.Fingerprint, error) {
	ctx = zlog.ContextWithValues(ctx,
		"component", "rhel/genericFileUpdater/Updater.Fetch",
		"url", u.url)
	zlog.Debug(ctx).Msg("attempting fetch of mapping file")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.url, nil)
	if err != nil {
		return "", err
	}
	if u.lastModified != "" {
		req.Header.Set("if-modified-since", u.lastModified)
	}

	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotModified:
		zlog.Debug(ctx).
			Str("since", u.lastModified).
			Msg("response not modified; no update necessary")
		return "", nil
	default:
		return "", fmt.Errorf("received status code %d querying mapping url", resp.StatusCode)
	}

	u.lastModified = resp.Header.Get("last-modified")
	w, err := zw.Create(u.namespace)
	if err != nil {
		return "", err
	}
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		return "", err
	}
	return "", nil
}

// TODO(crozzy):
// - docs
// -
func (u *genericFileUpdater) ParseIndexerData(ctx context.Context, f fs.FS) ([]driver.IndexerData, error) {
	b, err := f.Open(u.namespace)
	if err != nil {
		// TODO: explaining error
		return nil, err
	}
	mf := &mappingFile2{}
	if err := json.NewDecoder(b).Decode(mf); err != nil {
		return nil, fmt.Errorf("failed to decode mapping file: %w", err)
	}
	ds := []driver.IndexerData{}
	for k, v := range mf.Data {
		d := driver.IndexerData{
			Namespace: u.namespace,
			Key:       k,
		}
		var err error
		d.Value, err = json.Marshal(v)
		if err != nil {
			return nil, err
		}
		ds = append(ds, d)
	}
	return ds, nil
}
