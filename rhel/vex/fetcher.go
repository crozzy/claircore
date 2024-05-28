package vex

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/klauspost/compress/snappy"
	"github.com/klauspost/compress/zstd"
	"github.com/quay/zlog"

	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/pkg/tmp"
)

var (
	compressedFileTimeout = 2 * time.Minute
	deletedTemplate       = `{"document":{"tracking":{"id":"%s","status":"deleted"}}}`
	cvePathRegex          = regexp.MustCompile(`^\d{4}\/(cve-\d{4}-\d*).json$`)
)

func (u *VEXUpdater) Fetch(ctx context.Context, hint driver.Fingerprint) (io.ReadCloser, driver.Fingerprint, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "rhel/VEXUpdater.Fetch")
	fp, err := ParseFingerprint(hint)
	if err != nil {
		return nil, hint, err
	}

	f, err := tmp.NewFile("", "rhel-vex.")
	if err != nil {
		return nil, hint, err
	}

	cw := snappy.NewBufferedWriter(f)

	var success bool
	defer func() {
		if err := cw.Close(); err != nil {
			zlog.Warn(ctx).Err(err).Msg("unable to close snappy writer")
		}
		if success {
			if _, err := f.Seek(0, io.SeekStart); err != nil {
				zlog.Warn(ctx).
					Err(err).
					Msg("unable to seek file back to start")
			}
		} else {
			if err := f.Close(); err != nil {
				zlog.Warn(ctx).Err(err).Msg("unable to close spool")
			}
		}
	}()

	if fp.changesEtag == "" { // Used to inform whether this is the first run.
		// We need to go after the full corpus of vulnerabilities
		// First we target the archive_latest.txt file
		latestURI, err := u.url.Parse(latestFile)
		if err != nil {
			return nil, hint, err
		}
		latestReq, err := http.NewRequestWithContext(ctx, http.MethodGet, latestURI.String(), nil)
		if err != nil {
			return nil, hint, err
		}
		latestRes, err := u.client.Do(latestReq)
		if err != nil {
			return nil, hint, err
		}
		defer latestRes.Body.Close()

		if latestRes.StatusCode != http.StatusOK {
			return nil, hint, fmt.Errorf("unexpected response from archive_latest.txt: %s", latestRes.Status)
		}

		body, err := io.ReadAll(latestRes.Body) // Fine to use as expecting small number of bytes.
		if err != nil {
			return nil, hint, err
		}

		compressedFilename := string(body)
		zlog.Debug(ctx).
			Str("filename", compressedFilename).
			Msg("requesting latest compressed file")

		uri, err := u.url.Parse(compressedFilename)
		if err != nil {
			return nil, hint, err
		}

		rctx, cancel := context.WithTimeout(ctx, compressedFileTimeout)
		defer cancel()

		req, err := http.NewRequestWithContext(rctx, http.MethodGet, uri.String(), nil)
		if err != nil {
			return nil, hint, err
		}

		res, err := u.client.Do(req)
		if res != nil {
			defer res.Body.Close()
		}
		if err != nil {
			return nil, hint, err
		}
		if res.StatusCode != http.StatusOK {
			return nil, hint, fmt.Errorf("unexpected response from latest compressed file: %s", res.Status)
		}

		lm := res.Header.Get("last-modified")
		fp.requestTime, err = time.Parse(http.TimeFormat, lm)
		if err != nil {
			return nil, hint, fmt.Errorf("could not parse last-modified header %s: %w", lm, err)
		}
		z, err := zstd.NewReader(res.Body)
		if err != nil {
			return nil, hint, err
		}
		defer z.Close()
		r := tar.NewReader(z)

		var (
			h              *tar.Header
			buf, bc        bytes.Buffer
			entriesWritten int
		)
		for h, err = r.Next(); errors.Is(err, nil); h, err = r.Next() {
			if h.Typeflag != tar.TypeReg {
				continue
			}
			year, err := strconv.ParseInt(path.Dir(h.Name), 10, 64)
			if err != nil {
				return nil, hint, fmt.Errorf("error parsing year %w", err)
			}
			if year < lookBackToYear {
				continue
			}
			buf.Grow(int(h.Size))
			if _, err := buf.ReadFrom(r); err != nil {
				return nil, hint, err
			}

			err = json.Compact(&bc, buf.Bytes())
			if err != nil {
				return nil, hint, fmt.Errorf("error compressing JSON %s: %w", h.Name, err)
			}
			bc.WriteByte('\n')
			cw.Write(bc.Bytes())
			buf.Reset()
			bc.Reset()
			entriesWritten++
		}
		if !errors.Is(err, io.EOF) {
			return nil, hint, fmt.Errorf("error reading tar contents: %w", err)
		}

		zlog.Debug(ctx).
			Str("updater", u.Name()).
			Int("entries written", entriesWritten).
			Msg("finished writing compressed data to spool")
	}

	err = u.processChanges(ctx, cw, fp)
	if err != nil {
		return nil, hint, err
	}

	err = u.processDeletions(ctx, cw, fp)
	if err != nil {
		return nil, hint, err
	}

	fp.requestTime = time.Now()
	success = true
	return f, driver.Fingerprint(fp.String()), nil
}

// processChanges deals with the published changes.csv, adding records
// to the wtr is they are deemed to have changed since the compressed
// file was last processed. wtr and fp can be modified.
func (u *VEXUpdater) processChanges(ctx context.Context, wtr io.Writer, fp *fingerprint) error {
	uri, err := u.url.Parse(changesFile)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri.String(), nil)
	if err != nil {
		return err
	}
	if fp.changesEtag != "" {
		req.Header.Add("If-None-Match", fp.changesEtag)
	}
	res, err := u.client.Do(req)
	if res != nil {
		defer res.Body.Close()
	}
	if err != nil {
		return err
	}

	switch res.StatusCode {
	case http.StatusOK:
		if t := fp.changesEtag; t == "" || t != res.Header.Get("etag") {
			break
		}
		fallthrough
	case http.StatusNotModified:
		return nil
	default:
		return fmt.Errorf("unexpected response from changes.csv: %s", res.Status)
	}
	fp.changesEtag = res.Header.Get("etag")

	rd := csv.NewReader(res.Body)
	rd.FieldsPerRecord = 2
	rd.ReuseRecord = true
	var (
		l       int
		buf, bc bytes.Buffer
	)
	rec, err := rd.Read()
	for ; err == nil; rec, err = rd.Read() {
		if len(rec) != 2 {
			return fmt.Errorf("could not parse changes.csv file")
		}

		cvePath, uTime := rec[0], rec[1]
		year, err := strconv.ParseInt(path.Dir(cvePath), 10, 64)
		if err != nil {
			return fmt.Errorf("error parsing year %w", err)
		}
		if year < lookBackToYear {
			continue
		}
		updatedTime, err := time.Parse(time.RFC3339, uTime)
		if err != nil {
			return fmt.Errorf("line %d: %w", l, err)
		}
		if updatedTime.After(fp.requestTime) {
			advisoryURI, err := u.url.Parse(cvePath)
			if err != nil {
				return err
			}
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, advisoryURI.String(), nil)
			if err != nil {
				return fmt.Errorf("error creating advisory request %w", err)
			}

			// Use a func here as we're in a loop and want to make sure the
			// body is closed in all events.
			err = func() error {
				res, err := u.client.Do(req)
				if err != nil {
					return fmt.Errorf("error making advisory request %w", err)
				}
				defer res.Body.Close()
				switch res.StatusCode {
				case http.StatusOK:
					// Add compacted JSON to buffer.
					_, err = buf.ReadFrom(res.Body)
					if err != nil {
						return fmt.Errorf("error reading from buffer: %w", err)
					}
					zlog.Debug(ctx).Str("url", advisoryURI.String()).Msg("copying body to file")
					err = json.Compact(&bc, buf.Bytes())
					if err != nil {
						return fmt.Errorf("error compressing JSON: %w", err)
					}
				default:
					// Something went wrong, try and read some body and return an error.
					var b strings.Builder
					if _, err := io.Copy(&b, res.Body); err != nil {
						zlog.Warn(ctx).Err(err).Msg("additional error while reading error response")
					} else {
						zlog.Warn(ctx).Str("response", b.String()).Msg("received error response")
					}
					return fmt.Errorf("unexpected response from advisary URL: %s %s", res.Status, req.URL)
				}

				bc.WriteByte('\n')
				wtr.Write(bc.Bytes())
				buf.Reset()
				bc.Reset()
				l++
				return nil
			}()
			if !errors.Is(err, nil) {
				return err
			}
		}
	}
	switch err {
	case io.EOF:
	default:
		return fmt.Errorf("error parsing the changes.csv file: %w", err)
	}
	return nil
}

// processDeletions deals with the published deletions.csv, adding records
// to the wtr is they are deemed to have changed since the compressed
// file was last processed. wtr and fp can be modified.
func (u *VEXUpdater) processDeletions(ctx context.Context, wtr io.Writer, fp *fingerprint) error {
	deletionURI, err := u.url.Parse(deletionsFile)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, deletionURI.String(), nil)
	if err != nil {
		return err
	}
	if fp.deletionsEtag != "" {
		req.Header.Add("If-None-Match", fp.deletionsEtag)
	}
	res, err := u.client.Do(req)
	if res != nil {
		defer res.Body.Close()
	}
	if err != nil {
		return err
	}

	switch res.StatusCode {
	case http.StatusOK:
		if t := fp.deletionsEtag; t == "" || t != res.Header.Get("etag") {
			break
		}
		fallthrough
	case http.StatusNotModified, http.StatusNotFound: // TODO: Remove StatusNotFound once deletions.csv is implemented.
		return nil
	default:
		return fmt.Errorf("unexpected response from deletions.csv: %s", res.Status)
	}
	fp.deletionsEtag = res.Header.Get("etag")

	rd := csv.NewReader(res.Body)
	rd.FieldsPerRecord = 2
	rd.ReuseRecord = true
	var buf, bc bytes.Buffer
	rec, err := rd.Read()
	for ; err == nil; rec, err = rd.Read() {
		if len(rec) != 2 {
			return fmt.Errorf("could not parse deletions.csv file")
		}

		cvePath, uTime := rec[0], rec[1]
		updatedTime, err := time.Parse(time.RFC3339, uTime)
		if err != nil {
			return err
		}
		if updatedTime.After(fp.requestTime) {
			deletedJSON, err := createDeletedJSON(cvePath)
			if err != nil {
				zlog.Warn(ctx).Err(err).Msg("error creating JSON object denoting deletion")
			}
			bc.Write(deletedJSON)
			bc.WriteByte('\n')
			wtr.Write(bc.Bytes())
			buf.Reset()
			bc.Reset()
		}
	}
	switch err {
	case io.EOF:
	default:
		return fmt.Errorf("error parsing the deletions.csv file: %w", err)
	}
	return nil
}

func createDeletedJSON(cvePath string) ([]byte, error) {
	ms := cvePathRegex.FindStringSubmatch(cvePath)
	if len(ms) != 2 {
		return nil, errors.New("failed to parse CVE path")
	}
	j := fmt.Sprintf(deletedTemplate, strings.ToUpper(ms[1]))
	return []byte(j), nil
}
