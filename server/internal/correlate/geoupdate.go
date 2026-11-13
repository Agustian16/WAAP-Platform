package correlate

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// GeoUpdater keeps MaxMind GeoLite2 City and ASN databases current (FR-6.1). MaxMind publishes new builds
// twice a week; files younger than MaxAge are reused.
type GeoUpdater struct {
	Dir        string
	AccountID  string // optional: with it, the documented basic-auth download is used
	LicenseKey string
	MaxAge     time.Duration
	Client     *http.Client
	// Base is the download host, overridable in tests.
	Base string
}

func (u *GeoUpdater) path(edition string) string { return filepath.Join(u.Dir, edition+".mmdb") }

// Ensure downloads any database that is missing or older than MaxAge. It returns the City and ASN paths.
// A failed download keeps the previous file when there is one.
func (u *GeoUpdater) Ensure(ctx context.Context) (city, asn string, changed bool, err error) {
	if err = os.MkdirAll(u.Dir, 0o700); err != nil {
		return
	}
	var errs []error
	for _, ed := range []string{"GeoLite2-City", "GeoLite2-ASN"} {
		p := u.path(ed)
		if st, e := os.Stat(p); e == nil && time.Since(st.ModTime()) < u.MaxAge {
			continue
		}
		if e := u.download(ctx, ed, p); e != nil {
			errs = append(errs, fmt.Errorf("%s: %w", ed, e))
			continue
		}
		changed = true
	}
	city, asn = u.path("GeoLite2-City"), u.path("GeoLite2-ASN")
	for _, p := range []string{city, asn} {
		if _, e := os.Stat(p); e != nil {
			return "", "", false, errors.Join(errs...)
		}
	}
	return city, asn, changed, errors.Join(errs...)
}

func (u *GeoUpdater) download(ctx context.Context, edition, dest string) error {
	base := u.Base
	if base == "" {
		base = "https://download.maxmind.com"
	}
	var req *http.Request
	var err error
	if u.AccountID != "" {
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, base+"/geoip/databases/"+edition+"/download?suffix=tar.gz", nil)
		if err == nil {
			req.SetBasicAuth(u.AccountID, u.LicenseKey)
		}
	} else {
		// MaxMind's direct-download permalink authenticates with the key as a parameter. It goes only to MaxMind,
		// over HTTPS, and is never logged here.
		q := url.Values{"edition_id": {edition}, "license_key": {u.LicenseKey}, "suffix": {"tar.gz"}}
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, base+"/app/geoip_download?"+q.Encode(), nil)
	}
	if err != nil {
		return err
	}
	client := u.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Minute}
	}
	res, err := client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // the URL carries the key; do not let it reach the log
		}
		return fmt.Errorf("download failed: %v", err)
	}
	defer res.Body.Close()
	switch {
	case res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden:
		return fmt.Errorf("MaxMind rejected the license key (HTTP %d)", res.StatusCode)
	case res.StatusCode != http.StatusOK:
		return fmt.Errorf("HTTP %d from MaxMind", res.StatusCode)
	}
	gz, err := gzip.NewReader(io.LimitReader(res.Body, 512<<20))
	if err != nil {
		return fmt.Errorf("not a gzip archive: %w", err)
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return errors.New("archive has no .mmdb file")
		}
		if err != nil {
			return err
		}
		if h.Typeflag != tar.TypeReg || !strings.HasSuffix(h.Name, ".mmdb") {
			continue
		}
		tmp := dest + ".tmp"
		f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		_, err = io.Copy(f, io.LimitReader(tr, 512<<20))
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err == nil {
			if _, err = NewGeo(nil, tmp, ""); err == nil { // prove it opens before replacing the good copy
				err = os.Rename(tmp, dest)
			}
		}
		if err != nil {
			os.Remove(tmp)
		}
		return err
	}
}
