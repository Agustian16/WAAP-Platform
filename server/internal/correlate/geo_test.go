package correlate

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Agustian16/WAAP-Platform/server/internal/store"
)

// Runs when the GeoLite2 databases have been downloaded (control plane with MAXMIND_LICENSE_KEY, into data/geoip).
func TestGeoLite2Lookup(t *testing.T) {
	dir := filepath.Join("..", "..", "data", "geoip")
	city, asn := filepath.Join(dir, "GeoLite2-City.mmdb"), filepath.Join(dir, "GeoLite2-ASN.mmdb")
	if _, err := os.Stat(city); err != nil {
		t.Skip("GeoLite2 not downloaded")
	}
	g, err := NewGeo([]store.GeoOverride{{CIDR: "8.8.8.0/24", CountryCode: "ZZ", ASName: "override", Lon: 1, Lat: 2}}, city, asn)
	if err != nil {
		t.Fatal(err)
	}
	if l := g.Lookup("1.1.1.1"); l.ASN != 13335 || l.ASName == "" {
		t.Fatalf("1.1.1.1: %+v", l)
	}
	if l := g.Lookup("81.2.69.142"); l.CountryCode != "GB" || l.Lat == 0 {
		t.Fatalf("81.2.69.142: %+v", l)
	}
	if l := g.Lookup("8.8.8.8"); l.CountryCode != "ZZ" || l.ASName != "override" {
		t.Fatalf("operator override must win over MaxMind: %+v", l)
	}
	if l := g.Lookup("10.1.2.3"); l.CountryCode != "ZZ" {
		t.Fatalf("private address: %+v", l)
	}
}
