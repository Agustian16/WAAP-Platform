// Package correlate is the Attack Correlation Engine (PRD 2.1 item 5, FR-6.1 to FR-6.4): it enriches audit
// transactions, maps them to kill chain stages and groups them into campaigns.
package correlate

import (
	"math"
	"net/netip"
	"os"
	"sort"

	"github.com/oschwald/maxminddb-golang"

	"github.com/Agustian16/WAAP-Platform/server/internal/model"
	"github.com/Agustian16/WAAP-Platform/server/internal/store"
)

// Stages in kill chain order (PRD 4.6.2). WEAPON is never assigned: a WAF cannot observe it.
var Stages = []string{"RECON", "WEAPON", "DELIVERY", "EXPLOIT", "INSTALL", "C2", "OBJECTIVES"}

func StageIndex(s string) int {
	for i, x := range Stages {
		if x == s {
			return i
		}
	}
	return -1
}

var Categories = []string{"SQLI", "XSS", "RCE", "LFI", "SCANNER", "PROTOCOL", "LEAKAGE"}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// MapRule resolves a rule to its mapping row: the narrowest id range wins (so an override for one custom
// rule beats a family range); rules outside every range fall back to a tag match.
func MapRule(table []model.KillchainMapping, ruleID int, tags []string) *model.KillchainMapping {
	var best *model.KillchainMapping
	for i := range table {
		m := &table[i]
		if ruleID >= m.RuleIDFrom && ruleID <= m.RuleIDTo && (best == nil || m.RuleIDTo-m.RuleIDFrom < best.RuleIDTo-best.RuleIDFrom) {
			best = m
		}
	}
	if best != nil {
		return best
	}
	for i := range table {
		if t := table[i].Tag; t != nil && contains(tags, *t) {
			return &table[i]
		}
	}
	return nil
}

// Outcome classifies a transaction that matched at least one rule (FR-6.4).
func Outcome(action string, status uint16) string {
	if action == "DENY" {
		return "BLOCKED"
	}
	if status >= 200 && status < 300 {
		return "POSSIBLY_SUCCESSFUL"
	}
	return "DETECTED"
}

// RiskScore is the Campaign Risk Score, 0-100 (FR-6.3): stage reached, distinct targets, category variety,
// success signal and volume. Same weights as riskScore in web/lib/killchain.ts.
func RiskScore(highestStage string, targets, categories int, possiblySuccessful, events int64) int {
	stage := 8.0
	if i := StageIndex(highestStage); i >= 0 {
		stage = []float64{8, 8, 25, 50, 62, 68, 75}[i]
	}
	t := float64(min(max(targets-1, 0), 4) * 3)
	v := float64(min(max(categories-1, 0), 4) * 3)
	s := 0.0
	if possiblySuccessful > 0 {
		s = 15 + float64(min(possiblySuccessful, 5))
	}
	vol := math.Min(math.Log10(math.Max(float64(events), 1))*2.5, 5)
	return int(math.Max(0, math.Min(100, math.Round(stage+t+v+s+vol))))
}

// ---------- GeoIP / ASN enrichment (FR-6.1) ----------

type Loc struct {
	CountryCode, ASName string
	ASN                 uint32
	Lon, Lat            float64
}

// Geo resolves client addresses: operator overrides first, then MaxMind databases when configured.
type Geo struct {
	overrides []override // longest prefix first
	city, asn *maxminddb.Reader
}

type override struct {
	prefix netip.Prefix
	loc    Loc
}

// NewGeo builds the resolver. cityDB and asnDB are optional paths to GeoLite2/GeoIP2 .mmdb files.
func NewGeo(ov []store.GeoOverride, cityDB, asnDB string) (*Geo, error) {
	g := &Geo{}
	for _, o := range ov {
		p, err := netip.ParsePrefix(o.CIDR)
		if err != nil {
			continue
		}
		g.overrides = append(g.overrides, override{p, Loc{o.CountryCode, o.ASName, o.ASN, o.Lon, o.Lat}})
	}
	sort.Slice(g.overrides, func(i, j int) bool { return g.overrides[i].prefix.Bits() > g.overrides[j].prefix.Bits() })
	var err error
	if cityDB != "" {
		if g.city, err = openMMDB(cityDB); err != nil {
			return nil, err
		}
	}
	if asnDB != "" {
		if g.asn, err = openMMDB(asnDB); err != nil {
			return nil, err
		}
	}
	return g, nil
}

// openMMDB reads the whole database into memory instead of memory-mapping it, so the file on disk can be
// replaced by an update while lookups continue (Windows refuses to replace a mapped file).
func openMMDB(path string) (*maxminddb.Reader, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return maxminddb.FromBytes(b)
}

// Lookup never fails: an address nothing knows about resolves to country "ZZ" at 0,0.
func (g *Geo) Lookup(ip string) Loc {
	loc := Loc{CountryCode: "ZZ"}
	addr, err := netip.ParseAddr(ip)
	if err != nil || g == nil {
		return loc
	}
	for _, o := range g.overrides {
		if o.prefix.Contains(addr) {
			return o.loc
		}
	}
	if g.city != nil {
		var rec struct {
			Country struct {
				ISOCode string `maxminddb:"iso_code"`
			} `maxminddb:"country"`
			Location struct {
				Latitude  float64 `maxminddb:"latitude"`
				Longitude float64 `maxminddb:"longitude"`
			} `maxminddb:"location"`
		}
		if g.city.Lookup(addr.AsSlice(), &rec) == nil && rec.Country.ISOCode != "" {
			loc.CountryCode, loc.Lon, loc.Lat = rec.Country.ISOCode, rec.Location.Longitude, rec.Location.Latitude
		}
	}
	if g.asn != nil {
		var rec struct {
			Number uint32 `maxminddb:"autonomous_system_number"`
			Org    string `maxminddb:"autonomous_system_organization"`
		}
		if g.asn.Lookup(addr.AsSlice(), &rec) == nil {
			loc.ASN, loc.ASName = rec.Number, rec.Org
		}
	}
	return loc
}
