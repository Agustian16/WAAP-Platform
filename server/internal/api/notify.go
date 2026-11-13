package api

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/smtp"
	"strings"
	"time"

	"github.com/Agustian16/WAAP-Platform/server/internal/model"
)

// Notifiers fans an escalation out to every configured channel (FR-6.3). Nil channels are skipped.
func Notifiers(ns ...func(model.Campaign, string)) func(model.Campaign, string) {
	var live []func(model.Campaign, string)
	for _, n := range ns {
		if n != nil {
			live = append(live, n)
		}
	}
	if len(live) == 0 {
		return nil
	}
	return func(c model.Campaign, stage string) {
		for _, n := range live {
			n(c, stage)
		}
	}
}

// EmailConfig is SMTP delivery of escalation alerts.
type EmailConfig struct {
	Addr     string   // host:port
	Security string   // starttls (default), tls (implicit, port 465) or none
	Username string   // optional; PLAIN auth, only ever over TLS unless the server is local
	Password string   //
	From     string   //
	To       []string //
	WebURL   string   // console origin, for the link to the campaign
}

// oneLine strips CR/LF so attacker-influenced text (actor keys carry User-Agents) cannot inject mail headers.
func oneLine(s string) string {
	s = strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
	if len(s) > 160 {
		s = s[:160]
	}
	return s
}

var stageNames = map[string]string{"RECON": "Reconnaissance", "DELIVERY": "Delivery", "EXPLOIT": "Exploitation", "INSTALL": "Installation",
	"C2": "Command & Control", "OBJECTIVES": "Actions on Objectives"}

func escalationMail(cfg EmailConfig, c model.Campaign, stage string, now time.Time) []byte {
	name := stageNames[stage]
	if name == "" {
		name = stage
	}
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n",
		cfg.From, strings.Join(cfg.To, ", "), oneLine(fmt.Sprintf("[Corazium] %s reached %s (risk %d)", c.ActorKey, name, c.RiskScore)), now.Format(time.RFC1123Z))
	fmt.Fprintf(&b, "A correlated attack campaign escalated to a later kill chain stage.\r\n\r\n")
	asn := oneLine(c.ASName) // operator overrides already name the AS number, MaxMind organisations do not
	if !strings.HasPrefix(asn, "AS") {
		asn = strings.TrimSpace(fmt.Sprintf("AS%d %s", c.ASN, asn))
	}
	fmt.Fprintf(&b, "Campaign:  %s\r\nActor:     %s (%s, %s)\r\nStage:     %s\r\nRisk:      %d / 100\r\nEvents:    %d (%d possibly successful)\r\n",
		c.ID, oneLine(c.ActorKey), c.CountryCode, asn, name, c.RiskScore, c.EventCount, c.PossiblySuccessful)
	for i, t := range c.Targets {
		if i == 10 {
			fmt.Fprintf(&b, "           ... and %d more\r\n", len(c.Targets)-10)
			break
		}
		label := "Targets:"
		if i > 0 {
			label = ""
		}
		fmt.Fprintf(&b, "%-10s %s\r\n", label, oneLine(t))
	}
	if cfg.WebURL != "" {
		fmt.Fprintf(&b, "\r\nOpen it: %s/attacks?campaign=%s\r\n", strings.TrimRight(cfg.WebURL, "/"), c.ID)
	}
	return []byte(b.String())
}

// send delivers one message. STARTTLS is required when Security is starttls, so credentials and alert contents
// never cross the network in clear text by accident.
func (cfg EmailConfig) send(msg []byte) error {
	host, _, err := net.SplitHostPort(cfg.Addr)
	if err != nil {
		return fmt.Errorf("SMTP address: %w", err)
	}
	tc := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	var conn net.Conn
	if cfg.Security == "tls" {
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", cfg.Addr, tc)
	} else {
		conn, err = net.DialTimeout("tcp", cfg.Addr, 10*time.Second)
	}
	if err != nil {
		return err
	}
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()
	if cfg.Security == "" || cfg.Security == "starttls" {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return fmt.Errorf("%s does not offer STARTTLS (set SMTP_SECURITY=none only for a local relay)", cfg.Addr)
		}
		if err := c.StartTLS(tc); err != nil {
			return err
		}
	}
	if cfg.Username != "" {
		// smtp.PlainAuth itself refuses to send credentials without TLS unless the host is localhost.
		if err := c.Auth(smtp.PlainAuth("", cfg.Username, cfg.Password, host)); err != nil {
			return err
		}
	}
	if err := c.Mail(cfg.From); err != nil {
		return err
	}
	for _, to := range cfg.To {
		if err := c.Rcpt(to); err != nil {
			return fmt.Errorf("recipient %s: %w", to, err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

// EmailNotifier returns the email channel, or nil when SMTP is not configured.
func EmailNotifier(cfg EmailConfig) func(model.Campaign, string) {
	if cfg.Addr == "" || cfg.From == "" || len(cfg.To) == 0 {
		return nil
	}
	return func(c model.Campaign, stage string) {
		msg := escalationMail(cfg, c, stage, time.Now())
		go func() {
			if err := cfg.send(msg); err != nil {
				slog.Warn("escalation email failed", "campaign", c.ID, "err", err)
			}
		}()
	}
}
