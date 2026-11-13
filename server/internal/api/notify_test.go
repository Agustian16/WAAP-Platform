package api

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Agustian16/WAAP-Platform/server/internal/model"
)

// fakeSMTP accepts one message and returns its DATA section and envelope.
func fakeSMTP(t *testing.T, starttls bool) (addr string, got chan []string) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	got = make(chan []string, 1)
	go func() {
		defer l.Close()
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r, w := bufio.NewReader(c), bufio.NewWriter(c)
		say := func(s string) { w.WriteString(s + "\r\n"); w.Flush() }
		say("220 fake ESMTP")
		var lines []string
		inData := false
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				got <- lines
				return
			}
			line = strings.TrimRight(line, "\r\n")
			if inData {
				if line == "." {
					inData = false
					say("250 queued")
					continue
				}
				lines = append(lines, line)
				continue
			}
			switch cmd := strings.ToUpper(strings.SplitN(line, " ", 2)[0]); cmd {
			case "EHLO", "HELO":
				if starttls {
					say("250-fake\r\n250 STARTTLS")
				} else {
					say("250 fake")
				}
			case "MAIL", "RCPT":
				lines = append(lines, line)
				say("250 ok")
			case "DATA":
				inData = true
				say("354 go")
			case "QUIT":
				say("221 bye")
				got <- lines
				return
			default:
				say("502 no")
			}
		}
	}()
	return l.Addr().String(), got
}

func TestEmailNotifier(t *testing.T) {
	c := model.Campaign{ID: "cmp_1", ActorKey: "ua:abcd Evil\r\nBcc: victim@example.com", CountryCode: "CN", ASN: 64516, ASName: "Sample",
		RiskScore: 71, EventCount: 20, Targets: []string{"api.domain.com/api/v1/login"}}

	addr, got := fakeSMTP(t, false)
	notify := EmailNotifier(EmailConfig{Addr: addr, Security: "none", From: "waf@corazium.test", To: []string{"soc@corazium.test"}, WebURL: "https://console.test"})
	notify(c, "EXPLOIT")
	var lines []string
	select {
	case lines = <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("no mail delivered")
	}
	all := strings.Join(lines, "\n")
	for _, want := range []string{"MAIL FROM:<waf@corazium.test>", "RCPT TO:<soc@corazium.test>", "reached Exploitation (risk 71)", "https://console.test/attacks?campaign=cmp_1"} {
		if !strings.Contains(all, want) {
			t.Fatalf("mail lacks %q:\n%s", want, all)
		}
	}
	for _, l := range lines {
		if strings.HasPrefix(strings.ToLower(l), "bcc:") {
			t.Fatalf("header injection through the actor key:\n%s", all)
		}
	}

	// starttls (the default) refuses a server that cannot encrypt: no silent clear-text fallback.
	addr2, _ := fakeSMTP(t, false)
	if err := (EmailConfig{Addr: addr2, From: "a@b.test", To: []string{"c@d.test"}}).send([]byte("x")); err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("expected a STARTTLS refusal, got %v", err)
	}
	if EmailNotifier(EmailConfig{}) != nil {
		t.Fatal("unconfigured email must be off")
	}
}
