package main

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

type failingTransport struct{}

func (failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("system DNS unavailable")
}

func TestLookupWithDirectDNSFallback(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("8.8.8.8")) }))
	defer server.Close()
	dns, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer dns.Close()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := dns.ReadFrom(buf)
			if err != nil {
				return
			}
			var req dnsmessage.Message
			if req.Unpack(buf[:n]) != nil || len(req.Questions) == 0 {
				continue
			}
			q := req.Questions[0]
			resp := dnsmessage.Message{Header: dnsmessage.Header{ID: req.Header.ID, Response: true, RecursionAvailable: true}, Questions: req.Questions}
			if q.Type == dnsmessage.TypeA {
				resp.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 30}, Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}}}}
			}
			if b, err := resp.Pack(); err == nil {
				_, _ = dns.WriteTo(b, addr)
			}
		}
	}()
	fallback := fallbackHTTPClient(dns.LocalAddr().String())
	transport := fallback.Transport.(*http.Transport)
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	transport.TLSClientConfig = server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	transport.TLSClientConfig.RootCAs = pool
	transport.TLSClientConfig.InsecureSkipVerify = false
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	ip, err := lookupPublicIPv4(&http.Client{Transport: failingTransport{}}, fallback, "https://example.com:"+port)
	if err != nil || ip != "8.8.8.8" {
		t.Fatalf("fallback got %q, error %v", ip, err)
	}
}

func TestFetchPublicIPv4(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
		want       string
	}{
		{"valid", "8.8.8.8\n", http.StatusOK, "8.8.8.8"},
		{"private", "192.168.1.1", http.StatusOK, ""},
		{"ipv6", "2001:4860:4860::8888", http.StatusOK, ""},
		{"malformed", "not an ip", http.StatusOK, ""},
		{"server error", "8.8.8.8", http.StatusServiceUnavailable, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			got, err := fetchPublicIPv4(server.Client(), server.URL)
			if got != tc.want || (err == nil) != (tc.want != "") {
				t.Fatalf("got %q, error %v", got, err)
			}
		})
	}
}

func TestRuleEditing(t *testing.T) {
	a := &app{selected: -1}
	a.openEditor(-1)
	a.saveRule()
	if !a.editing || a.errorText == "" || len(a.rules) != 0 {
		t.Fatal("empty rule should remain in editor")
	}
	a.draft.domain = " *.example.com "
	a.draft.resolver = " 10.0.0.53 "
	a.saveRule()
	if a.editing || len(a.rules) != 1 || a.rules[0].domain != "example.com" || a.selected != 0 {
		t.Fatal("rule was not saved")
	}
	a.openEditor(0)
	a.draft.resolver = "10.0.0.54"
	a.saveRule()
	if len(a.rules) != 1 || a.rules[0].resolver != "10.0.0.54" {
		t.Fatal("rule was not updated")
	}
}

func TestMakePolicies(t *testing.T) {
	rules := []rule{{domain: "*.Example.COM", resolver: "10.0.0.53", protocol: "UDP", active: true}, {domain: "host.example.com", resolver: "2001:db8::53", protocol: "UDP", active: true}, {domain: "bad", active: false}}
	got, err := makePolicies(rules)
	if err != nil || len(got) != 2 || len(got[0].Namespace) != 1 || got[0].Namespace[0] != ".example.com" || len(got[1].Namespace) != 1 || got[1].Namespace[0] != ".host.example.com" {
		t.Fatalf("policies: %#v, %v", got, err)
	}
	for _, bad := range []rule{{domain: "*.example.com", resolver: "1.1.1.1:53", protocol: "UDP", active: true}, {domain: "bad_domain", resolver: "1.1.1.1", protocol: "UDP", active: true}, {domain: "example.com", resolver: "1.1.1.1", protocol: "DoH", active: true}, {domain: "example.com", resolver: "1.1.1.1", protocol: "UDP", publicIP: "2001:db8::/32", active: true}} {
		if _, err := makePolicies([]rule{bad}); err == nil {
			t.Fatalf("accepted invalid rule: %#v", bad)
		}
	}
	if _, err := makePolicies([]rule{rules[0], rules[0]}); err == nil {
		t.Fatal("accepted duplicate namespace")
	}
	rules[1].domain = "example.com"
	if _, err := makePolicies(rules); err == nil {
		t.Fatal("accepted equivalent wildcard and bare suffix")
	}
}

func TestMultipleDomains(t *testing.T) {
	r := rule{domain: "*.Example.com, foo.test bar.test", resolver: "10.0.0.53", protocol: "UDP", active: true}
	p, err := makePolicies([]rule{r})
	if err != nil || len(p) != 1 || !slices.Equal(p[0].Namespace, []string{".example.com", ".foo.test", ".bar.test"}) {
		t.Fatalf("policies = %#v, %v", p, err)
	}
	r.domain = "example.com, *.EXAMPLE.com"
	if _, err := makePolicies([]rule{r}); err == nil {
		t.Fatal("accepted duplicate domain")
	}
	r.domain = "example.com, foo.test"
	r.publicIP = "142.110.0.0/16"
	other := rule{domain: "foo.test bar.test", resolver: "10.0.0.54", protocol: "UDP", active: true, publicIP: "142.110.10.0/24"}
	if _, err := makePolicies([]rule{r, other}); err == nil {
		t.Fatal("accepted overlapping domain and public IP conditions")
	}
	other.publicIP = "68.147.10.102"
	if _, err := makePolicies([]rule{r, other}); err != nil {
		t.Fatalf("rejected disjoint conditions: %v", err)
	}
	var legacy policyRule
	if err := json.Unmarshal([]byte(`{"namespace":".example.com","resolver":"10.0.0.53"}`), &legacy); err != nil || !slices.Equal(legacy.Namespace, []string{".example.com"}) {
		t.Fatalf("legacy applied policy = %#v, %v", legacy, err)
	}
}

func TestPoliciesForIP(t *testing.T) {
	rules := []rule{
		{domain: "example.com", resolver: "10.0.0.1", protocol: "UDP", active: true, publicIP: "142.110.0.0/16"},
		{domain: "example.com", resolver: "10.0.0.2", protocol: "UDP", active: true, publicIP: "68.147.10.102"},
		{domain: "other.com", resolver: "10.0.0.3", protocol: "UDP", active: true},
	}
	for _, tc := range []struct {
		ip, want string
		count    int
	}{{"142.110.9.7", "10.0.0.1", 2}, {"68.147.10.102", "10.0.0.2", 2}, {"8.8.8.8", "10.0.0.3", 1}} {
		p, err := policiesForIP(rules, tc.ip)
		if err != nil || len(p) != tc.count || p[0].Resolver != tc.want {
			t.Fatalf("%s: %#v, %v", tc.ip, p, err)
		}
	}
	if _, err := policiesForIP(rules, ""); err == nil {
		t.Fatal("accepted unavailable public IP")
	}
	rules[1].publicIP = "142.110.1.1"
	if _, err := policiesForIP(rules, "142.110.1.1"); err == nil {
		t.Fatal("accepted overlapping conditions")
	}
}

func TestConditionMismatch(t *testing.T) {
	for _, tc := range []struct {
		condition, ip string
		known, want   bool
	}{
		{"142.110.0.0/16", "142.110.5.1", true, false},
		{"142.110.0.0/16", "68.147.10.102", true, true},
		{"68.147.10.102", "68.147.10.103", true, true},
		{"", "68.147.10.102", true, false},
		{"142.110.0.0/16", "68.147.10.102", false, false},
	} {
		if got := conditionMismatch(tc.condition, tc.ip, tc.known); got != tc.want {
			t.Fatalf("conditionMismatch(%q, %q, %v) = %v", tc.condition, tc.ip, tc.known, got)
		}
	}
}

func TestNRPTViewFormatting(t *testing.T) {
	script := `function Get-DnsClientNrptRule { [CmdletBinding()] param() [pscustomobject]@{ Name = 'rule1'; Namespace = @('.example.com'); NameServers = @('10.0.0.53'); Empty = ''; Enabled = $false; CimClass = 'metadata' }; [pscustomobject]@{ Name = 'rule2'; Namespace = @('.second.com'); NameServers = @('10.0.0.54') } }` + "\n" + nrptViewScript
	output, err := runPowerShellOutput(script, nil)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(output, "\n")
	if len(lines) < 3 || !strings.HasPrefix(lines[0], "Namespace") || !strings.HasPrefix(lines[1], "NameServers") {
		t.Fatalf("unexpected order: %q", output)
	}
	for _, unwanted := range []string{"CimClass", "Empty", "#< CLIXML", "\n\n"} {
		if strings.Contains(output, unwanted) {
			t.Fatalf("unexpected %q in output: %s", unwanted, output)
		}
	}
	if !strings.Contains(output, "Enabled") || !strings.Contains(output, "False") || !strings.Contains(output, "{.second.com}") {
		t.Fatalf("missing properties or second rule: %s", output)
	}
}

func TestPowerShellErrorXML(t *testing.T) {
	output := `#< CLIXML
<Objs xmlns="http://schemas.microsoft.com/powershell/2004/04"><S S="Error">Access denied_x000D__x000A_</S></Objs>`
	if got := powershellError(output); got != "Access denied" {
		t.Fatalf("error = %q", got)
	}
}
