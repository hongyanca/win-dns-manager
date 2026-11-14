package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf16"
)

type policyRule struct {
	Namespace []string `json:"namespace"`
	Resolver  string   `json:"resolver"`
}

// Older applied state stored one namespace as a string.
func (p *policyRule) UnmarshalJSON(data []byte) error {
	var raw struct {
		Namespace json.RawMessage `json:"namespace"`
		Resolver  string          `json:"resolver"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	var names []string
	if err := json.Unmarshal(raw.Namespace, &names); err != nil {
		var name string
		if err := json.Unmarshal(raw.Namespace, &name); err != nil {
			return err
		}
		names = []string{name}
	}
	p.Namespace, p.Resolver = names, raw.Resolver
	return nil
}

func parseDomains(input string) ([]string, error) {
	parts := strings.FieldsFunc(input, func(r rune) bool { return r == ',' || unicode.IsSpace(r) })
	if len(parts) == 0 {
		return nil, fmt.Errorf("enter at least one domain suffix")
	}
	names := make([]string, 0, len(parts))
	for _, part := range parts {
		name := strings.TrimSuffix(strings.TrimPrefix(strings.ToLower(part), "*."), ".")
		if len(name) == 0 || len(name) > 253 {
			return nil, fmt.Errorf("invalid domain %q", part)
		}
		for _, label := range strings.Split(name, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return nil, fmt.Errorf("invalid domain %q", part)
			}
			for _, ch := range label {
				if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
					return nil, fmt.Errorf("invalid domain %q", part)
				}
			}
		}
		names = append(names, name)
	}
	return names, nil
}

func makePolicies(rules []rule) ([]policyRule, error) {
	result := make([]policyRule, 0, len(rules))
	seen := map[string][]netip.Prefix{}
	for _, r := range rules {
		if !r.active {
			continue
		}
		condition, err := parseIPCondition(r.publicIP)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", r.domain, err)
		}
		if r.protocol != "UDP" {
			return nil, fmt.Errorf("%s: NRPT supports only the UDP setting in this app", r.domain)
		}
		ip, err := netip.ParseAddr(strings.TrimSpace(r.resolver))
		if err != nil || ip.Zone() != "" {
			return nil, fmt.Errorf("%s: resolver must be an IP address without a port", r.domain)
		}
		names, err := parseDomains(r.domain)
		if err != nil {
			return nil, err
		}
		namespaces := make([]string, 0, len(names))
		for _, domain := range names {
			name := "." + domain
			for _, other := range seen[name] {
				if !condition.IsValid() || !other.IsValid() || condition.Contains(other.Addr()) || other.Contains(condition.Addr()) {
					return nil, fmt.Errorf("overlapping public IPv4 conditions for namespace %s", name)
				}
			}
			seen[name] = append(seen[name], condition)
			namespaces = append(namespaces, name)
		}
		result = append(result, policyRule{namespaces, ip.String()})
	}
	return result, nil
}

func parseIPCondition(value string) (netip.Prefix, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return netip.Prefix{}, nil
	}
	if ip, err := netip.ParseAddr(value); err == nil && ip.Is4() {
		return netip.PrefixFrom(ip, 32), nil
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil || !prefix.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("enter an IPv4 address or IPv4 CIDR range")
	}
	return prefix.Masked(), nil
}

func conditionMismatch(condition, publicIP string, known bool) bool {
	if !known || strings.TrimSpace(condition) == "" {
		return false
	}
	prefix, err := parseIPCondition(condition)
	ip, ipErr := netip.ParseAddr(publicIP)
	return err == nil && prefix.IsValid() && ipErr == nil && ip.Is4() && !prefix.Contains(ip)
}

func policiesForIP(rules []rule, publicIP string) ([]policyRule, error) {
	if _, err := makePolicies(rules); err != nil {
		return nil, err
	}
	ip, err := netip.ParseAddr(publicIP)
	for _, r := range rules {
		if r.active && r.publicIP != "" && (err != nil || !ip.Is4()) {
			return nil, fmt.Errorf("public IPv4 is unavailable; refresh it before applying conditional rules")
		}
	}
	selected := make([]rule, 0, len(rules))
	for _, r := range rules {
		if !r.active {
			continue
		}
		prefix, _ := parseIPCondition(r.publicIP)
		if prefix.IsValid() && !prefix.Contains(ip) {
			continue
		}
		selected = append(selected, r)
	}
	return makePolicies(selected)
}

const applyScript = `$ErrorActionPreference = 'Stop'
$marker = 'Conditional DNS Manager / v1'
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run Conditional DNS Manager as administrator to apply NRPT rules.' }
$desired = @(($policyJSON | ConvertFrom-Json))
$gpoPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig'
if ($desired.Count -gt 0 -and (Test-Path -LiteralPath $gpoPath)) {
 throw 'A Group Policy NRPT configuration exists. Windows may ignore local rules; no changes were made.'
}
$all = @(Get-DnsClientNrptRule)
$owned = @($all | Where-Object { $_.Comment -eq $marker })
foreach ($r in $desired) {
 foreach ($namespace in $r.namespace) {
  foreach ($other in $all) {
   if ($other.Comment -ne $marker -and @($other.Namespace) -contains $namespace) { throw "An existing NRPT rule already owns namespace $namespace." }
  }
 }
}
$created = @()
$removed = @()
try {
 foreach ($old in $owned) { Remove-DnsClientNrptRule -Name $old.Name -Force -ErrorAction Stop; $removed += $old }
 foreach ($r in $desired) { $created += Add-DnsClientNrptRule -Namespace ([string[]]$r.namespace) -NameServers $r.resolver -Comment $marker -DisplayName 'Conditional DNS Manager' -PassThru -ErrorAction Stop }
 Clear-DnsClientCache -ErrorAction Stop
} catch {
 $problem = $_.Exception.Message
 $rollbackErrors = @()
 foreach ($r in $created) { try { Remove-DnsClientNrptRule -Name $r.Name -Force -ErrorAction Stop } catch { $rollbackErrors += $_.Exception.Message } }
 foreach ($old in $removed) { try { Add-DnsClientNrptRule -Namespace $old.Namespace -NameServers $old.NameServers -Comment $marker -DisplayName 'Conditional DNS Manager' -ErrorAction Stop | Out-Null } catch { $rollbackErrors += $_.Exception.Message } }
 if ($rollbackErrors.Count) { throw "Apply failed: $problem. Rollback also failed: $($rollbackErrors -join '; ')" }
 throw "Apply failed and previous app rules were restored: $problem"
}`

func runPowerShell(script string, input []byte) error {
	_, err := runPowerShellOutput(script, input)
	return err
}

func runPowerShellOutput(script string, input []byte) (string, error) {
	encoded := encodePowerShell(script)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmd.Stdin = bytes.NewReader(input)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		return "", fmt.Errorf("Windows operation timed out; check NRPT rules before retrying")
	}
	if err != nil {
		message := powershellError(stderr.String())
		if message == "" {
			message = err.Error()
		}
		return "", fmt.Errorf("%s", message)
	}
	return strings.TrimSpace(stdout.String()), nil
}

func powershellError(output string) string {
	output = strings.TrimSpace(output)
	if !strings.HasPrefix(output, "#< CLIXML") {
		return output
	}
	data := strings.TrimSpace(strings.TrimPrefix(output, "#< CLIXML"))
	decoder := xml.NewDecoder(strings.NewReader(data))
	var errors []string
	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}
		start, ok := token.(xml.StartElement)
		if !ok || start.Name.Local != "S" {
			continue
		}
		isError := false
		for _, attr := range start.Attr {
			if attr.Name.Local == "S" && attr.Value == "Error" {
				isError = true
			}
		}
		if isError {
			var value string
			if decoder.DecodeElement(&value, &start) == nil {
				errors = append(errors, value)
			}
		}
	}
	if len(errors) == 0 {
		return "PowerShell reported an error."
	}
	message := strings.Join(errors, "")
	message = strings.ReplaceAll(message, "_x000D_", "\r")
	message = strings.ReplaceAll(message, "_x000A_", "\n")
	return strings.TrimSpace(message)
}

func encodePowerShell(script string) string {
	units := utf16.Encode([]rune(script))
	encoded := make([]byte, 2*len(units))
	for i, u := range units {
		encoded[2*i] = byte(u)
		encoded[2*i+1] = byte(u >> 8)
	}
	return base64.StdEncoding.EncodeToString(encoded)
}

func runElevatedApply(data []byte) error {
	_, err := runElevatedScript(data, applyScript+"\n$response = 'OK'")
	return err
}

const nrptViewScript = `$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$rules = @(Get-DnsClientNrptRule -ErrorAction Stop)
for ($i = 0; $i -lt $rules.Count; $i++) {
 if ($i -gt 0) { [Console]::Out.WriteLine('----------------------------------------') }
 $rule = $rules[$i]
 $properties = @($rule.PSObject.Properties | Where-Object { $_.Name -notmatch '^(Cim|PS)' })
 $names = @('Namespace', 'NameServers') + @($properties | Where-Object { $_.Name -notin @('Namespace', 'NameServers') } | ForEach-Object { $_.Name })
 $lines = @()
 $width = 0
 foreach ($name in $names) {
  $property = $properties | Where-Object { $_.Name -eq $name } | Select-Object -First 1
  if ($null -eq $property -or $null -eq $property.Value) { continue }
  $values = @($property.Value | Where-Object { $null -ne $_ -and -not [string]::IsNullOrWhiteSpace([string]$_) })
  if ($values.Count -eq 0) { continue }
  $value = $values -join ', '
  if ($name -eq 'Namespace') { $value = '{' + $value + '}' }
  $lines += [pscustomobject]@{ Name = $name; Value = $value }
  $width = [Math]::Max($width, $name.Length)
 }
 foreach ($line in $lines) { [Console]::Out.WriteLine(($line.Name.PadRight($width) + ' : ' + $line.Value)) }
}`

func readNRPTRules() (string, error) {
	output, err := runPowerShellOutput(nrptViewScript, nil)
	if err != nil {
		return "", err
	}
	if output == "" {
		return "No NRPT rules found.", nil
	}
	return output, nil
}

func runElevatedScript(data []byte, script string) (string, error) {
	dir, err := os.MkdirTemp("", "conditional-dns-apply-")
	if err != nil {
		return "", fmt.Errorf("prepare administrator request: %w", err)
	}
	defer os.RemoveAll(dir)
	resultPath := filepath.Join(dir, "result.txt")
	result64 := base64.StdEncoding.EncodeToString([]byte(resultPath))
	data64 := base64.StdEncoding.EncodeToString(data)
	// Both dynamic values are base64 encoded, so they cannot become PowerShell code.
	child := "$policyJSON = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + data64 + "'))\n" +
		"$resultPath = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + result64 + "'))\n" +
		"try {\n" + script + "\n[IO.File]::WriteAllText($resultPath, ('OK' + [char]10 + $response), [Text.Encoding]::UTF8)\n} catch {\n[IO.File]::WriteAllText($resultPath, $_.Exception.Message, [Text.Encoding]::UTF8)\nexit 1\n}"
	encoded := encodePowerShell(child)
	if len(encoded) > 30000 {
		return "", fmt.Errorf("too many rules to send to the administrator prompt")
	}
	launcher := `$ErrorActionPreference = 'Stop'
$encoded = [Console]::In.ReadToEnd()
try {
 $p = Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList @('-NoLogo','-NoProfile','-NonInteractive','-EncodedCommand',$encoded) -Verb RunAs -WindowStyle Hidden -Wait -PassThru -ErrorAction Stop
 exit $p.ExitCode
} catch {
 if ($_.Exception.NativeErrorCode -eq 1223) { [Console]::Error.Write('Administrator approval was canceled.'); exit 2 }
 [Console]::Error.Write($_.Exception.Message); exit 1
}`
	cmd := exec.Command("powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encodePowerShell(launcher))
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmd.Stdin = strings.NewReader(encoded)
	out, launchErr := cmd.CombinedOutput()
	result, readErr := os.ReadFile(resultPath)
	if readErr == nil {
		message := strings.TrimSpace(strings.TrimPrefix(string(result), "\ufeff"))
		if launchErr == nil && strings.HasPrefix(message, "OK\n") {
			return strings.TrimPrefix(message, "OK\n"), nil
		}
		if message != "" {
			return "", fmt.Errorf("%s", message)
		}
	}
	if launchErr != nil && strings.TrimSpace(string(out)) != "" {
		return "", fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return "", fmt.Errorf("administrator operation did not report a result; check NRPT rules before retrying")
}
func applyPolicies(policies []policyRule) error {
	data, err := json.Marshal(policies)
	if err != nil {
		return err
	}
	return runElevatedApply(data)
}
func flushDNS() error {
	return runPowerShell("$ErrorActionPreference = 'Stop'; Clear-DnsClientCache -ErrorAction Stop", nil)
}
