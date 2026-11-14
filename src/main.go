package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"dns-splitter/asset"
	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
)

type rule struct {
	domain, resolver, protocol, publicIP string
	active                               bool
}

var deleteIcon = ui.MustParseSVG([]byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18M8 6V4h8v2M5 6l1 14h12l1-14M10 10v6M14 10v6"/></svg>`))
var moonIcon = ui.MustParseSVG([]byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20.9 13A9 9 0 0 1 11 3.1 9 9 0 1 0 20.9 13Z"/></svg>`))
var sunIcon = ui.MustParseSVG([]byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.42 1.42M17.65 17.65l1.42 1.42M2 12h2M20 12h2M4.93 19.07l1.42-1.42M17.65 6.35l1.42-1.42"/></svg>`))

type app struct {
	rules                              []rule
	search, fallback, fallbackProtocol string
	automatic                          bool
	selected                           int
	editing                            bool
	draft                              rule
	editIndex                          int
	errorText                          string
	window                             *mygo.Window
	publicIP                           string
	publicIPStatus                     string
	lastIPCheck, nextIPCheck           time.Time
	refreshTimer                       *time.Timer
	checkingIP                         bool
	closed                             bool
	operationBusy                      bool
	operationStatus                    string
	windowSize                         windowSize
	showNRPT                           bool
	nrptOutput                         string
	publicIPKnown                      bool
	appliedRules                       []rule
	appliedPolicies                    []policyRule
	failedPolicyKey                    string
}

func newApp() *app {
	a := &app{selected: -1, windowSize: loadWindowSize(), operationStatus: "Apply requests administrator approval"}
	var err error
	a.rules, err = loadRules()
	if err != nil {
		a.operationStatus = "Could not load saved rules: " + err.Error()
	}
	a.appliedRules, a.appliedPolicies, err = loadApplied()
	if err != nil {
		a.operationStatus = "Could not load applied rule state: " + err.Error()
	}
	return a
}

func (a *app) runOperation(apply bool) {
	if a.operationBusy {
		return
	}
	snapshot := append([]rule(nil), a.rules...)
	var policies []policyRule
	if apply {
		ip := ""
		if a.publicIPKnown {
			ip = a.publicIP
		}
		var err error
		policies, err = policiesForIP(snapshot, ip)
		if err != nil {
			a.operationStatus = err.Error()
			return
		}
		a.failedPolicyKey = ""
	}
	a.operationBusy = true
	a.operationStatus = "Working…"
	if apply {
		a.operationStatus = "Waiting for administrator approval…"
	}
	go func() {
		var err error
		applied := false
		if apply {
			err = applyPolicies(policies)
			if err == nil {
				applied = true
				if saveErr := saveRules(snapshot); saveErr != nil {
					err = fmt.Errorf("rules applied, but saving the rule list failed: %w", saveErr)
				}
				if saveErr := saveApplied(snapshot, policies); saveErr != nil {
					err = fmt.Errorf("rules applied, but saving applied state failed: %w", saveErr)
				}
			}
		} else {
			err = flushDNS()
		}
		a.window.Update(func() {
			if a.closed {
				return
			}
			a.operationBusy = false
			if applied {
				a.appliedRules = snapshot
				a.appliedPolicies = policies
			}
			if err != nil {
				a.operationStatus = err.Error()
			} else if apply {
				a.operationStatus = "NRPT rules applied"
			} else {
				a.operationStatus = "DNS cache flushed"
			}
			if err == nil {
				a.reconcileConditions()
			}
		})
	}()
}

func (a *app) reconcileConditions() {
	if a.operationBusy || !a.publicIPKnown || len(a.appliedRules) == 0 {
		return
	}
	policies, err := policiesForIP(a.appliedRules, a.publicIP)
	if err != nil {
		a.operationStatus = "Cannot evaluate conditions: " + err.Error()
		return
	}
	if slices.EqualFunc(policies, a.appliedPolicies, func(a, b policyRule) bool { return a.Resolver == b.Resolver && slices.Equal(a.Namespace, b.Namespace) }) {
		a.failedPolicyKey = ""
		return
	}
	key := fmt.Sprint(policies)
	if key == a.failedPolicyKey {
		return
	}
	snapshot := append([]rule(nil), a.appliedRules...)
	a.operationBusy = true
	a.operationStatus = "Public IP changed; waiting for administrator approval…"
	go func() {
		err := applyPolicies(policies)
		applied := err == nil
		if err == nil {
			if e := saveApplied(snapshot, policies); e != nil {
				err = fmt.Errorf("rules updated, but applied state could not be saved: %w", e)
			}
		}
		a.window.Update(func() {
			if a.closed {
				return
			}
			a.operationBusy = false
			if applied {
				a.appliedPolicies = policies
			}
			if err != nil {
				a.failedPolicyKey = key
				a.operationStatus = "Conditional rules may be out of date: " + err.Error()
				return
			}
			a.failedPolicyKey = ""
			a.operationStatus = "Conditional NRPT rules updated"
			a.reconcileConditions()
		})
	}()
}

func (a *app) persistRules() {
	if err := saveRules(a.rules); err != nil {
		a.operationStatus = "Could not save rules: " + err.Error()
	} else {
		a.operationStatus = "Rules saved; select Apply to update Windows"
	}
}

func (a *app) showNRPTRules() {
	if a.operationBusy {
		return
	}
	a.operationBusy = true
	a.operationStatus = "Loading NRPT rules…"
	go func() {
		output, err := readNRPTRules()
		a.window.Update(func() {
			if a.closed {
				return
			}
			a.operationBusy = false
			if err != nil {
				a.operationStatus = "Could not read NRPT rules: " + err.Error()
			} else {
				a.nrptOutput = output
				a.showNRPT = true
				a.operationStatus = "NRPT rules loaded"
			}
			a.reconcileConditions()
		})
	}()
}
func fetchPublicIPv4(client *http.Client, endpoint string) (string, error) {
	resp, err := client.Get(endpoint)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("lookup returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	if err != nil {
		return "", err
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(string(body)))
	if err != nil || !ip.Is4() || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return "", fmt.Errorf("lookup returned an invalid public IPv4 address")
	}
	return ip.String(), nil
}

// fallbackHTTPClient resolves names through the specified DNS server directly.
// Keeping the URL's hostname intact preserves TLS hostname verification.
func fallbackHTTPClient(dnsAddress string) *http.Client {
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, dnsAddress)
	}}
	dialer := &net.Dialer{Resolver: resolver}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = dialer.DialContext
	return &http.Client{Transport: transport, Timeout: 8 * time.Second}
}

func lookupPublicIPv4(normal, fallback *http.Client, endpoint string) (string, error) {
	ip, err := fetchPublicIPv4(normal, endpoint)
	if err == nil {
		return ip, nil
	}
	ip, fallbackErr := fetchPublicIPv4(fallback, endpoint)
	if fallbackErr != nil {
		return "", fmt.Errorf("normal lookup failed: %v; fallback lookup failed: %w", err, fallbackErr)
	}
	return ip, nil
}

func (a *app) refreshPublicIP() {
	if a.checkingIP {
		return
	}
	a.scheduleIPRefresh()
	a.checkingIP = true
	a.publicIPStatus = ""
	go func() {
		ip, err := lookupPublicIPv4(&http.Client{Timeout: 8 * time.Second}, fallbackHTTPClient("1.1.1.1:53"), "https://api.ipify.org")
		a.window.Update(func() {
			if a.closed {
				return
			}
			a.checkingIP = false
			if err != nil {
				a.publicIPKnown = false
				a.publicIPStatus = "Lookup failed. Use refresh to try again."
				for _, r := range a.appliedRules {
					if r.active && r.publicIP != "" {
						a.operationStatus = "Public IP unavailable; conditional NRPT rules may be out of date."
						break
					}
				}
				return
			}
			a.publicIP = ip
			a.publicIPKnown = true
			a.lastIPCheck = time.Now()
			a.publicIPStatus = ""
			a.reconcileConditions()
		})
	}()
}
func (a *app) openEditor(index int) {
	a.editIndex = index
	a.draft = rule{protocol: "UDP", active: true}
	if index >= 0 {
		a.draft = a.rules[index]
		if names, err := parseDomains(a.draft.domain); err == nil {
			a.draft.domain = strings.Join(names, ", ")
		}
	}
	a.errorText = ""
	a.editing = true
}
func (a *app) saveRule() {
	a.draft.domain = strings.TrimSpace(a.draft.domain)
	a.draft.resolver = strings.TrimSpace(a.draft.resolver)
	a.draft.publicIP = strings.TrimSpace(a.draft.publicIP)
	if _, err := makePolicies([]rule{{domain: a.draft.domain, resolver: a.draft.resolver, protocol: a.draft.protocol, publicIP: a.draft.publicIP, active: true}}); err != nil {
		a.errorText = err.Error()
		return
	}
	names, _ := parseDomains(a.draft.domain)
	a.draft.domain = strings.Join(names, ", ")
	if a.editIndex >= 0 {
		a.rules[a.editIndex] = a.draft
		a.selected = a.editIndex
	} else {
		a.rules = append(a.rules, a.draft)
		a.selected = len(a.rules) - 1
	}
	a.editing = false
}
func (a *app) view(c *ui.Context) {
	t := c.Theme()
	if !a.nextIPCheck.IsZero() && !a.closed {
		c.After(time.Second)
	}
	background, panel := ui.Hex("#f5f6f8"), ui.Hex("#ffffff")
	if t.Dark {
		background, panel = ui.Hex("#18181b"), ui.Hex("#242428")
	}
	ui.Column(c).Fill().Background(background).Children(func() {
		ui.Scroll(c).Grow(1).Padding(28, 36).Gap(20).Children(func() {
			ui.Row(c).AlignItems(ui.Center).Children(func() {
				ui.Text(c, "Conditional DNS Manager").FontSize(27).Bold().Grow(1)
				icon, label, target := moonIcon, "Switch to dark theme", mygo.ThemeDark
				if t.Dark {
					icon, label, target = sunIcon, "Switch to light theme", mygo.ThemeLight
				}
				if ui.ButtonBase(c).Size(32, 32).Center().Label(label).Tooltip(label).Children(func() { ui.Icon(c, icon).FontSize(20) }).Clicked() {
					mygo.Theme.SetSource(target)
					if err := saveTheme(string(target)); err != nil {
						a.operationStatus = "Could not save theme: " + err.Error()
					}
					c.Invalidate()
				}
			})
			section(c, "NETWORK STATUS & FALLBACK")
			ui.Row(c).Gap(14).AlignItems(ui.Stretch).Children(func() {
				card(c, func() {
					ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
						title := "Current public IPv4"
						if a.checkingIP {
							title = "Checking public IPv4"
						}
						ui.Text(c, title).Bold()
						button := ui.ButtonBase(c).Label("Refresh public IPv4").Tooltip("Refresh public IPv4").Width(32).Height(32).Center().Radius(4).Disabled(a.checkingIP).Children(func() { ui.Text(c, "↻").FontSize(20) })
						if button.Clicked() {
							a.refreshPublicIP()
						}
					})
					ip := a.publicIP
					if ip == "" {
						ip = "Not checked"
					}
					ui.Text(c, ip).FontSize(22).Bold()
					last := "Last checked: Never"
					if !a.lastIPCheck.IsZero() {
						last = "Last checked: " + a.lastIPCheck.Format("3:04:05 PM")
					}
					if !a.nextIPCheck.IsZero() {
						remaining := time.Until(a.nextIPCheck)
						seconds := int((remaining + time.Second - 1) / time.Second)
						if seconds < 0 {
							seconds = 0
						}
						last += fmt.Sprintf("  ·  Next check: in %ds", seconds)
					}
					ui.Text(c, last).FontSize(12).TextColor(t.TextMuted)
					if a.publicIPStatus != "" {
						ui.Text(c, a.publicIPStatus).FontSize(12).TextColor(t.TextMuted)
					}
				})
				card(c, func() {
					ui.Text(c, "Default DNS resolver").Bold()
					ui.Text(c, "Managed by Windows").FontSize(20).Bold()
					ui.Text(c, "Unmatched domains use your network's DNS settings.").FontSize(12).TextColor(t.TextMuted)
				})
			})
			section(c, "CONDITIONAL DOMAIN ROUTING")
			ui.Column(c).Background(panel).Border(1, t.Border).Radius(8).Padding(16).Gap(12).Children(func() {
				ui.Row(c).Gap(12).Children(func() {
					ui.TextInput(c, &a.search).Placeholder("Search domains...").Label("Search domains").Grow(1)
					if ui.PrimaryButton(c, "+ Add rule").Disabled(a.operationBusy).Clicked() {
						a.openEditor(-1)
					}
				})
				ui.Row(c).Gap(12).Padding(8, 0).Children(func() {
					ui.Text(c, "DOMAIN / SUFFIX").FontSize(11).Bold().Width(0).Grow(1)
					ui.Text(c, "TARGET RESOLVER").FontSize(11).Bold().Width(120)
					ui.Text(c, "PUBLIC IP").FontSize(11).Bold().Width(120)
					ui.Text(c, "PROTOCOL").FontSize(11).Bold().Width(65)
					ui.Text(c, "ACTIVE").FontSize(11).Bold().Width(71)
				})
				count := 0
				deleteIndex := -1
				for i := range a.rules {
					r := &a.rules[i]
					if !strings.Contains(strings.ToLower(r.domain), strings.ToLower(strings.TrimSpace(a.search))) {
						continue
					}
					count++
					idx := i
					ui.Row(c.Key(fmt.Sprintf("rule-%d", i))).Gap(12).Padding(8, 0).AlignItems(ui.Center).Children(func() {
						ui.Row(c).Width(0).Grow(1).MinWidth(0).Height(32).Background(t.Surface).Border(1, t.Border).Radius(6).AlignItems(ui.Center).Children(func() {
							label := r.domain
							if a.selected == idx {
								label = "●  " + label
							}
							tip := r.domain + " — applies on any public IPv4"
							if r.publicIP != "" {
								tip = r.domain + " — public IPv4 condition: " + r.publicIP
							}
							button := ui.ButtonBase(c).Grow(1).MinWidth(0).Height(30).Center().Label(label).Tooltip(tip).Disabled(a.operationBusy).Children(func() { ui.Text(c, label).SingleLine().Ellipsis("…").Shrink(1).MinWidth(0) })
							if button.DoubleClicked() {
								a.selected = idx
								a.openEditor(idx)
							} else if button.Clicked() {
								a.selected = idx
							}
							if ui.ButtonBase(c).Size(30, 30).Center().Label("Edit " + r.domain).Tooltip("Edit rule").Disabled(a.operationBusy).Children(func() { ui.Text(c, "✎").FontSize(16) }).Clicked() {
								a.selected = idx
								a.openEditor(idx)
							}
						})
						ui.Text(c, r.resolver).Width(120).SingleLine().Ellipsis("…")
						condition := r.publicIP
						if condition == "" {
							condition = "Any"
						}
						ui.Text(c, condition).Width(120).SingleLine().Ellipsis("…")
						ui.Text(c, r.protocol).Width(65)
						ui.Row(c).Width(71).Gap(6).AlignItems(ui.Center).Children(func() {
							mismatch := conditionMismatch(r.publicIP, a.publicIP, a.publicIPKnown)
							value := &r.active
							off := false
							label := "Active: " + r.domain
							if mismatch {
								value = &off
								label += " (public IPv4 does not match)"
							}
							switchControl := ui.Switch(c, value).Label(label).Width(35).Disabled(a.operationBusy || mismatch)
							if mismatch {
								switchControl.Tooltip("Current public IPv4 does not match this rule")
							}
							if switchControl.Changed() {
								a.persistRules()
							}
							if ui.ButtonBase(c).Size(30, 30).Center().Label("Delete " + r.domain).Tooltip("Delete rule").Disabled(a.operationBusy).Children(func() { ui.Icon(c, deleteIcon).FontSize(16) }).Clicked() {
								deleteIndex = idx
							}
						})
					})
				}
				if deleteIndex >= 0 {
					a.rules = append(a.rules[:deleteIndex], a.rules[deleteIndex+1:]...)
					if a.selected == deleteIndex {
						a.selected = -1
					} else if a.selected > deleteIndex {
						a.selected--
					}
					a.persistRules()
				}
				if count == 0 {
					ui.Text(c, "No rules to show. Add a rule to get started.").TextColor(t.TextMuted).Padding(16, 4)
				}
				ui.Row(c).Gap(8).Children(func() {
					ui.Text(c, fmt.Sprintf("%d rules", len(a.rules))).Grow(1).TextColor(t.TextMuted)
				})
			})
		})
		ui.Row(c).Background(panel).Border(1, t.Border).Padding(14, 36).Gap(10).AlignItems(ui.Center).Children(func() {
			ui.Text(c, a.operationStatus).Grow(1).TextColor(t.TextMuted)
			if ui.Button(c, "Flush DNS cache").Disabled(a.operationBusy).Clicked() {
				a.runOperation(false)
			}
			if ui.Button(c, "View NRPT rules").Disabled(a.operationBusy).Clicked() {
				a.showNRPTRules()
			}
			if ui.PrimaryButton(c, "Apply").Disabled(a.operationBusy).Clicked() {
				a.runOperation(true)
			}
		})
	})
	ui.Modal(c, &a.editing, func() {
		ui.Column(c).Width(440).Gap(12).Children(func() {
			title := "Add conditional DNS rule"
			if a.editIndex >= 0 {
				title = "Edit conditional DNS rule"
			}
			ui.Text(c, title).FontSize(21).Bold()
			ui.Field(c, "Domain suffixes", func() { ui.TextInput(c, &a.draft.domain).Placeholder("example.local, example.com") })
			ui.Text(c, "Separate domains with commas or spaces.").FontSize(12).TextColor(t.TextMuted)
			ui.Field(c, "Target resolver IP", func() { ui.TextInput(c, &a.draft.resolver).Placeholder("10.0.0.53") })
			ui.Field(c, "Public IPv4 condition (optional)", func() { ui.TextInput(c, &a.draft.publicIP).Placeholder("12.34.56.78 or 142.110.0.0/16") })
			ui.Text(c, "Leave blank to apply on any network.").FontSize(12).TextColor(t.TextMuted)
			ui.Text(c, "NRPT uses the Windows DNS client; custom ports and per-rule DoH/DoT are not supported.").FontSize(12).TextColor(t.TextMuted)
			ui.Checkbox(c, &a.draft.active, "Rule active")
			if a.errorText != "" {
				ui.Text(c, a.errorText).TextColor(t.Danger)
			}
			ui.Row(c).Gap(8).Children(func() {
				ui.Text(c, "").Grow(1)
				if ui.Button(c, "Cancel").Clicked() {
					a.editing = false
				}
				if ui.PrimaryButton(c, "Save rule").Clicked() {
					a.saveRule()
					if !a.editing {
						a.persistRules()
					}
				}
			})
		})
	})
	ui.Modal(c, &a.showNRPT, func() {
		ui.Column(c).Width(600).Gap(12).Children(func() {
			ui.Text(c, "Windows NRPT rules").FontSize(21).Bold()
			ui.Text(c, "Output of Get-DnsClientNrptRule").FontSize(12).TextColor(t.TextMuted)
			ui.ScrollBoth(c).Height(320).Border(1, t.Border).Radius(6).Padding(12).Children(func() { ui.Text(c, a.nrptOutput).Font("monospace") })
			ui.Row(c).Justify(ui.End).Children(func() {
				if ui.Button(c, "Close").Clicked() {
					a.showNRPT = false
				}
			})
		})
	})
}

func (a *app) scheduleIPRefresh() {
	if a.refreshTimer != nil {
		a.refreshTimer.Stop()
	}
	deadline := time.Now().Add(30 * time.Second)
	a.nextIPCheck = deadline
	a.refreshTimer = time.AfterFunc(time.Until(deadline), func() {
		a.window.Update(func() {
			if !a.closed && a.nextIPCheck == deadline {
				if a.checkingIP {
					a.scheduleIPRefresh()
				} else {
					a.refreshPublicIP()
				}
			}
		})
	})
}
func section(c *ui.Context, s string) {
	ui.Text(c, s).FontSize(14).Bold().TextColor(c.Theme().TextMuted)
}
func card(c *ui.Context, fn func()) {
	t := c.Theme()
	panel := ui.Hex("#ffffff")
	if t.Dark {
		panel = ui.Hex("#242428")
	}
	ui.Column(c).Grow(1).MinWidth(0).Background(panel).Border(1, t.Border).Radius(8).Padding(18).Gap(10).Children(fn)
}
func main() {
	a := newApp()
	mygo.App.WhenReady(func() {
		if theme := loadTheme(); theme != "" {
			mygo.Theme.SetSource(mygo.ThemeSource(theme))
		}
		workArea := mygo.Screen.PrimaryDisplay().WorkArea
		if workArea.Width >= 680 && a.windowSize.Width > workArea.Width {
			a.windowSize.Width = workArea.Width
		}
		if workArea.Height >= 500 && a.windowSize.Height > workArea.Height {
			a.windowSize.Height = workArea.Height
		}
		a.window = mygo.NewWindow(mygo.WindowOptions{Title: "Conditional DNS Manager", Width: a.windowSize.Width, Height: a.windowSize.Height, MinWidth: 680, MinHeight: 500, Content: ui.View(a.view)})
		if err := a.window.SetIcon(asset.AppIcon); err != nil {
			log.Printf("window icon: %v", err)
		}
		showWindow := func() { a.window.Show(); a.window.Restore(); a.window.Focus() }
		tray, err := mygo.NewTray(mygo.TrayOptions{
			Icon:    asset.AppIcon,
			ToolTip: "Conditional DNS Manager",
			Menu: mygo.NewMenu([]*mygo.MenuItem{
				{Label: "Open Conditional DNS Manager", Click: func(*mygo.MenuItem, *mygo.Window) { showWindow() }},
				mygo.Separator(),
				{Label: "Quit", Click: func(*mygo.MenuItem, *mygo.Window) { mygo.App.Quit() }},
			}),
		})
		if err != nil {
			log.Printf("system tray unavailable: %v", err)
			a.operationStatus = "System tray unavailable; the window will minimize normally."
		} else {
			tray.OnClick(showWindow)
			a.window.OnMinimize(func() { a.window.Hide() })
		}
		a.window.OnResize(func() {
			if !a.window.IsMaximized() && !a.window.IsMinimized() {
				w, h := a.window.Size()
				if w >= 680 && h >= 500 {
					a.windowSize = windowSize{Width: w, Height: h}
				}
			}
		})
		a.window.OnClosed(func() {
			if tray != nil {
				tray.Destroy()
			}
			_ = saveWindowSize(a.windowSize)
			a.closed = true
			if a.refreshTimer != nil {
				a.refreshTimer.Stop()
			}
		})
		a.refreshPublicIP()
	})
	if err := mygo.App.Run(); err != nil {
		log.Fatal(err)
	}
}
