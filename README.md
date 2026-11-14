# Conditional DNS Manager

A Windows desktop app for configuring conditional DNS routing through the Name Resolution Policy Table (NRPT), built in Go with MyGo native UI.

## Framework

The interface uses [MyGo](https://mygo.egoist.dev/docs), a Go desktop application framework. This project uses MyGo's [native UI](https://mygo.egoist.dev/docs/ui): the interface is written in Go and drawn by MyGo, without an HTML/JavaScript frontend or WebView2. The MyGo version is pinned in `go.mod`; Go downloads the required modules when building the project.

## Build the Windows binary

Install Go 1.27.4 or later, open PowerShell in the project directory, and run:

```powershell
go run github.com/egoist/mygo/cmd/mygo build -skip-installer
```

This creates `build/windows-amd64/DNSManager.exe`, with the icon from `asset/app-icon.png` embedded in the executable. Launch it by double-clicking the file or running `./build/windows-amd64/DNSManager.exe` from PowerShell. The first build needs access to the Go module dependencies. The MyGo CLI is run at the version pinned in `go.mod`.

This command builds the executable directly; it does not create an installer or sign the binary. Applying NRPT rules still requires approval through the Windows administrator prompt.

## Install for the current user

After building, run these commands from the project directory in PowerShell:

```powershell
$installDir = Join-Path $env:LOCALAPPDATA 'Programs\win-dns-manger'
New-Item -ItemType Directory -Path $installDir -Force | Out-Null
Copy-Item -LiteralPath 'build\windows-amd64\DNSManager.exe' -Destination $installDir -Force
```

Launch `DNSManager.exe` from that folder. Rebuild and repeat the copy to update it.

## Run

Install Go 1.27.4 or later and run `go run ./src` from a Windows terminal. Apply opens the Windows administrator approval prompt; the app itself does not need to be launched as administrator. Run `go test ./...` to check validation and the IP lookup code.

The application source and tests are in `src/`. The `asset/` folder contains the app icon and a small Go package that embeds it into the executable. Project configuration and Go module files remain in the project root.

The window can be resized in both directions and remembers its normal size when closed. The light/dark theme selection is saved. Use **View NRPT rules** to display the output of `Get-DnsClientNrptRule` using the current user's permissions.

Minimizing the window keeps the app running in the Windows notification area. Click its tray icon to restore the window, or right-click the icon and choose **Open Conditional DNS Manager** or **Quit**. Closing the window also quits the app. Public IP checks and conditional rule re-evaluation continue while minimized.

## Rules

Add domain suffixes such as `example.com` (or `*.example.com`) and specify a DNS server IP address. Enter multiple suffixes separated by commas or spaces to give them one shared resolver and public IP condition. Both spellings create the same suffix policy. Double-click a domain to edit it. Edits are saved to `%APPDATA%\DNSManager\rules.json`; settings from the previous `ConditionalDNSManager` folder are migrated on first launch. NRPT is configured through Windows' DnsClient PowerShell cmdlets. Apply replaces only rules bearing this app's ownership marker and flushes the DNS cache. Changes take effect in Windows when Apply is selected. Clear the list and apply to remove all app-owned rules. Windows retains the policies after the app closes or the computer restarts.

Unmatched names use the DNS settings configured by Windows. NRPT rules work for applications using the Windows DNS client; applications with their own resolver, including `nslookup` and some browser DNS-over-HTTPS configurations, can bypass them. Use `Resolve-DnsName` to check behavior through the Windows DNS client. Windows policy configured by Group Policy can override local NRPT; the app refuses to apply nonempty rules when it detects the Group Policy NRPT registry key. Other local rules are left untouched, and the app rejects duplicate namespaces.

Each rule can optionally match a single public IPv4 address or CIDR range, such as `12.34.56.78` or `142.110.0.0/16`. Leave the condition blank for any network. Rules for the same suffix may use non-overlapping conditions. Apply uses the most recently detected public IP; when a later check changes which applied rules match, the app requests administrator approval to update NRPT. If approval is canceled or a lookup fails, the existing NRPT policies can remain in effect and may be out of date. Retry by selecting Apply. Conditions are re-evaluated only while the app is running, and NRPT policies persist when it closes; this is not a fail-safe network boundary.

This version supports resolver IP addresses with the Windows DNS client's standard transport and port. Custom ports and per-rule DoH/DoT are not supported. The app does not yet monitor whether another component removes policies after a network change. If applying fails it attempts to restore the app's previous rules, but rollback may also fail; the error reports this. Policies can remain active even after the app closes or its rule list is lost.

The app looks up your public IPv4 address through api.ipify.org at startup and every 30 seconds while the window is open. Manual refresh restarts the countdown. If the normal lookup fails, it retries using DNS directly at 1.1.1.1; this requires access to that server and the IP lookup service. The fallback bypasses configured HTTP proxies.
