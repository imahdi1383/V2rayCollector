# Introduction

**First project on the internet** that crawls v2ray configs from Telegram channels. And the list will update every 5 hours. 😋

# How to use this ?! 🤔


- ‼ Github banned github actions on my account :( so you can use the list below Or you can fork this repo and enable github actions on your account and use your own subs links :) 
-------------------------------

It is so easy just go ahead and download a V2ray Client App that **supports subscription link** and use these links as subscription link 🤩
Config Type|subscription link
-------------------------------|-----------------------------|
Vmess         |https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/vmess_iran.txt      |
ShadowSocks        |https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/ss_iran.txt  |
Trojan |https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/trojan_iran.txt|
Vless|https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/vless_iran.txt|
Mixed (configs of this are different)|https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/mixed_iran.txt|

# Run locally (without GitHub Actions)

## Prerequisites
- Go 1.22+ (see `go.mod`)

## Windows (PowerShell)
Install Go (example via winget):

```powershell
winget install --id GoLang.Go --source winget
go version
```

Run once from the repo root:

```powershell
go mod download
go run . -sort
```

If Telegram opens in your browser but CLI tools time out, you likely need the same proxy/VPN your browser uses.
Go uses `HTTP_PROXY` / `HTTPS_PROXY` env vars (it does not automatically use Windows proxy settings):

```powershell
$env:HTTP_PROXY="http://127.0.0.1:2080"
$env:HTTPS_PROXY="http://127.0.0.1:2080"
go run . -sort
```

Or use the helper scripts:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run-once.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run-every-15min.ps1
```

`scripts/run-once.ps1` will also try to auto-use your Windows proxy settings if `HTTP_PROXY`/`HTTPS_PROXY` are not set.

## Linux / macOS

```bash
go mod download
go run . -sort
```

## Outputs
This overwrites these files in the repo root:
- `vmess_iran.txt`
- `vless_iran.txt`
- `trojan_iran.txt`
- `ss_iran.txt`
- `mixed_iran.txt`

## NekoRay auto-import (optional)
If you put a portable NekoRay folder next to this repo (for example: `nekoray-*/nekoray/config/profiles`), the collector will also create JSON profiles there so they show up in the NekoRay GUI.

Flags:
- Disable: `-nekoray=false`
- Custom profiles dir: `-nekoray-profiles "C:\path\to\nekoray\config\profiles"`
- Import a different file: `-nekoray-input vless_iran.txt`
- URL test + sort by ping (default enabled): `-nekoray-urltest=true`
- URL test all profiles (can be slow): `-nekoray-urltest-all=true`
- Override test URL / timeouts: `-nekoray-test-url http://cp.cloudflare.com/ -nekoray-test-timeout 30 -nekoray-test-concurrency 5`


## Todos
 - [x] Adding comments to functions
 - [x] Getting messges modular so it can be easy to edit
 - [ ] Add feature to only stores configs from present until x days ago
 - [x] Sort the stored configs (from latest to oldest)
 - [x] Optimze config exctraction (only get config and remove the dsc and other things)
 - [x] Read Channels from channels.csv (it should support {all_messages} flag)
 - [ ] Update README (add usage of configs in different os and move channels list to channels.csv)
 - [ ] Add support for v2ray configs that posted in json data
 - [ ] Add support for configing script to limit configs count in each files
 - [ ] Add support for testing v2ray configs and adding only correct and working configs in files
 - [x] Fix issue at removing duplicate lines ( duplicates won't create by script , some channels put duplicate configs in their chats :D )

# Telegram channels list that used as source 😉 
click [here](https://github.com/mrvcoder/V2rayCollector/blob/main/channels.csv) to see the list

If you know other telegram channels which they put V2ray Configs feel free to add pull request :)
