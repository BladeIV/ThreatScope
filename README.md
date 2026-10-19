# ThreatScope

A live cyber-attack map for your terminal: a dotted world map with attack arcs flying between
countries, impact ripples, a live attack feed, and panels for the most attacked countries,
attack types and targets.

Single file, **Python standard library only**. Works on Windows, macOS and Linux (uses curses
where available, otherwise a plain-ANSI renderer that works in Windows Terminal and PowerShell).

## Run

```
python threatscope.py
```

## Data sources

| Mode | What you see |
|---|---|
| *(default)* | **Simulated** attacks. Nothing real; good as a screensaver or demo. |
| `--radar` | **Real, aggregated** data from Cloudflare Radar: which countries attack which, the attack-type mix, and the most attacked and attacking countries, from HTTP attack traffic Cloudflare mitigated over the last 24 hours. Refreshed every 5 minutes. Radar publishes shares, not individual events, so the arcs are sampled from those real proportions. |
| `--log FILE` | **Live** attacks against your own machine. Tails a Windows Firewall log (`pfirewall.log`), an nginx/Apache access log, or an SSH auth / fail2ban log. Attacker IPs are geolocated with the free ip-api.com service. |
| `--feed FILE` | Your own events, one JSON object per line, tailed live. |

### Cloudflare Radar

Create a free API token at https://dash.cloudflare.com/profile/api-tokens with the
**Radar: Read** permission, then:

```
# PowerShell
$env:CLOUDFLARE_API_TOKEN="<token>"
# bash
export CLOUDFLARE_API_TOKEN=<token>

python threatscope.py --radar
```

The token is only read from the environment. Never commit it.

### Your own logs

```
python threatscope.py --log C:\Windows\System32\LogFiles\Firewall\pfirewall.log
python3 threatscope.py --log /var/log/nginx/access.log
```

To turn on Windows Firewall logging (PowerShell as Administrator):

```
Set-NetFirewallProfile -All -LogBlocked True -LogMaxSizeKilobytes 16384
```

Useful options: `--here LAT,LON` sets your location (otherwise it's looked up from your public
IP), `--log-replay` also shows what's already in the file, and `--log-all` counts every line with
a public IP.

### JSON feed

```json
{"src": "CN", "dst": "US", "type": "malware", "name": "AgentTesla", "industry": "Healthcare"}
```

`src` and `dst` are ISO country codes or `{"lat": .., "lon": .., "name": ..}`.

## Keys

`q` quit · `p` pause · `+` / `-` arc rate · `1` `2` `3` toggle attack types ·
`m` dotted/solid map · `c` clear stats

## Other options

`--map dots|solid`, `--fps N`, `--ansi` (force the plain-ANSI renderer),
`--snapshot WxH` (render one simulated frame as ANSI text and exit, handy for screenshots).

## See also

[ThreatMap](../ThreatMap) is the follow-up project: a SIEM-style map of real attacks on your own
MikroTik routers, collected over syslog, with offline GeoIP, SQLite storage and detections.
