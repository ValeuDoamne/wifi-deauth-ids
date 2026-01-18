# WPA Deauth IDS

Check your networks for deauthentication packets being sent into your network.

Uses a WiFi capable card to go in monitor mode to monitor the incoming WiFi traffic.

## Setup

Sync the python packages using `uv`:
```
uv sync --no-dev
```

## Usage

Activate monitor mode on your wireless card:
```bash
$ sudo airmon-ng start wlan0
```

Use the script as `root`:
```
# python main.py -i wlan0mon -b 00:11:22:33:44:55
```

Where `00:11:22:33:44:55` is the BSSID of the network you would like to watch for.
