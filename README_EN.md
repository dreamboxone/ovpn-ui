[فارسی](README.md) | [English](README_EN.md)

<p align="center">
  <img src="media/logo.png" alt="ovpn-ui" width="260">
</p>

# ovpn-ui for OpenWrt

**ovpn-ui** is a VPN and Xray management panel that installs directly on an **OpenWrt 25.12+** router and runs as a procd service, without Docker.

It is based on [vpn-ui](https://github.com/Sir-MmD/vpn-ui), itself an extended [3X-UI](https://github.com/MHSanaei/3x-ui), reworked and trimmed down to what a router can run.

![Overview](media/overview.png)

> [!WARNING]
> **At least 256 MB of RAM is required.** The panel and its embedded Xray core use about 150-200 MB. On a router with less than 256 MB the panel may not start at all, or may be killed when memory runs out. If Passwall 2 runs on the same router (a second Xray), 512 MB or more is recommended.

## Contents

- [Requirements](#requirements)
- [Install](#install)
- [Logging in](#logging-in)
- [Uninstall](#uninstall)
- [What this build actually runs](#what-this-build-actually-runs)
- [Creating an IKEv2 inbound](#creating-an-ikev2-inbound)
- [Running next to Passwall 2](#running-next-to-passwall-2)
- [Firewall impact](#firewall-impact)
- [Command line](#command-line)
- [Building the packages](#building-the-packages)

## Requirements

| | |
|---|---|
| OS | **OpenWrt 25.12 or newer** (`apk` package manager). Older `opkg` releases are not supported. |
| RAM | **256 MB** minimum (see the warning above) |
| Free space | About **230 MB** on `/`: a 41 MB download that installs to ~125 MB, plus the Xray core and geo files (~60 MB) the panel unpacks when it starts |
| Internet | Needed during install: strongSwan and the kernel modules come from the official OpenWrt feeds |
| Architecture | ARMv7 (`arm_cortex-a*`), ARM64 (`aarch64_*`), `x86_64`. MIPS routers are not supported. |

Check yours with `grep DISTRIB_ARCH /etc/openwrt_release`. Examples:

| `DISTRIB_ARCH` | Devices |
|---|---|
| `arm_cortex-a7_neon-vfpv4` | ipq40xx: Google Wifi AC-1304, GL.iNet B1300, Linksys EA6350v3 |
| `arm_cortex-a9_vfpv3-d16` | mvebu: Linksys WRT1900/3200ACM |
| `arm_cortex-a15_neon-vfpv4` | ipq806x: Netgear R7800, TP-Link C2600 |
| `aarch64_cortex-a53`, `aarch64_*` | filogic, rockchip, Raspberry Pi, qualcommax |
| `x86_64` | PCs and VMs |

## Install

On the router, as root:

```sh
wget -qO- https://raw.githubusercontent.com/dreamboxone/ovpn-ui/main/packaging/openwrt/install.sh | sh
```

The installer:
1. Checks the OpenWrt version, architecture, RAM and free space.
2. Downloads the matching package from [Releases](https://github.com/dreamboxone/ovpn-ui/releases) and verifies its sha256.
3. Installs the package and its dependencies, and starts the service.
4. Prints the panel URL, username and password.

**Offline install:** download `ovpn-ui-<arch>.apk` from Releases and copy it to the router:

```sh
scp -O ovpn-ui-arm_cortex-a7_neon-vfpv4.apk root@192.168.1.1:/tmp/
```

Then on the router:

```sh
apk update
apk add --allow-untrusted /tmp/ovpn-ui-arm_cortex-a7_neon-vfpv4.apk
```

(`--allow-untrusted` is needed because the package is not signed with the OpenWrt release key.)

## Logging in

A random username, password and URL path are generated at install:

```sh
cat /etc/ovpn-ui/initial-credentials
```

```
username=admin4821
password=********************
port=2053
path=k3j9x0q2m7a1
url=http://192.168.1.1:2053/k3j9x0q2m7a1/
```

1. From the router's LAN, open `url` in a browser.
2. Log in with `username` and `password`.
3. Change the password in **Settings**, or with `ovpn-ui --pass NEW_PASSWORD`.

> [!NOTE]
> The panel is reachable from the LAN only: OpenWrt's default firewall blocks it from the WAN. Do not open the panel port on the WAN.

Forgot the path or port? Run `ovpn-ui info`.

## Uninstall

```sh
apk del ovpn-ui
```

Removing the package:
- Stops the service and charon, and removes the IKEv2 firewall rules.
- Removes the dependencies that were installed only for the panel (strongSwan, kernel modules).
- **Keeps the database in `/etc/ovpn-ui`.** To remove everything:

```sh
rm -rf /etc/ovpn-ui /etc/config/ovpn-ui
```

If you used OpenWrt's own strongSwan service (`swanctl`) before installing the panel, the panel disabled it. Turn it back on after uninstalling:

```sh
/etc/init.d/swanctl enable && /etc/init.d/swanctl start
```

## What this build actually runs

### Supported

| Protocol | Notes |
|---|---|
| VLESS, VMess, Trojan, Shadowsocks | Through the embedded Xray core (Reality, XHTTP, WebSocket, gRPC, ...) |
| AnyTLS, TUIC, NaiveProxy, Hysteria | Protocols added to the patched Xray core |
| WireGuard (Xray) | Userspace WireGuard in Xray |
| HTTP, Mixed (SOCKS), Tunnel (dokodemo), TUN | Xray inbounds |
| **IKEv2/IPsec** | All three modes: **EAP-MSCHAPv2** (username/password), **PSK**, **EAP-TLS**. Uses OpenWrt's strongSwan packages and the router's own kernel modules. |
| SSH | An SSH server inside the panel itself (no daemon, no kernel module) |

Outbounds: every Xray outbound, WARP (WireGuard method) and NordVPN.

### Not supported

These protocols exist in upstream vpn-ui for x86 servers, but they need bundled x86 daemons or kernel modules OpenWrt does not have. **They are removed from the panel in this build**: they are not offered when creating inbounds or outbounds, and the API refuses them.

- L2TP and L2TP/IPsec
- PPTP
- OpenVPN
- OpenConnect (Cisco)
- SSTP
- Kernel WireGuard (C) and AmneziaWG
- GRE
- MTProto Proxy (Telegram)
- VPN tunnels as outbounds (IKEv2, L2TP, OpenVPN, ...)

Features that cannot work on a router and are removed from the panel:
- **In-panel update.** It installs the x86 server release. On OpenWrt you update by installing a newer package.
- **WARP-CLI**, which needs apt/dnf. WARP through the WireGuard method works.
- **The `vpn-ui` menu**, a bash script for systemd. Use the `ovpn-ui` command instead.

### Other panel features

- Multiple admins with per-inbound access, and reseller accounts with a traffic balance
- Per-account traffic, expiry, device and speed limits
- Freeze, bulk operations, TXT and PDF export of account links
- Subscriptions, Telegram bot, database backup and restore
- SSL certificate manager (acme.sh). On a router use the **Cloudflare DNS** method, since port 80 usually belongs to LuCI. Certificate issuance has not been tested on a real router yet.

## Creating an IKEv2 inbound

1. **Inbounds → Add Inbound**, protocol **IKEv2**, port 500.
2. Choose the auth mode:
   - **EAP-MSCHAPv2**: press **Generate Self-Signed Cert**. Apple devices need an RSA certificate.
   - **PSK**: enter a shared key.
   - **EAP-TLS**: paste the server certificate and the CA that signed your client certificates.
3. If the router sits behind another NAT (an ISP modem), put the public IP or domain in **Server Address**, and forward UDP 500 and 4500 on the modem to the router.
4. Add accounts and save.
5. On a phone: an IKEv2 VPN, the server address, the account's username and password. For MSCHAPv2, install the CA certificate on the phone.

IKEv2 client traffic goes through the panel's Xray core, so the panel's routing and outbounds apply to it.

## Running next to Passwall 2

The panel can be installed on a router that runs Passwall 2. Conditions:

- **Ports:** ovpn-ui inbound ports must not collide with Passwall 2's local ports (its TPROXY, SOCKS and DNS ports). IKEv2 uses UDP 500 and 4500, which Passwall 2 does not touch.
- **LAN traffic:** stays with Passwall 2. The panel does not touch LAN traffic.
- **IKEv2 client traffic:** goes through the panel's Xray, not through Passwall 2. Passwall 2's nftables chain runs just before the panel's and marks this traffic too. Without a fix, IKEv2 clients connected but had no internet. The panel clears that mark for the VPN client address range only (`10.0.0.0/12`).
- **Sending IKEv2 users through Passwall 2's proxy:** create a SOCKS outbound in the panel pointing at Passwall 2's local SOCKS port, and route to it.
- **The panel's own Xray traffic** (mark `0xff`) is skipped by Passwall 2 and leaves directly.
- **RAM:** two Xray processes run at once; 512 MB is recommended.

## Firewall impact

- **`/etc/config/firewall` is never modified**, and no zones or forwardings are added.
- **Only while at least one IKEv2 inbound is enabled**, the panel writes `/usr/share/nftables.d/chain-pre/input/90-ovpn-ui.nft` and reloads fw4. The file holds three rules:
  - UDP 500 and 4500 (IKE)
  - ESP
  - Decrypted IKEv2 client traffic: only from `10.0.0.0/12`, and only when it really came out of an IPsec SA

  The file is removed when the last IKEv2 inbound is disabled or deleted, or when the package is removed.
- The panel keeps its own nftables table (`table ip vpn`) and a `fwmark 0x1 → table 100` policy route to steer IKEv2 traffic into Xray.
- `/etc/sysctl.d/99-vpn-ui.conf` sets `ip_forward=1` and `rp_filter=2`.
- OpenWrt's own `swanctl` service is disabled, so only one charon holds UDP 500/4500.
- **Xray inbound ports (e.g. VLESS) are not opened on the WAN automatically.** Add a rule for each:

```sh
uci add firewall rule
uci set firewall.@rule[-1].name='ovpn-ui-vless'
uci set firewall.@rule[-1].src='wan'
uci set firewall.@rule[-1].dest_port='443'
uci set firewall.@rule[-1].proto='tcp udp'
uci set firewall.@rule[-1].target='ACCEPT'
uci commit firewall && service firewall restart
```

## Command line

| Task | Command |
|---|---|
| Status, URL, username | `ovpn-ui info` |
| Change username/password | `ovpn-ui --user admin --pass NEW_PASSWORD` |
| Change panel port/path | `ovpn-ui --port 8443 --path mypanel` |
| Service | `/etc/init.d/ovpn-ui start\|stop\|restart\|enable\|disable` |
| Logs | `logread -e ovpn-ui` |
| Service config | `/etc/config/ovpn-ui` (directories, log level, memory limit) |
| Database | `/etc/ovpn-ui/vpn-ui.db` (kept across sysupgrade) |

The `ovpn-ui` command restarts the service around settings changes by itself.

## Building the packages

GitHub Actions (`.github/workflows/openwrt-apk.yml`) builds every package on push to `main`, and publishes them to a release on every `v*` tag.

On Linux with Go, zig 0.13+ and an OpenWrt 25.12 SDK:

```sh
git clone --recursive https://github.com/dreamboxone/ovpn-ui.git && cd ovpn-ui
packaging/openwrt/build-binary.sh arm
packaging/openwrt/make-apk.sh /path/to/openwrt-sdk-25.12.x arm
ls build/out/openwrt/dist/
```

## Credits

- [vpn-ui](https://github.com/Sir-MmD/vpn-ui) by Sir-MmD
- [3X-UI](https://github.com/MHSanaei/3x-ui) by MHSanaei
- [Xray-core](https://github.com/XTLS/Xray-core)
- [strongSwan](https://www.strongswan.org/) and [OpenWrt](https://openwrt.org/)

## Donate

Support **Sir-MmD**, the original vpn-ui developer (the same addresses the panel's Donate button shows):

🔹USDC-Polygon: ```0xdC2Ab962954e8fA1502C44656c5A32CF2979568C```

🔹USDT-BEP20: ```0xdC2Ab962954e8fA1502C44656c5A32CF2979568C```

🔹USDT-TRC20: ```TXEhckDXtdLGAjP5PZXfNnQjPHzEVTcBmR```

🔹TRX: ```TXEhckDXtdLGAjP5PZXfNnQjPHzEVTcBmR```

🔹LTC: ```ltc1qmapmnuf6cq9x679nmu0k4uyq779mxxcwnkgdll```

🔹BTC: ```bc1q62w7lyndzndsp74vj4dsayvun8xnapzq6hx5ea```

🔹ETH: ```0xdC2Ab962954e8fA1502C44656c5A32CF2979568C```
