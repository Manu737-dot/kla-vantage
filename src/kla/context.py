"""Network context recorded with every run.

Answers "what was my connection like at that moment?" so later we can tell a
slow LLM API apart from weak Wi-Fi, a phone hotspot, a VPN, or a different ISP.
Every function here returns None on failure instead of raising: a missing tool
or a dead network is data, not a crash.
"""

from __future__ import annotations

import json
import re
import time
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import dns.exception
import dns.resolver

from kla import util

VPN_IFACE = re.compile(
    r"^(tun|tap|wg|proton|pvpn|ppp|ipsec|nordlynx|tailscale|zt|cloudflarewarp|warp|mullvad)", re.I
)
ARPHRD_NONE = "65534"  # kernel link type of tun and WireGuard devices (no hardware address)
USB_TETHER_DRIVERS = {"rndis_host", "cdc_ether", "cdc_ncm", "ipheth", "cdc_mbim", "qmi_wwan"}
POWERSAVE = {"0": "default", "1": "ignore", "2": "off", "3": "on"}


@dataclass
class PublicInfo:
    asn: int | None = None
    as_name: str | None = None
    source: str | None = None
    cf_colo: str | None = None
    warp: str | None = None  # Cloudflare's own view: "on"/"plus" = traffic came through WARP
    error: str | None = None
    # Kept in memory only (to mask it in traceroutes); never written anywhere.
    public_ip: str | None = field(default=None, repr=False)


@dataclass
class NetCheck:
    """Which network is this, and is a VPN on? Taken at the start and end of every run."""

    ts: datetime
    egress_iface: str | None = None  # where internet traffic leaves (a VPN shows up here)
    router_iface: str | None = None  # the physical network underneath, even with a VPN on
    router_ip: str | None = None
    # Kept in memory only; the database gets a salted hash of it (see netcheck.py).
    router_mac: str | None = field(default=None, repr=False)
    vpn_kind: str | None = None
    warp_cli: str | None = None

    @property
    def vpn_active(self) -> bool:
        return self.vpn_kind is not None


@dataclass
class NetContext:
    conn_type: str = "unknown"
    iface: str | None = None
    gateway: str | None = None
    vpn_active: bool | None = None
    metered: str | None = None
    nm_connectivity: str | None = None
    wifi_signal_pct: int | None = None
    wifi_dbm: float | None = None
    wifi_freq_mhz: int | None = None
    wifi_band: str | None = None
    wifi_bitrate_mbps: float | None = None
    wifi_powersave: str | None = None
    router_rtt_ms: float | None = None
    router_rtt_mdev_ms: float | None = None
    router_loss_pct: float | None = None
    on_ac: bool | None = None
    boot_id: str | None = None
    suspended_total_s: float | None = None
    waited_for_network_s: float = 0.0
    public: PublicInfo = field(default_factory=PublicInfo)
    warp_cli: str | None = None
    # Which network the run started on (stored in `net_checks`, not in `runs`).
    start_check: NetCheck | None = None

    def to_row(self) -> dict[str, Any]:
        """Columns for the `runs` table. The public IP is deliberately left out."""
        row = asdict(self)
        pub = row.pop("public")
        for key in ("gateway", "warp_cli", "start_check"):
            row.pop(key)
        row["asn"] = pub["asn"]
        row["as_name"] = pub["as_name"]
        row["asn_source"] = pub["source"] or pub["error"]
        row["cf_colo"] = pub["cf_colo"]
        for key in ("vpn_active", "on_ac"):
            row[key] = None if row[key] is None else int(row[key])
        return row


# ---------------------------------------------------------------- routing


def egress_route() -> tuple[str | None, str | None]:
    """(gateway, interface) that internet traffic actually leaves through.

    `ip route get` follows policy routing too, so it also notices VPNs that
    steer traffic with routing rules instead of the main table.
    """
    res = util.run_cmd(["ip", "-j", "route", "get", "1.1.1.1"], timeout=5)
    if not res.ok:
        return None, None
    try:
        info = json.loads(res.stdout)[0]
    except (ValueError, IndexError):
        return None, None
    return info.get("gateway"), info.get("dev")


def nm_device(iface: str) -> dict[str, str]:
    res = util.run_cmd(
        [
            "nmcli",
            "-t",
            "-f",
            "GENERAL.TYPE,GENERAL.CONNECTION,GENERAL.METERED",
            "device",
            "show",
            iface,
        ],
        timeout=10,
    )
    out: dict[str, str] = {}
    for line in res.stdout.splitlines():
        key, _, value = line.partition(":")
        out[key.strip()] = value.strip()
    return out


def nm_connectivity() -> str | None:
    res = util.run_cmd(["nmcli", "-t", "-f", "CONNECTIVITY", "general"], timeout=10)
    return (res.stdout.strip() or None) if res.ok else None


def iface_driver(iface: str, sys_root: Path = Path("/sys/class/net")) -> str | None:
    try:
        return (sys_root / iface / "device" / "driver").resolve().name
    except OSError:
        return None


def is_tunnel(iface: str | None, sys_root: Path = Path("/sys/class/net")) -> bool:
    """True for tun/tap and WireGuard devices, whatever the VPN app calls them."""
    if not iface:
        return False
    try:
        if (sys_root / iface / "tun_flags").exists():
            return True
        return (sys_root / iface / "type").read_text().strip() == ARPHRD_NONE
    except OSError:
        return False


def warp_status() -> str | None:
    """Cloudflare WARP's own answer: "connected", "disconnected", "connecting"; None if absent.

    WARP can switch itself on ("Always On") after a network change, part-way
    through a run, so this is asked at the start and at the end of every run.
    """
    res = util.run_cmd(["warp-cli", "--accept-tos", "status"], timeout=5)
    if not res.ok:
        return None
    m = re.search(r"Status update:\s*(\w+)", res.stdout)
    return m.group(1).lower() if m else None


def vpn_kind(
    iface: str | None, warp: str | None, sys_root: Path = Path("/sys/class/net")
) -> str | None:
    """Name of the VPN carrying internet traffic, or None when there is none."""
    if warp == "connected" or (iface and re.match(r"(cloudflarewarp|warp)", iface, re.I)):
        return "cloudflare-warp"
    if iface and (VPN_IFACE.match(iface) or is_tunnel(iface, sys_root)):
        return f"tunnel:{iface}"
    return None


def router_route() -> tuple[str | None, str | None]:
    """(gateway, interface) of the physical network, ignoring any VPN on top.

    `ip route get` (egress_route) answers with the VPN device when one is on.
    The main routing table still holds the real default route via the router.
    """
    res = util.run_cmd(["ip", "-j", "route", "show", "default"], timeout=5)
    if not res.ok:
        return None, None
    try:
        routes = json.loads(res.stdout)
    except ValueError:
        return None, None
    usable = [
        r
        for r in routes
        if r.get("gateway") and r.get("dev") and not VPN_IFACE.match(str(r.get("dev")))
    ]
    if not usable:
        return None, None
    best = min(usable, key=lambda r: int(r.get("metric") or 0))
    return best["gateway"], best["dev"]


def router_mac(gateway: str, iface: str) -> str | None:
    """The router's hardware (MAC) address from the neighbour table; one ping fills it if empty."""
    for attempt in range(2):
        res = util.run_cmd(["ip", "-j", "neigh", "show", gateway, "dev", iface], timeout=5)
        try:
            entries = json.loads(res.stdout) if res.ok else []
        except ValueError:
            entries = []
        for entry in entries:
            mac = str(entry.get("lladdr") or "").lower()
            if re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", mac) and mac != "00:00:00:00:00:00":
                return mac
        if attempt == 0:
            util.run_cmd(["ping", "-n", "-c", "1", "-W", "1", "-I", iface, gateway], timeout=5)
    return None


def check_network() -> NetCheck:
    """Which router and which VPN, right now. Only fast local commands; never raises."""
    check = NetCheck(ts=util.utc_now())
    try:
        _, check.egress_iface = egress_route()
        check.router_ip, check.router_iface = router_route()
        if check.router_ip and check.router_iface:
            check.router_mac = router_mac(check.router_ip, check.router_iface)
        check.warp_cli = warp_status()
        check.vpn_kind = vpn_kind(check.egress_iface, check.warp_cli)
    except Exception:  # a failed check is missing data, never a lost run
        pass
    return check


def classify_connection(
    nm_type: str | None,
    iface: str | None,
    ssid: str | None,
    metered: str | None,
    driver: str | None,
    hotspot_ssids: list[str],
    tunnel: bool = False,
) -> str:
    """Label the connection: wifi, hotspot, usb-tether, ethernet, mobile-modem, vpn, none."""
    if not iface:
        return "none"
    if tunnel or VPN_IFACE.match(iface) or nm_type in ("wireguard", "tun", "vpn"):
        return "vpn"
    if driver in USB_TETHER_DRIVERS:
        return "usb-tether"
    if nm_type == "wifi":
        names = {s.lower() for s in hotspot_ssids}
        # Android/iOS hotspots announce themselves as metered; NetworkManager
        # then reports "yes (guessed)".
        if (ssid and ssid.lower() in names) or (metered or "").startswith("yes"):
            return "hotspot"
        return "wifi"
    if nm_type == "ethernet":
        return "ethernet"
    if nm_type in ("gsm", "cdma", "modem"):
        return "mobile-modem"
    return nm_type or "unknown"


# ------------------------------------------------------------------ wi-fi


def parse_nmcli_fields(line: str) -> list[str]:
    """Split one `nmcli -t` line; colons inside values are escaped as `\\:`."""
    return [p.replace("\\:", ":") for p in re.split(r"(?<!\\):", line)]


def wifi_info(iface: str) -> dict[str, Any]:
    res = util.run_cmd(
        [
            "nmcli",
            "-t",
            "-f",
            "IN-USE,SIGNAL,FREQ,RATE",
            "device",
            "wifi",
            "list",
            "ifname",
            iface,
            "--rescan",
            "no",
        ],
        timeout=10,
    )
    info: dict[str, Any] = {}
    for line in res.stdout.splitlines():
        fields = parse_nmcli_fields(line)
        if len(fields) >= 4 and fields[0] == "*":
            info["wifi_signal_pct"] = _int(fields[1])
            freq = _int(fields[2].split()[0]) if fields[2] else None
            info["wifi_freq_mhz"] = freq
            if freq:
                info["wifi_band"] = "2.4GHz" if freq < 3000 else ("5GHz" if freq < 5925 else "6GHz")
            info["wifi_bitrate_mbps"] = _float(fields[3].split()[0]) if fields[3] else None
            break
    info["wifi_dbm"] = wifi_dbm(iface)
    return info


def wifi_dbm(iface: str, path: Path = Path("/proc/net/wireless")) -> float | None:
    """Signal level in dBm from the kernel (closer to 0 is stronger; -67 is ok, -80 is poor)."""
    try:
        lines = path.read_text().splitlines()
    except OSError:
        return None
    for line in lines:
        if line.strip().startswith(f"{iface}:"):
            parts = line.split()
            if len(parts) >= 4:
                return _float(parts[3].rstrip("."))
    return None


def wifi_powersave(
    connection_name: str | None, conf_dir: Path = Path("/etc/NetworkManager/conf.d")
) -> str | None:
    """Wi-Fi power saving can add tens of ms to every packet, so we record it."""
    if not connection_name:
        return None
    res = util.run_cmd(
        ["nmcli", "-t", "-f", "802-11-wireless.powersave", "connection", "show", connection_name],
        timeout=10,
    )
    value = res.stdout.strip().partition(":")[2].strip() if res.ok else ""
    if value in ("", "default", "0"):
        # Fall back to the global NetworkManager setting.
        try:
            for conf in sorted(conf_dir.glob("*.conf")):
                m = re.search(r"wifi\.powersave\s*=\s*(\d)", conf.read_text())
                if m:
                    return f"default:{POWERSAVE.get(m.group(1), m.group(1))}"
        except OSError:
            pass
        return "default"
    return POWERSAVE.get(value, value)


# ----------------------------------------------------------------- router


_PING_SUMMARY = re.compile(r"= ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms")
_PING_LOSS = re.compile(r"([\d.]+)% packet loss")
_PING_TIME = re.compile(r"time=([\d.]+) ms")


def parse_ping(text: str) -> dict[str, float | None]:
    times = [float(t) for t in _PING_TIME.findall(text)]
    loss = _PING_LOSS.search(text)
    summary = _PING_SUMMARY.search(text)
    median = sorted(times)[len(times) // 2] if times else None
    return {
        "router_rtt_ms": median,
        "router_rtt_mdev_ms": float(summary.group(4)) if summary else None,
        "router_loss_pct": float(loss.group(1)) if loss else None,
    }


def ping_router(gateway: str, count: int = 5) -> dict[str, float | None]:
    """Ping the home router: high numbers here mean a Wi-Fi/home problem, not the internet."""
    res = util.run_cmd(
        ["ping", "-n", "-c", str(count), "-i", "0.2", "-W", "1", gateway], timeout=count + 10
    )
    return parse_ping(res.stdout)


# --------------------------------------------------------- power and sleep


def on_ac_power(root: Path = Path("/sys/class/power_supply")) -> bool | None:
    try:
        supplies = list(root.iterdir())
    except OSError:
        return None
    found = None
    for supply in supplies:
        try:
            if (supply / "type").read_text().strip() == "Mains":
                found = (supply / "online").read_text().strip() == "1"
                if found:
                    return True
        except OSError:
            continue
    return found


def boot_state() -> tuple[str | None, float]:
    """(boot id, seconds spent asleep since boot).

    CLOCK_BOOTTIME keeps counting while the laptop sleeps; CLOCK_MONOTONIC does
    not. The difference is total sleep time, which lets us tell "the laptop was
    asleep" from "the laptop restarted" (new boot id) when a gap appears.
    """
    try:
        boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()[:12]
    except OSError:
        boot_id = None
    asleep = time.clock_gettime(time.CLOCK_BOOTTIME) - time.clock_gettime(time.CLOCK_MONOTONIC)
    return boot_id, round(asleep, 1)


# ------------------------------------------------------------ ISP / ASN


def _http_get_text(url: str, timeout: float = 10) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "kenya-llm-latency/0.1"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read(65536).decode("utf-8", "replace")


def _cymru_txt(name: str) -> str | None:
    try:
        answer = dns.resolver.resolve(name, "TXT", lifetime=5)
    except (dns.exception.DNSException, OSError):
        return None
    for rr in answer:
        return b"".join(rr.strings).decode("utf-8", "replace")
    return None


def clean_as_name(name: str | None) -> str | None:
    """One spelling per ISP, whichever lookup service answered.

    RIPEstat says "Tawala Networks Limited - Tawala Networks Limited"; Team Cymru
    says "Tawala Networks Limited - Tawala Networks Limited, KE". Both become
    "Tawala Networks Limited".
    """
    if not name:
        return None
    name = re.sub(r",\s*[A-Z]{2}$", "", name.strip())
    return name.split(" - ")[0].strip() or None


def asn_name_from_cymru(asn: int) -> str | None:
    txt = _cymru_txt(f"AS{asn}.asn.cymru.com")
    return txt.split("|")[-1].strip() if txt else None


def lookup_public_info(timeout: float = 10) -> PublicInfo:
    """Find my ISP's ASN and name. The public IP never leaves this function's result.

    1. https://1.1.1.1/cdn-cgi/trace tells us our public IP (and which
       Cloudflare city answered, e.g. MBA = Mombasa).
    2. RIPEstat (run by the RIPE NCC internet registry) maps IP -> ASN + name.
       Team Cymru's DNS service is the fallback.
    Common "what is my IP" APIs rate-limit shared ISP addresses (carrier-grade
    NAT), which is why these two were chosen.
    """
    info = PublicInfo()
    try:
        trace = dict(
            line.split("=", 1)
            for line in _http_get_text("https://1.1.1.1/cdn-cgi/trace", timeout).splitlines()
            if "=" in line
        )
    except (OSError, ValueError) as exc:
        info.error = f"public_ip_failed: {type(exc).__name__}"
        return info
    info.public_ip = trace.get("ip")
    info.cf_colo = trace.get("colo")
    info.warp = trace.get("warp")
    if not info.public_ip:
        info.error = "public_ip_missing"
        return info
    try:
        data = json.loads(
            _http_get_text(
                "https://stat.ripe.net/data/prefix-overview/data.json"
                f"?resource={info.public_ip}&sourceapp=kenya-llm-latency",
                timeout,
            )
        )
        asns = data.get("data", {}).get("asns") or []
        if asns:
            info.asn = int(asns[0]["asn"])
            info.as_name = clean_as_name(str(asns[0].get("holder") or ""))
            info.source = "ripestat"
            return info
    except (OSError, ValueError, KeyError, TypeError):
        pass
    if ":" not in info.public_ip:
        rev = ".".join(reversed(info.public_ip.split(".")))
        txt = _cymru_txt(f"{rev}.origin.asn.cymru.com")
        if txt:
            first = txt.split("|")[0].strip().split()
            if first and first[0].isdigit():
                info.asn = int(first[0])
                info.as_name = clean_as_name(asn_name_from_cymru(info.asn))
                info.source = "cymru"
                return info
    info.error = "asn_lookup_failed"
    return info


# --------------------------------------------------------------- gather


def wait_for_route(wait_limit_s: float) -> tuple[str | None, str | None, float]:
    """(gateway, interface, seconds waited). Interface None = no network at all.

    Right after waking from sleep the Wi-Fi may not be connected yet, so wait a little.
    """
    start = time.monotonic()
    gateway, iface = egress_route()
    while iface is None and time.monotonic() - start < wait_limit_s:
        time.sleep(5)
        gateway, iface = egress_route()
    return gateway, iface, round(time.monotonic() - start, 1)


def gather(context_cfg: dict[str, Any], *, lookup_public: bool = True) -> NetContext:
    ctx = NetContext()
    wait_limit = float(context_cfg.get("wait_for_network_s", 60))
    gateway, iface, ctx.waited_for_network_s = wait_for_route(wait_limit)
    ctx.gateway, ctx.iface = gateway, iface
    ctx.nm_connectivity = nm_connectivity()

    if iface:
        dev = nm_device(iface)
        nm_type = dev.get("GENERAL.TYPE")
        connection_name = dev.get("GENERAL.CONNECTION") or None
        ctx.metered = dev.get("GENERAL.METERED") or None
        ctx.conn_type = classify_connection(
            nm_type,
            iface,
            connection_name,
            ctx.metered,
            iface_driver(iface),
            list(context_cfg.get("hotspot_ssids") or []),
            tunnel=is_tunnel(iface),
        )
        ctx.warp_cli = warp_status()
        ctx.vpn_active = ctx.conn_type == "vpn" or vpn_kind(iface, ctx.warp_cli) is not None
        if nm_type == "wifi":
            for key, value in wifi_info(iface).items():
                setattr(ctx, key, value)
            ctx.wifi_powersave = wifi_powersave(connection_name)
    else:
        ctx.conn_type = "none"

    if gateway:
        for key, value in ping_router(
            gateway, int(context_cfg.get("router_ping_count", 5))
        ).items():
            setattr(ctx, key, value)
    ctx.on_ac = on_ac_power()
    ctx.boot_id, ctx.suspended_total_s = boot_state()
    if lookup_public and iface:
        ctx.public = lookup_public_info()
    ctx.start_check = check_network()
    return ctx


def _int(text: str) -> int | None:
    try:
        return int(text)
    except (TypeError, ValueError):
        return None


def _float(text: str) -> float | None:
    try:
        return float(text)
    except (TypeError, ValueError):
        return None
