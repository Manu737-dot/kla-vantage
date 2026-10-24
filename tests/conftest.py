"""Shared test fixtures. No test may touch the real network (enforced below)."""

from __future__ import annotations

import socket
from pathlib import Path
from typing import Any

import pycurl
import pytest
import yaml

from kla import ai, context, dnsprobe, http, util
from kla.config import DEFAULT_CONFIG, load_config


def _blocked(*args: Any, **kwargs: Any) -> Any:
    raise AssertionError("a test tried to use the real network")


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket.socket, "connect", _blocked)
    monkeypatch.setattr(http, "CURL_FACTORY", _blocked)
    monkeypatch.setattr(dnsprobe, "_udp_query", _blocked)
    monkeypatch.setattr(dnsprobe, "_tcp_query", _blocked)
    monkeypatch.setattr(dnsprobe, "_getaddrinfo", _blocked)
    monkeypatch.setattr(context, "_http_get_text", _blocked)
    monkeypatch.setattr(context, "_cymru_txt", lambda name: None)
    monkeypatch.setattr(
        util, "run_cmd", lambda args, timeout=30: util.CmdResult(127, "", "blocked")
    )
    # Tests run as if the laptop has a network route; offline tests switch this off.
    monkeypatch.setattr(ai, "online", lambda cfg: True)
    for key in ("GEMINI_API_KEY", "OPENROUTER_API_KEY", "GROQ_API_KEY", "OPENAI_API_KEY"):
        monkeypatch.delenv(key, raising=False)


@pytest.fixture
def cfg(tmp_path: Path):
    """The real config, but with all storage inside a temp folder."""
    raw = yaml.safe_load(DEFAULT_CONFIG.read_text())
    raw["storage"] = {
        "db_path": "data/test.sqlite3",
        "export_dir": "data/export",
        "reports_dir": "reports",
        "lock_path": "data/kla.lock",
    }
    raw["probe"]["pause_between_targets_s"] = 0
    (tmp_path / "config").mkdir()
    path = tmp_path / "config" / "config.yaml"
    path.write_text(yaml.safe_dump(raw))
    return load_config(path)


class FakeCurl:
    """Stands in for pycurl.Curl: replays scripted headers, body, timings and errors."""

    def __init__(
        self,
        *,
        times: dict[str, int] | None = None,
        status: int = 200,
        http_version: int = 3,
        ip: str = "203.0.113.10",
        headers: list[bytes] | None = None,
        chunks: list[bytes] | None = None,
        debug: list[bytes] | None = None,
        error: tuple[int, str] | None = None,
        num_connects: int = 1,
    ) -> None:
        self.opts: dict[int, Any] = {}
        self.times = times or {
            "namelookup": 100,
            "connect": 60_000,
            "appconnect": 180_000,
            "pretransfer": 181_000,
            "starttransfer": 400_000,
            "total": 401_000,
        }
        self.status, self.http_version, self.ip = status, http_version, ip
        self.headers = headers or [
            b"HTTP/2 200\r\n",
            b"server: cloudflare\r\n",
            b"cf-ray: 8a1b2c3d4e5f6a7b-MBA\r\n",
        ]
        self.chunks = chunks if chunks is not None else [b"{}"]
        self.debug = debug or [
            b"SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384 / X25519",
            b"ALPN: server accepted h2",
        ]
        self.error, self.num_connects = error, num_connects
        self.closed = False
        self.performs = 0

    def setopt(self, opt: int, value: Any) -> None:
        self.opts[opt] = value

    def perform(self) -> None:
        self.performs += 1
        for d in self.debug:
            self.opts[pycurl.DEBUGFUNCTION](pycurl.INFOTYPE_TEXT, d)
        for h in self.headers:
            self.opts[pycurl.HEADERFUNCTION](h)
        for c in self.chunks:
            if self.opts[pycurl.WRITEFUNCTION](c) == 0:
                raise pycurl.error(23, "Failure writing output to destination")
        if self.error:
            raise pycurl.error(*self.error)

    def getinfo(self, opt: int) -> Any:
        mapping = {
            pycurl.NAMELOOKUP_TIME_T: self.times.get("namelookup", 0),
            pycurl.CONNECT_TIME_T: self.times.get("connect", 0),
            pycurl.APPCONNECT_TIME_T: self.times.get("appconnect", 0),
            pycurl.PRETRANSFER_TIME_T: self.times.get("pretransfer", 0),
            pycurl.STARTTRANSFER_TIME_T: self.times.get("starttransfer", 0),
            pycurl.TOTAL_TIME_T: self.times.get("total", 0),
            pycurl.NUM_CONNECTS: self.num_connects,
            pycurl.RESPONSE_CODE: self.status,
            pycurl.INFO_HTTP_VERSION: self.http_version,
            pycurl.PRIMARY_IP: self.ip,
            pycurl.SIZE_DOWNLOAD_T: sum(len(c) for c in self.chunks),
        }
        return mapping[opt]

    def close(self) -> None:
        self.closed = True


@pytest.fixture
def fake_curl(monkeypatch: pytest.MonkeyPatch):
    """Install a factory; returns the list of created FakeCurl handles."""
    made: list[FakeCurl] = []

    def install(**kwargs: Any) -> list[FakeCurl]:
        def factory() -> FakeCurl:
            c = FakeCurl(**kwargs)
            made.append(c)
            return c

        monkeypatch.setattr(http, "CURL_FACTORY", factory)
        return made

    return install


def net_context(public_ip: str = "198.51.100.77") -> context.NetContext:
    ctx = context.NetContext(
        conn_type="wifi",
        iface="wlp61s0",
        gateway="192.168.0.1",
        vpn_active=False,
        wifi_signal_pct=63,
        wifi_dbm=-55.0,
        wifi_freq_mhz=2432,
        wifi_band="2.4GHz",
        router_rtt_ms=2.8,
        router_loss_pct=0.0,
        on_ac=True,
        boot_id="abc123",
        suspended_total_s=100.0,
    )
    ctx.public = context.PublicInfo(
        asn=329367,
        as_name="Tawala Networks Limited",
        source="ripestat",
        cf_colo="MBA",
        public_ip=public_ip,
    )
    return ctx
