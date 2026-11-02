
from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import tempfile
import time
import uuid
import urllib.error
import urllib.request
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterator, Sequence

for stream in (sys.stdout, sys.stderr):
    try:
        stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass


class hnjg_cfg:
    root        = Path(__file__).resolve().parent
    games_file  = root.parent / "data" / "games.json"
    state_file  = root / "hnjg_state.json"
    me_url      = "https://discord.com/api/v9/users/@me?with_analytics_token=true"
    science_url = "https://discord.com/api/v9/science"
    cdn_url     = "https://cdn.discordapp.com/detectables/games.json"
    batch_size  = 50
    batch_delay = 1
    max_age     = 12 * 3600
    version     = "1.0.9253"
    build       = 594031
    native      = 88414
    os_ver      = "10.0.26200"
    ua          = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) discord/1.0.9253 Chrome/148.0.7778.280 "
        "Electron/42.7.1 Safari/537.36"
    )


_hnjg_ps = r'''
param(
  [int]$ProcessId = 0,
  [string]$Path,
  [Parameter(Mandatory = $true)][string]$UserId
)

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class CertPubKeyHash {
  const uint X509_ASN_ENCODING = 0x00000001;
  const uint PKCS_7_ASN_ENCODING = 0x00010000;
  const uint CALG_SHA_256 = 0x0000800C;

  [StructLayout(LayoutKind.Sequential)] struct Blob { public uint cbData; public IntPtr pbData; }
  [StructLayout(LayoutKind.Sequential)] struct AlgId { public IntPtr pszObjId; public Blob Parameters; }
  [StructLayout(LayoutKind.Sequential)] struct BitBlob { public uint cbData; public IntPtr pbData; public uint cUnusedBits; }
  [StructLayout(LayoutKind.Sequential)] struct PubKeyInfo { public AlgId Algorithm; public BitBlob PublicKey; }
  [StructLayout(LayoutKind.Sequential)] struct FileTime { public uint Low; public uint High; }
  [StructLayout(LayoutKind.Sequential)]
  struct CertInfo {
    public uint Version; public Blob SerialNumber; public AlgId SignatureAlgorithm; public Blob Issuer;
    public FileTime NotBefore; public FileTime NotAfter; public Blob Subject;
    public PubKeyInfo SubjectPublicKeyInfo; public BitBlob IssuerUniqueId; public BitBlob SubjectUniqueId;
    public uint ExtensionCount; public IntPtr Extensions;
  }
  [StructLayout(LayoutKind.Sequential)]
  struct CertContext {
    public uint EncodingType; public IntPtr Encoded; public uint EncodedSize;
    public IntPtr CertInfo; public IntPtr Store;
  }

  [DllImport("crypt32.dll", SetLastError = true)]
  static extern bool CryptHashPublicKeyInfo(
    IntPtr provider, uint algid, uint flags, uint encoding, ref PubKeyInfo info, byte[] hash, ref uint hashSize);

  public static byte[] Hash(IntPtr certContext) {
    var ctx = Marshal.PtrToStructure<CertContext>(certContext);
    var info = Marshal.PtrToStructure<CertInfo>(ctx.CertInfo);
    var hash = new byte[32];
    uint hashSize = 32;
    if (!CryptHashPublicKeyInfo(IntPtr.Zero, CALG_SHA_256, 0, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, ref info.SubjectPublicKeyInfo, hash, ref hashSize) || hashSize != 32)
      throw new InvalidOperationException("CryptHashPublicKeyInfo failed");
    return hash;
  }
}
"@

if (!$Path) {
  if (!$ProcessId) { throw "Pass -Path <exe> or -ProcessId <pid>." }
  $Path = (Get-Process -Id $ProcessId).Path
}
if (!$Path) { throw "Could not resolve executable path." }

$fs = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
try {
  $fileSize = [UInt64]$fs.Length
  $readSize = [int][Math]::Min($fs.Length, 0x10000)
  $buf = [byte[]]::new($readSize)
  $read = $fs.Read($buf, 0, $readSize)
  if ($read -lt 0x40) { throw "File prefix is too small." }
  if ($read -ne $readSize) { [Array]::Resize([ref]$buf, $read) }
} finally {
  $fs.Dispose()
}

if ([BitConverter]::ToUInt16($buf, 0) -ne 0x5A4D) { throw "Not an MZ executable." }
$pe = [BitConverter]::ToInt32($buf, 0x3C)
if ($pe -lt 0 -or [BitConverter]::ToUInt32($buf, $pe) -ne 0x4550) { throw "Not a PE executable." }

$fh = $pe + 4
$sections = [BitConverter]::ToUInt16($buf, $fh + 2)
$timestamp = [BitConverter]::ToUInt32($buf, $fh + 4)
$optSize = [BitConverter]::ToUInt16($buf, $fh + 16)
$opt = $fh + 20
$isPe32Plus = [BitConverter]::ToUInt16($buf, $opt) -eq 0x20B
if (!$isPe32Plus) { throw "Discord only fingerprints PE32+." }
$sizeOfImage = [BitConverter]::ToUInt32($buf, $opt + 56)

$sectionTable = $opt + $optSize
$sha256 = [Security.Cryptography.SHA256]::Create()
$headerHash = $sha256.ComputeHash([byte[]]$buf[0..($sectionTable - 1)])
$sectionHash = $sha256.ComputeHash([byte[]]$buf[$sectionTable..($sectionTable + $sections * 40 - 1)])

$machineGuid = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Cryptography" -Name MachineGuid).MachineGuid
$machineUserHash = $sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($machineGuid + $UserId))

$sig = Get-AuthenticodeSignature -LiteralPath $Path
$signed = $sig.Status -eq "Valid" -and $sig.SignerCertificate
if ($signed) {
  $name = $sig.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
  $certHash = $sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($name) + [CertPubKeyHash]::Hash($sig.SignerCertificate.Handle))
} else {
  $certHash = [byte[]]::new(32)
}

$flags = 0
if ($signed) { $flags += 1 }
if ($isPe32Plus) { $flags += 2 }

$out = [byte[]](@(1, [byte]$flags) +
  [BitConverter]::GetBytes($fileSize) +
  [BitConverter]::GetBytes($timestamp) +
  [BitConverter]::GetBytes($sizeOfImage) +
  $headerHash + $machineUserHash + $sectionHash + $certHash)

$key = $sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($UserId + "https://discord.com/careers"))
for ($i = 1; $i -lt $out.Length; $i++) {
  $out[$i] = $out[$i] -bxor $key[($i - 1) -band 31]
}

[Convert]::ToBase64String($out)
'''


def hnjg_gen_fp(uid: str, path: str = "", pid: int = 0) -> str:
    if os.name != "nt":
        raise RuntimeError("windows only")
    tmp = Path(tempfile.gettempdir()) / f"hnjg_{uuid.uuid4().hex}.ps1"
    tmp.write_text(_hnjg_ps, encoding="utf-8")
    try:
        args = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                "-File", str(tmp), "-UserId", uid]
        args += (["-ProcessId", str(pid)] if pid else ["-Path", path])
        r = subprocess.run(args, capture_output=True, text=True, timeout=60)
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass
    if r.returncode != 0:
        lines = (r.stderr or r.stdout or "").strip().splitlines()
        raise RuntimeError(lines[-1] if lines else "powershell failed")
    out = [l.strip() for l in r.stdout.splitlines() if l.strip()]
    if not out:
        raise RuntimeError("no output")
    return out[-1]


class hnjg_con:
    AC = "\x1b[38;5;39m"
    DM = "\x1b[38;5;33m"
    OK = "\x1b[38;5;82m"
    WN = "\x1b[38;5;214m"
    ER = "\x1b[38;5;196m"
    W  = "\x1b[38;5;255m"
    GR = "\x1b[38;5;240m"
    DK = "\x1b[38;5;235m"
    X  = "\x1b[0m"
    R  = "\x1b[38;5;196m"
    O  = "\x1b[38;5;39m"
    G  = "\x1b[38;5;82m"
    Y  = "\x1b[38;5;214m"
    RL = "─" * 48

    def __init__(self) -> None:
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
        if sys.platform == "win32":
            import ctypes
            k = ctypes.windll.kernel32
            h = k.GetStdHandle(-11)
            m = ctypes.c_uint32()
            if k.GetConsoleMode(h, ctypes.byref(m)):
                k.SetConsoleMode(h, m.value | 0x0004)

    def _ts(self) -> str:
        return f"{self.GR}{time.strftime('%H:%M:%S')}{self.X}"

    def _tag(self, label: str, color: str) -> str:
        return f"{color}{label}{self.X}"

    def _ln(self, tag: str, t: str, d: str, c: str) -> None:
        print(f"  {self._ts()}  {tag}  {self.W}{t}{self.X}  {self.GR}|{self.X}  {c}{d}{self.X}")

    def ok(self, t: str, d: str)   -> None: self._ln(self._tag("  OK  ", f"\x1b[48;5;22m{self.OK}"),   t, d, self.OK)
    def sent(self, t: str, d: str) -> None: self._ln(self._tag(" SENT ", f"\x1b[48;5;17m{self.AC}"),   t, d, self.AC)
    def warn(self, t: str, d: str) -> None: self._ln(self._tag(" WARN ", f"\x1b[48;5;52m{self.WN}"),   t, d, self.WN)
    def err(self, t: str, d: str)  -> None: self._ln(self._tag(" FAIL ", f"\x1b[48;5;52m{self.ER}"),   t, d, self.ER)
    def info(self, d: str)         -> None: print(f"  {self._ts()}  {self.GR}···{self.X}  {self.W}{d}{self.X}")
    def rule(self)                 -> None: print(f"\n  {self.DK}{self.RL}{self.X}\n")
    def clear(self)                -> None: print("\x1b[2J\x1b[3J\x1b[H", end="")

    def banner(self) -> None:
        self.clear()
        print()
        print("\033[0;97;47m▀\033[0;91m   \033[0;31;47m▄\033[0;37m \033[0;97;47m▀\033[0;31m▄\033[0;91m  \033[0;31;47m▄\033[0;37m \033[0;91m    \033[0;97;47m▀\033[0;37m \033[0;97m▄▀\033[0;91m▀\033[0;31m▀\033[0;91m \033[0;37m      \033[0;97;47m▀\033[0;91m▀\033[0;31m▀▀▄\033[0;37m \033[0;97m▄▀\033[0;91m▀\033[0;31m▀▄\033[0;37m \033[0;97;47m▀\033[0;91m▀\033[0;31m▀▀▄\033[0;37m \033[0;97m▄▀\033[0;91m▀\033[0;31m▀\033[0;91m \033[0;37m \033[0;97m▄▀\033[0;91m▀\033[0;31m▀█\033[0;37m     \033[0m")
        print("\033[0;31m█▀▀▀█\033[0;37m \033[0;31m█\033[0;91m \033[0;31m▀▄█\033[0;37m \033[0;91m▄   \033[0;31m█\033[0;37m \033[0;31;47m▄\033[0;91m \033[0;31m▀▀█\033[0;37m      \033[0;31m█▀▀▀▄\033[0;37m \033[0;31;47m▄\033[0;31m▀▀▀█\033[0;37m \033[0;31m█\033[0;91m   \033[0;31m█\033[0;37m \033[0;31;47m▄\033[0;91m \033[0;31m▀▀█\033[0;37m \033[0;31;47m▄\033[0;31m▀▀\033[0;91m ▄\033[0;37m     \033[0m")
        print("\033[0;31m▀\033[0;91m   \033[0;31m▀\033[0;37m \033[0;31m▀\033[0;91m   \033[0;31m▀\033[0;37m \033[0;31m▀▀▀▀\033[0;91m \033[0;37m \033[0;91m \033[0;31m▀▀▀▀\033[0;37m      \033[0;31m▀▀▀▀\033[0;91m \033[0;37m \033[0;31m▀\033[0;91m   \033[0;31m▀\033[0;37m \033[0;31m▀▀▀▀\033[0;91m \033[0;37m \033[0;91m \033[0;31m▀▀▀▀\033[0;37m \033[0;91m \033[0;31m▀▀▀▀\033[0;37m     \033[0m")
        print("\033[0;97m▄▀\033[0;91m▀\033[0;31m▀█\033[0;37m \033[0;97;47m▀\033[0;91m    \033[0;37m \033[0;97m▄▀\033[0;91m▀\033[0;31m▀▄\033[0;37m \033[0;97m▀\033[0;31;47m▄\033[0;31m▀\033[0;37m \033[0;97m▄▀\033[0;91m▄▀\033[0;31m▄\033[0;37m \033[0;97m▄▀\033[0;91m▀\033[0;31m▀█\033[0;37m \033[0;97;47m▀\033[0;91m▀\033[0;31m▀▀▄\033[0m")
        print("\033[0;31;47m▄\033[0;91m   ▄\033[0;37m \033[0;31m█\033[0;91m   ▄\033[0;37m \033[0;31;47m▄\033[0;31m▀▀▀█\033[0;37m \033[0;91m \033[0;31m█\033[0;91m \033[0;37m \033[0;31;47m▄\033[0;91m \033[0;31m▀\033[0;91m \033[0;31m█\033[0;37m \033[0;31;47m▄\033[0;31m▀▀\033[0;91m ▄\033[0;37m \033[0;31m█▀▀▀▄\033[0m")
        print("\033[0;91m \033[0;31m▀▀▀▀\033[0;37m \033[0;91m \033[0;31m▀▀▀▀\033[0;37m \033[0;31m▀\033[0;91m   \033[0;31m▀\033[0;37m \033[0;31m▀▀▀\033[0;37m \033[0;31m▀\033[0;91m   \033[0;31m▀\033[0;37m \033[0;91m \033[0;31m▀▀▀▀\033[0;37m \033[0;31m▀\033[0;91m   \033[0;31m▀\033[0m")
        print(f"\n  {self.GR}v{hnjg_cfg.version}  ·  build {hnjg_cfg.build}{self.X}\n")


@dataclass
class hnjg_state:
    token:               str   = ""
    cookie:              str   = ""
    fingerprint:         str   = ""
    analytics_token:     str   = ""
    fetched_at:          int   = 0
    used_games:          list  = None
    total_games:         int   = 0
    total_hours:         float = 0.0

    def __post_init__(self) -> None:
        if self.used_games is None:
            self.used_games = []

    @classmethod
    def load(cls) -> hnjg_state:
        if hnjg_cfg.state_file.exists():
            data = json.loads(hnjg_cfg.state_file.read_text(encoding="utf-8"))
            s = cls(**{k: data.get(k, v) for k, v in cls().__dict__.items() if k != "used_games"})
            s.used_games = data.get("used_games", [])
            return s
        return cls()

    def save(self) -> None:
        hnjg_cfg.state_file.write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")

    @property
    def stale(self) -> bool:
        return not self.analytics_token or (time.time() - self.fetched_at) > hnjg_cfg.max_age

    @property
    def has_cookie(self) -> bool:
        return bool(self.cookie.strip())

    @property
    def has_token(self) -> bool:
        return bool(self.token.strip())


def hnjg_local_props() -> dict:
    return {
        "os": "Windows",
        "browser": "Discord Client",
        "release_channel": "stable",
        "client_version": hnjg_cfg.version,
        "os_version": hnjg_cfg.os_ver,
        "os_arch": "x64",
        "app_arch": "x64",
        "system_locale": "en-GB",
        "has_client_mods": False,
        "browser_user_agent": hnjg_cfg.ua,
        "browser_version": "42.7.1",
        "os_sdk_version": "26200",
        "client_build_number": hnjg_cfg.build,
        "native_build_number": hnjg_cfg.native,
        "client_event_source": None,
        "client_app_state": "focused",
    }


def hnjg_super_props(sig: str, hb: str) -> str:
    p = hnjg_local_props()
    p["client_launch_id"] = str(uuid.uuid4())
    p["launch_signature"] = sig
    p["client_heartbeat_session_id"] = hb
    return base64.b64encode(json.dumps(p, separators=(",", ":")).encode()).decode()


def hnjg_fetch_token(token: str, props: str) -> str:
    req = urllib.request.Request(hnjg_cfg.me_url, headers={
        "authorization": token,
        "user-agent": hnjg_cfg.ua,
        "x-super-properties": props,
    })
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"rejected ({e.code})")
    t = data.get("analytics_token")
    if not t:
        raise RuntimeError("no analytics_token")
    return t


def hnjg_ensure_token(s: hnjg_state, props: str) -> None:
    if s.stale:
        s.analytics_token = hnjg_fetch_token(s.token, props)
        s.fetched_at = int(time.time())
        s.save()


@dataclass(frozen=True)
class hnjg_session:
    hb:    str
    sig:   str
    props: str

    @classmethod
    def new(cls) -> hnjg_session:
        hb  = str(uuid.uuid4())
        sig = str(uuid.uuid4())
        return cls(hb, sig, hnjg_super_props(sig, hb))


@dataclass(frozen=True)
class hnjg_game:
    id:   str
    name: str
    exe:  str


def _hnjg_exe(g: dict) -> str:
    for e in g.get("executables", []):
        if e.get("os") == "win32" and e.get("name"):
            return e["name"]
    return "game.exe"


def _hnjg_dl_games() -> str:
    req = urllib.request.Request(hnjg_cfg.cdn_url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=30) as r:
        raw = r.read().decode()
    try:
        hnjg_cfg.games_file.parent.mkdir(parents=True, exist_ok=True)
        hnjg_cfg.games_file.write_text(raw, encoding="utf-8")
    except OSError:
        pass
    return raw


def _hnjg_parse_games(raw: str) -> list[hnjg_game]:
    games: list[hnjg_game] = []
    seen: set[str] = set()
    for e in json.loads(raw):
        gid = str(e.get("id", ""))
        if not gid.isdigit() or gid in seen:
            continue
        if not any(x.get("os") == "win32" and x.get("name") for x in e.get("executables", [])):
            continue
        seen.add(gid)
        games.append(hnjg_game(gid, e.get("name", "Unknown"), _hnjg_exe(e)))
    return games


def hnjg_load_games() -> list[hnjg_game]:
    raw = ""
    if hnjg_cfg.games_file.exists():
        raw = hnjg_cfg.games_file.read_text(encoding="utf-8").strip()
    if raw:
        try:
            g = _hnjg_parse_games(raw)
            if g:
                return g
        except (json.JSONDecodeError, ValueError):
            pass
    try:
        return _hnjg_parse_games(_hnjg_dl_games())
    except Exception:
        return []


class hnjg_client:
    def __init__(self, s: hnjg_state, sess: hnjg_session) -> None:
        self.s    = s
        self.sess = sess
        self._seq = 0

    def _nxt(self) -> int:
        self._seq += 1
        return self._seq

    def build_launch(self, g: hnjg_game) -> dict:
        now = int(time.time() * 1000)
        p = {
            "client_track_timestamp":        now,
            "client_heartbeat_session_id":   self.sess.hb,
            "event_sequence_number":         self._nxt(),
            "game":                          g.name,
            "game_id":                       g.id,
            "verified":                      True,
            "elevated":                      False,
            "is_launcher":                   False,
            "game_platform":                 "desktop",
            "detection_method":              "verified_game",
            "is_overlay_enabled":            False,
            "is_overlay_game_enabled":       True,
            "is_overlay_game_source":        "OOP_DEFAULT_DATABASE",
            "fullscreen_type":               "UNKNOWN",
            "hardware_display_count":        1,
            "overlay_method":                "Disabled",
            "activity_status_enabled":       True,
            "activity_status_shared_guilds": [],
            "current_user_status":           "online",
            "game_detection_enabled":        True,
            "executable_path":               g.exe,
            "voice_channel_id":              None,
            "voice_channel_type":            None,
            "voice_channel_bitrate":         None,
            "voice_channel_guild_id":        None,
            "hidden_by_distributor":         False,
            "game_metadata":                 None,
            "executable_fingerprint":        self.s.fingerprint,
            "client_performance_cpu":        None,
            "client_performance_memory":     None,
            "cpu_core_count":                None,
            "accessibility_features":        0,
            "rendered_locale":               "en-GB",
            "launch_signature":              self.sess.sig,
            "client_rtc_state":              None,
            "client_app_state":              "focused",
            "client_send_timestamp":         now,
        }
        if not self.s.fingerprint:
            del p["executable_fingerprint"]
        return {"type": "launch_game", "properties": p}

    def build_hb(self, g: hnjg_game, ms: int, sid: str,
                 init: bool, final: bool, ts: int | None = None) -> dict:
        ts = int(time.time() * 1000) if ts is None else ts
        return {
            "type": "running_game_heartbeat",
            "properties": {
                "client_track_timestamp":      ts,
                "client_heartbeat_session_id": self.sess.hb,
                "event_sequence_number":       self._nxt(),
                "game_id":                     g.id,
                "game_name":                   g.name,
                "game_metadata":               None,
                "game_executable":             g.exe,
                "game_detection_enabled":      True,
                "initial_heartbeat":           init,
                "final_heartbeat":             final,
                "game_session_id":             sid,
                "duration_tracked_ms":         ms,
                "rtc_connection_id":           None,
                "media_session_id":            None,
                "launch_signature":            self.sess.sig,
                "client_app_state":            "focused",
                "client_send_timestamp":       ts,
            },
        }

    def build_session(self, g: hnjg_game, ms: int) -> list[dict]:
        sid   = str(uuid.uuid4())
        now   = int(time.time() * 1000)
        start = max(now - ms, 0) or now
        return [
            self.build_hb(g, 0,  sid, True,  False, start),
            self.build_launch(g),
            self.build_hb(g, ms, sid, False, True,  now),
        ]

    def post(self, events: Sequence[dict]) -> int:
        body = json.dumps({"token": self.s.analytics_token, "events": list(events)}).encode()
        req  = urllib.request.Request(
            hnjg_cfg.science_url, data=body, method="POST",
            headers={
                "accept":               "*/*",
                "accept-language":      "en-GB",
                "authorization":        self.s.token,
                "content-type":         "application/json",
                "cookie":               self.s.cookie,
                "origin":               "https://discord.com",
                "referer":              "https://discord.com/channels/@me",
                "user-agent":           hnjg_cfg.ua,
                "x-debug-options":      "bugReporterEnabled",
                "x-discord-locale":     "en-GB",
                "x-discord-timezone":   "Europe/Oslo",
                "x-super-properties":   self.sess.props,
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                return r.status
        except urllib.error.HTTPError as e:
            return e.code
        except Exception:
            return 0


def _hnjg_chunks(items: Sequence[hnjg_game], n: int) -> Iterator[Sequence[hnjg_game]]:
    for i in range(0, len(items), n):
        yield items[i:i + n]


class hnjg_spoofer:
    def __init__(self, c: hnjg_client, con: hnjg_con) -> None:
        self.c   = c
        self.con = con

    def run(self, games: Sequence[hnjg_game], build) -> int:
        total   = len(games)
        sent_ok = 0
        for no, chunk in enumerate(_hnjg_chunks(games, hnjg_cfg.batch_size), 1):
            events = []
            for g in chunk:
                events.extend(build(g))
            status = self.c.post(events)
            if status == 204:
                sent_ok += len(chunk)
                self.con.sent(f"batch {no}", f"{sent_ok}/{total}")
            elif status in (401, 403):
                self.con.err(f"batch {no}", f"authentication rejected  [{status}]")
                return sent_ok
            else:
                self.con.warn(f"batch {no}", f"unexpected response  [{status}]")
            time.sleep(hnjg_cfg.batch_delay)
        return sent_ok


class hnjg_app:
    def __init__(self) -> None:
        self.con:    hnjg_con              = hnjg_con()
        self.s:      hnjg_state            = hnjg_state.load()
        self.sess:   hnjg_session | None   = None
        self.client: hnjg_client | None    = None
        self.games:  list[hnjg_game]       = []

    def _new_sess(self) -> None:
        self.sess   = hnjg_session.new()
        self.client = hnjg_client(self.s, self.sess)

    def _prompt_token(self) -> None:
        self.con.info("enter your account token to continue")
        v = input(f"  {self.con.AC}>{self.con.X} account token: ").strip()
        if v:
            self.s.token = v
            self.s.save()
            self.con.ok("auth", "token stored")

    def _prompt_cookie(self) -> None:
        self.con.info("enter your cf_clearance value from browser cookies")
        v = input(f"  {self.con.AC}>{self.con.X} cf_clearance: ").strip()
        if v:
            self.s.cookie = v
            self.s.save()
            self.con.ok("auth", "cookie stored")

    def _ready(self) -> bool:
        if not self.s.has_cookie:
            self.con.err("cookie", "not set")
            return False
        if self.s.stale:
            try:
                hnjg_ensure_token(self.s, self.sess.props)
            except Exception as e:
                self.con.err("auth", str(e))
                return False
            self._new_sess()
        return bool(self.s.analytics_token)

    def _refresh(self) -> None:
        C = self.con
        C.info("replace stored cookie? [y/n]")
        if input(f"  {C.AC}>{C.X} ").strip().lower() in ("y", "yes"):
            C.info("enter new cf_clearance value")
            v = input(f"  {C.AC}>{C.X} cf_clearance: ").strip()
            if v:
                self.s.cookie = v
                C.ok("auth", "cookie updated")
        C.info("re-authenticating session...")
        try:
            self.s.fetched_at = 0
            hnjg_ensure_token(self.s, self.sess.props)
        except Exception as e:
            C.err("auth", str(e))
            return
        self._new_sess()
        self.s.save()
        C.ok("auth", "session refreshed")

    def _set_fp(self) -> None:
        C   = self.con
        uid = hnjg_uid(self.s.token)
        if not uid:
            C.err("fingerprint", "no valid token loaded")
            return
        if os.name != "nt":
            C.err("fingerprint", "requires windows")
            return
        C.info("enter executable path or process id")
        v = input(f"  {C.AC}>{C.X} path / pid: ").strip().strip('"')
        if not v:
            return
        pid  = int(v) if v.isdigit() else 0
        path = "" if pid else v
        if path and not Path(path).exists():
            C.err("fingerprint", f"path not found: {path}")
            return
        C.info("computing fingerprint...")
        try:
            fp = hnjg_gen_fp(uid, path=path, pid=pid)
        except Exception as e:
            C.err("fingerprint", str(e))
            return
        self.s.fingerprint = fp
        self.s.save()
        C.ok("fingerprint", f"bound  {len(fp)} bytes")

    def _select(self, count: int) -> list[hnjg_game]:
        avail   = {g.id for g in self.games}
        unused  = [g.id for g in self.games if g.id not in self.s.used_games]
        used    = [gid for gid in self.s.used_games if gid in avail]
        if len(unused) >= count:
            sel = unused[:count]
        else:
            sel = unused[:]
            if used:
                rem     = count - len(sel)
                rotated = used[rem:] + used[:rem]
                sel.extend(rotated[:rem])
        self.s.used_games = [g for g in self.s.used_games if g not in sel] + sel
        m = {g.id: g for g in self.games}
        return [m[gid] for gid in sel if gid in m]

    def _claim(self) -> None:
        if not self._ready():
            return
        C = self.con
        C.info(f"catalogue loaded  {C.AC}{len(self.games)}{C.X} titles available")
        raw_n = input(f"  {C.AC}>{C.X} number of games [leave blank for all]: ").strip()
        try:
            n = int(raw_n) if raw_n else len(self.games)
        except ValueError:
            C.err("input", "expected a number")
            return
        n = min(n, len(self.games))
        raw_h = input(f"  {C.AC}>{C.X} hours per title [default 1]: ").strip()
        try:
            h = float(raw_h) if raw_h else 1.0
        except ValueError:
            C.err("input", "expected a number")
            return
        sel = self._select(n)
        if not sel:
            C.err("session", "no titles selected")
            return
        ms = int(h * 3600 * 1000)
        C.info(f"submitting  {C.AC}{len(sel)}{C.X} titles  ×  {C.AC}{h:g}h{C.X}  =  {C.AC}{len(sel)*h:,.0f}h{C.X} total")
        C.rule()
        ok = hnjg_spoofer(self.client, C).run(sel, lambda g: self.client.build_session(g, ms))
        C.ok("session", f"{ok}/{len(sel)} titles submitted  —  {ok*h:,.0f}h logged")
        self.s.total_games += ok
        self.s.total_hours += ok * h
        self.s.save()
        C.rule()
        input(f"  {C.AC}>{C.X} press enter to return to menu")

    def start(self) -> None:
        C = self.con
        C.banner()
        if not self.s.has_token:
            self._prompt_token()
        else:
            C.ok("auth", "account token loaded")
        if not self.s.has_token:
            C.err("auth", "account token is required")
            return
        if not self.s.has_cookie:
            C.banner()
            self._prompt_cookie()
        else:
            C.ok("auth", "cookie loaded")
        if not self.s.has_cookie:
            C.err("auth", "cookie is required")
            return
        C.banner()
        C.info("fetching game catalogue...")
        self.games = hnjg_load_games()
        if not self.games:
            C.err("catalogue", "failed to retrieve game list")
            return
        C.ok("catalogue", f"{C.AC}{len(self.games)}{C.X} titles indexed")
        if not self.s.fingerprint:
            C.warn("fingerprint", "not configured — activity may appear unverified")
        C.info("establishing session...")
        self._new_sess()
        try:
            hnjg_ensure_token(self.s, self.sess.props)
        except Exception as e:
            C.err("auth", str(e))
            return
        C.ok("session", "ready")
        self._menu()

    def _menu(self) -> None:
        C = self.con
        while True:
            C.clear()
            C.banner()
            C.info(f"titles indexed  {C.AC}{len(self.games)}{C.X}   sessions submitted  {C.AC}{self.s.total_games}{C.X}   total hours  {C.AC}{self.s.total_hours:,.0f}h{C.X}")
            C.rule()
            print(f"  {C.AC}  01  {C.X}  {C.W}Submit Game Activity{C.X}  {C.GR}— log hours across selected titles{C.X}")
            print(f"  {C.AC}  02  {C.X}  {C.W}Refresh Session{C.X}      {C.GR}— update cookie and re-authenticate{C.X}")
            print(f"  {C.AC}  03  {C.X}  {C.W}Bind Fingerprint{C.X}     {C.GR}— tie activity to a local executable{C.X}")
            print(f"  {C.AC}  04  {C.X}  {C.W}Exit{C.X}")
            C.rule()
            ch = input(f"  {C.AC}>{C.X} select option: ").strip()
            if   ch == "1": self._claim()
            elif ch == "2": self._refresh()
            elif ch == "3": self._set_fp()
            elif ch in ("4", ""): break
            else: C.warn("input", "enter 1 – 4")


def hnjg_uid(token: str) -> str:
    try:
        first = token.split(".", 1)[0]
        pad   = "=" * (-len(first) % 4)
        return base64.b64decode(first + pad).decode()
    except Exception:
        return ""


if __name__ == "__main__":
    try:
        hnjg_app().start()
    except KeyboardInterrupt:
        print()
        hnjg_con().warn("session", "terminated by user")