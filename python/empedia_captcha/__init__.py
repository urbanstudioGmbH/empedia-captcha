"""EMPEDIAcaptcha-SDK für Python (≥ 3.8, nur Standardbibliothek).

    from empedia_captcha import EmpediaCaptcha
    captcha = EmpediaCaptcha.from_env()          # EMPEDIA_CAPTCHA_SITEKEY / _SECRET / _BASE
    r = captcha.verify(request.form.get("empedia-captcha-token"), "contact")
    if not r.success: abort(400)
    v = captcha.check({"ip": ip, "email": email, "message": text})   # Inhaltsprüfung (ab Paket „Pro“)

Das Secret gehört nur auf den Server. Dienst nicht erreichbar: `fail_open` entscheidet (Standard False = ablehnen).
"""
import hashlib
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from html import escape
from typing import Any, Dict, List, Optional

TOKEN_FIELD = "empedia-captcha-token"


def solve_pow(challenge_id: str, bits: int, limit: int = 200_000_000) -> int:
    """Proof-of-Work lösen: kleinste Zahl n, sodass SHA-256(id:n) mit `bits` Nullbits beginnt."""
    full, rest = divmod(bits, 8)
    prefix = b"\x00" * full
    for n in range(limit):
        h = hashlib.sha256(f"{challenge_id}:{n}".encode()).digest()
        if h.startswith(prefix) and (rest == 0 or (h[full] >> (8 - rest)) == 0):
            return n
    raise RuntimeError("pow-limit")


@dataclass
class VerifyResult:
    success: bool
    error_codes: List[str] = field(default_factory=list)
    unreachable: bool = False
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CheckResult:
    verdict: str  # allow | review | block
    risk: int = 0
    reasons: List[str] = field(default_factory=list)
    unreachable: bool = False
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_blocked(self) -> bool:
        return self.verdict == "block"

    @property
    def needs_review(self) -> bool:
        return self.verdict == "review"


class EmpediaCaptcha:
    def __init__(self, sitekey: str = "", secret: str = "", base: str = "", timeout: float = 5.0, fail_open: bool = False):
        self.sitekey, self.secret, self.base = sitekey, secret, base.rstrip("/")
        self.timeout, self.fail_open = timeout, fail_open

    @classmethod
    def from_env(cls, **options) -> "EmpediaCaptcha":
        env = os.environ
        return cls(env.get("EMPEDIA_CAPTCHA_SITEKEY", ""), env.get("EMPEDIA_CAPTCHA_SECRET", ""), env.get("EMPEDIA_CAPTCHA_BASE", ""), **options)

    def _post(self, path: str, body: Dict[str, Any], origin: str = "") -> Optional[Dict[str, Any]]:
        headers = {"Content-Type": "application/json"}
        if origin:
            headers["Origin"] = origin
        req = urllib.request.Request(self.base + path, data=json.dumps(body).encode(), headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout * (6 if origin else 1)) as r:
                j = json.loads(r.read().decode() or "null")
        except urllib.error.HTTPError as e:  # Fehlerantworten tragen ebenfalls JSON
            try:
                j = json.loads(e.read().decode() or "null")
            except Exception:
                return None
        except Exception:
            return None
        return j if isinstance(j, dict) else None

    def verify(self, token: Optional[str], action: Optional[str] = None) -> VerifyResult:
        token = (token or "").strip()
        if not token:
            # Ohne Token: ist das Kontingent der Domain erschöpft, bekommt das Widget keine Aufgabe mehr.
            # Wer „Anfragen durchlassen“ gewählt hat, sperrt dann keine Besucher aus.
            if self.fail_open and self.quota_exceeded():
                return VerifyResult(True, ["quota-exceeded"], True)
            return VerifyResult(False, ["missing-input-response"])
        body = {"secret": self.secret, "response": token}
        if action:
            body["action"] = action
        r = self._post("/captcha/v1/siteverify", body)
        if r is None:
            return VerifyResult(self.fail_open, ["service-unreachable"], True)
        return VerifyResult(r.get("success") is True, list(r.get("error-codes") or []), False, r)

    def quota_exceeded(self) -> bool:
        """Ist das Kontingent dieser Domain erschöpft? (Antwort des Dienstes, bei Fehlern False.)"""
        url = f"{self.base}/captcha/v1/status?sitekey={urllib.parse.quote(self.sitekey, safe='')}"
        try:
            with urllib.request.urlopen(url, timeout=self.timeout) as r:
                j = json.loads(r.read().decode() or "null")
        except Exception:
            return False
        return isinstance(j, dict) and j.get("quota_exceeded") is True

    def check(self, fields: Dict[str, Any], token: Optional[str] = None) -> CheckResult:
        body: Dict[str, Any] = {"sitekey": self.sitekey, "secret": self.secret, "fields": fields}
        if token:
            body["response"] = token
        r = self._post("/captcha/v1/check", body)
        if r is None or r.get("success") is not True:
            return CheckResult("allow" if self.fail_open else "review", 0, ["service-unreachable"], True, r or {})
        return CheckResult(r.get("verdict", "allow"), int(r.get("risk", 0)), list(r.get("reasons") or []), False, r)

    def get_token(self, action: str, origin: str = "", signals: Optional[Dict[str, Any]] = None) -> Optional[str]:
        """Token selbst beschaffen (Server-zu-Server, Skripte, mobile Backends) – ohne Browser. `origin` muss zu den Hosts der Domain
        passen (z. B. "https://shop.example.com"). Gedacht, um offene Endpunkte teuer zu machen, nicht um Menschen zu prüfen."""
        ch = self._post("/captcha/v1/challenge", {"sitekey": self.sitekey, "action": action}, origin)
        c = (ch or {}).get("challenge")
        if not c:
            return None
        nonce = solve_pow(c["id"], int(c["bits"]))
        sig = {"hp": "", "t": 2500, "wd": False, "hl": False, "ia": 0, **(signals or {})}
        r = self._post("/captcha/v1/solve", {"challenge": c, "nonce": str(nonce), "signals": sig}, origin)
        return (r or {}).get("token")

    def report(self, kind: str, fields: Dict[str, Any]) -> bool:
        r = self._post("/captcha/v1/report", {"sitekey": self.sitekey, "secret": self.secret, "kind": kind, "fields": fields})
        return bool(r and r.get("success") is True)

    def script_tag(self) -> str:
        return f'<script src="{escape(self.base)}/captcha/v1/widget.js" async defer></script>'

    def widget_tag(self, action: str = "form") -> str:
        return f'<div class="empedia-captcha" data-sitekey="{escape(self.sitekey)}" data-action="{escape(action)}"></div>'
