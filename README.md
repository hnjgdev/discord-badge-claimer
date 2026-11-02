# hnjg

Spoof game hours on Discord. Sends fake game activity events to Discord's
analytics endpoint using your account token.

---

## requirements

- Python 3.10+
- Windows (for fingerprint feature — rest works anywhere)
- Discord token
- Discord `cf_clearance` cookie

---

## run

```
python hnjg.py
```

No installs needed.

---

## usage

First run asks for your token and cookie — both saved locally for next time.

Menu options:

- **1 — claim games** — pick how many games and how many hours each, fires it
- **2 — refresh auth** — update cookie or re-fetch token
- **3 — set fingerprint** — ties activity to a real `.exe` (optional, Windows only)
- **4 — exit**

---

## getting your cookie

Open Discord in browser → DevTools → Application → Cookies → `discord.com`
→ copy the `cf_clearance` value.

---

## notes

- Token and cookie are saved plaintext in `hnjg_state.json` — don't commit it.
- If you get 401/403, refresh your token or cookie from the menu.
