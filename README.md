
Spoofs game activity hours on Discord by submitting game session events to Discord's analytics endpoint.

---

## Requirements

- Python 3.10+
- Windows *(fingerprint feature only — core functionality is cross-platform)*
- A valid Discord account token
- A valid Discord `cf_clearance` cookie

---

## Usage

```
python hnjg.py
```

No external dependencies required.

On first run, the tool will prompt for your token and cookie. Both are saved locally and reused on subsequent runs.

---

## Menu

| Option | Description |
|--------|-------------|
| `1` — Claim games | Select the number of games and hours per game to submit |
| `2` — Refresh auth | Update the cookie or re-fetch the analytics token |
| `3` — Set fingerprint | Bind activity to a real executable *(optional, Windows only)* |
| `4` — Exit | Close the application |

---

## Obtaining the Cookie

1. Open Discord in a browser.
2. Open DevTools → **Application** → **Cookies** → `discord.com`
3. Copy the value of `cf_clearance`.

---

## Notes

- The token and cookie are stored in plaintext within `hnjg_state.json`. Ensure this file is excluded from version control.
- HTTP `401` or `403` responses indicate expired credentials. Use **option 2** from the menu to refresh.
