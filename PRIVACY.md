# Privacy Policy

Last updated: 2026-06-03

This privacy policy describes how the Hash Passwords Firefox extension handles data.

## Summary

- Password hashing is performed locally in the extension popup.
- The extension supports two local hashing modes: original MD5-compatible mode and PBKDF2-SHA256 mode.
- The extension does not send your passwords or generated hashes to any remote server.
- The extension does not include analytics, tracking, ads, or telemetry.

## Data Processed

The extension processes the following data to provide its functionality:

- Active tab URL (read-only): used to prefill and normalize the site/domain field.
- Site/domain value entered by the user: used as hashing input.
- Password entered by the user: used as hashing input.
- Generated hash: displayed in the popup (obfuscated by default) and optionally copied to clipboard on user action.
- Hash mode preference (SHA256 toggle on/off): stored to keep your selected algorithm mode across browser restarts.

## Permissions and Why They Are Used

- `tabs`: required to read the currently active tab URL so the site/domain can be prefilled.
- `storage`: required for:
	- session popup state (`storage.session`) so the password can remain available while the browser session is running,
	- persistent algorithm mode preference (`storage.local`) so the SHA256 toggle state survives browser restarts.

## Storage and Retention

- Password value is stored only in extension session storage (`storage.session`).
- Session storage is non-persistent and is cleared when the browser is restarted.
- The extension stores only the algorithm mode preference (boolean SHA256 toggle state) in persistent extension storage (`storage.local`).
- Passwords and generated hashes are not intentionally stored in persistent extension storage (`storage.local` or `storage.sync`).

## Clipboard

- The generated hash is copied to clipboard only when the user clicks the copy button.
- Clipboard writes are user-initiated.

## Network and Third Parties

- The extension does not make network requests for hashing operations.
- The extension does not share data with third parties.

## Hashing Algorithms

- Original mode uses an MD5-compatible approach aligned with PwdHash behavior.
- Strong mode uses PBKDF2-SHA256.
- Both modes run locally in the extension popup.

## Security Notes

- The extension is a local password transformation tool and does not manage website login sessions.
- Keep your device secure and use browser/profile protections (lock screen, profile security) appropriate to your environment.

## Changes to This Policy

If data handling changes, this file will be updated accordingly.
