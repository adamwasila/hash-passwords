# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project adheres to Semantic Versioning.

## [Unreleased]

### Changed

- No unreleased changes documented yet.

## [0.1.0] - 2026-06-04

### Added

- Firefox extension popup for generating site-specific passwords from a master password.
- Domain extraction and normalization from the active tab URL.
- Two hashing modes:
  - Legacy MD5-compatible mode aligned with PwdHash behavior.
  - PBKDF2-SHA256 mode for stronger hashing (not compatible with original PwdHash output).
- Hash identicon preview and copy-to-clipboard action in popup.
- Session-oriented state behavior that clears sensitive values on domain switch and timeout.
- CLI fallback tool in `cli/` for password generation outside the browser context. Not a part of the extension.
