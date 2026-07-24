# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [0.1.1] — 2026-07-24

### Added

- `repository`, `homepage`, `bugs` and `author` metadata for the npm page.
- Refined npm keywords for discoverability.

### Changed

- `git`-based installs now build `dist/` automatically via a `prepare` script.

## [0.1.0] — 2026-07-24

### Added

- Initial release. Runtime supply-chain tripwire for Node.js dependencies.
- Capability interceptors: `fs.read`, `fs.write`, `net.connect`
  (http/https/fetch), `process.spawn`, `env.read`, `os.info`.
- `observe` and `enforce` modes; per-package declarative policy
  (`dephawk.config.js`) with host/path globs and env allowlists.
- Stack-trace attribution to the exact package (scoped + nested aware).
- Console report + self-contained shareable `.dephawk/report.html`.
- `dephawk run <cmd>` CLI and `--import dephawk/register` entrypoint.
- Hexagonal architecture, zero runtime dependencies, ≥90% core coverage.

[0.1.1]: https://github.com/kellendir/dephawk/releases/tag/v0.1.1
[0.1.0]: https://github.com/kellendir/dephawk/releases/tag/v0.1.0
