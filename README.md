# puddle

Rubber ducks welcome.

puddle runs each devcontainer workspace in its own microVM on Windows, with puddle's own proxy as the
only way out of the VM. Outbound connections go to domains you allowed, per workspace or globally;
anything else waits in an approval inbox until you allow or deny it. It is a native Windows Rust
program with a Tauri desktop app, and builds on
[microsandbox](https://github.com/superradcompany/microsandbox) for the microVMs.

The idea follows [Huddle](https://github.com/infosupport/huddle); puddle is written from scratch and
shares no code with it.

**Status:** pre-implementation. There is no code yet.

## Branches

- `develop`: where work happens. Open pull requests against it.
- `main`: released versions only.

## Development

No code yet. Build and check commands go here once there is something to build.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Contributions need a signed [CLA](CLA.md). Security
problems: [SECURITY.md](SECURITY.md).

## Licence

Copyright (C) 2026 Tijs van Kampen and contributors.

puddle is free software under the GNU General Public License, version 3 or (at your option) any later
version: see [LICENSE](LICENSE). SPDX: `GPL-3.0-or-later`. Bundled third-party components keep
their own licences.
