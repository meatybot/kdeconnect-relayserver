<!--
SPDX-FileCopyrightText: 2026 meatybot <avatarcc@tuta.io>
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Releasing

Pushing a tag `v<version>` runs `.github/workflows/release.yml`, which does this:

1. Runs the CI workflow: build and tests on Ubuntu 24.04, Debian 13 and Arch Linux, a container
   smoke test and the REUSE license check. A failure stops the release.
2. Builds the server on Ubuntu 24.04 for x86_64 and aarch64 and runs the tests again on each.
   Ubuntu 24.04 is the oldest supported distribution, so the binaries run there and on newer
   systems with Qt 6.4 or later.
3. Builds the container image for linux/amd64 and linux/arm64 and pushes it to
   `ghcr.io/meatybot/kdeconnect-relayserver` with the tags `<version>`, `<major>.<minor>` and
   `latest`.
4. Creates the GitHub release with generated notes and attaches the two binaries, the systemd
   unit, a source tarball made by `git archive` and `SHA256SUMS`.

## Versioning

Versions follow [semantic versioning](https://semver.org/). The version lives in `project()` in
`CMakeLists.txt`, and the release workflow refuses a tag that does not match it.

The relay protocol has its own version number (`RelayProtocol::Version`, currently 1). Bump the
major version of the server when you bump the protocol version, because existing clients cannot
talk to the new server.

## Making a release

1. Update the version in `CMakeLists.txt` and commit it to `master`.
2. Make sure CI is green on that commit.
3. Tag and push:

   ```sh
   git tag -a v1.1.0 -m "Short summary of the release"
   git push origin v1.1.0
   ```

4. Watch the run:

   ```sh
   gh run list -R meatybot/kdeconnect-relayserver -w Release -L 1
   gh run watch <run-id> -R meatybot/kdeconnect-relayserver --exit-status
   ```

5. Check the release:

   ```sh
   gh release download v1.1.0 -R meatybot/kdeconnect-relayserver -D /tmp/rel
   cd /tmp/rel && sha256sum -c SHA256SUMS
   docker run --rm ghcr.io/meatybot/kdeconnect-relayserver:1.1.0 --version
   ```

The run takes about 10 minutes, most of it the arm64 image build under emulation.

## Re-running a failed release

Fix the problem on `master`, then either:

- rebuild the existing tag without moving it: run the Release workflow from the Actions tab with
  **Run workflow** and enter the tag, or `gh workflow run Release -R meatybot/kdeconnect-relayserver -f tag=<tag>`.
  The publish step reuses an existing release and replaces its assets.
- move the tag to the fixed commit with `git tag -f -a <tag> -m "..."` and
  `git push -f origin <tag>`. Only do this when nobody has downloaded the release yet. Otherwise
  release the next patch version.

## Updating the desktop client

kdeconnect-kde includes this repository as the git submodule `3rdparty/kdeconnect-relayserver`
and builds its relay tests against it. After a release that changes `src/relayprotocol.*` or the
server behaviour, bump the submodule there:

```sh
cd kdeconnect-kde
git -C 3rdparty/kdeconnect-relayserver fetch --tags
git -C 3rdparty/kdeconnect-relayserver checkout v1.1.0
git commit -am "Bump kdeconnect-relayserver to v1.1.0"
```
