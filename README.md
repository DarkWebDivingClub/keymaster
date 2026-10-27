# club.dwdc.keymaster

The desktop side of KeyMaster: a JSON-RPC daemon over a Unix domain
socket that manages identities and performs key operations, plus a thin
CLI client. Private keys stay on the phone; the daemon brokers requests
to it and serves SSH, GPG and Nostr agents on the desktop.

The KeyVault, KeyMaster, Avatar and host-service architecture is
described in [doc/ARCHITECTURE.md](doc/ARCHITECTURE.md).

## Modules

| Module | Produces | Purpose |
|---|---|---|
| `club.dwdc.keymaster.core` | library | Identity CRUD, realms, service handlers |
| `club.dwdc.keymaster.desktop` | library | File-backed stores, approval handlers, policy |
| `club.dwdc.keymaster.daemon` | `km-daemon.jar` | Unix socket JSON-RPC daemon |
| `club.dwdc.keymaster.cli` | `km-cli.jar` | JSON-RPC client (`km-cli`) |

## Prerequisites

- **JDK 21.** Required, and it must be explicit: JDK 25 is the default
  `java` on current Ubuntu and the build targets 21.
- Maven 3.9+

```sh
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
```

## Build

KeyMaster depends on `keyvault`, which depends on a patched `bitcoinj`
fork. Neither is published to a public repository, so build the chain in
this order — each step installs into `~/.m2`:

| Order | Repo | Command | Documented in |
|---|---|---|---|
| 1 | [bitcoinj](https://github.com/dukeh3/bitcoinj) (fork) | `./gradlew publishToMavenLocal` | its `FORK.md` |
| 2 | [keyvault](https://github.com/DarkWebDivingClub/keyvault) | `mvn install` | its `README.md` |
| 3 | this repo | `mvn install` | here |

```sh
git clone https://github.com/DarkWebDivingClub/keymaster.git
cd keymaster
mvn install
```

`mvn install` runs the unit tests. To skip them, add `-DskipTests`.

The internal Maven repository is `https://maven.398ja.xyz/releases`.
`keyvault` is not published there yet, so step 2 is not optional.

## Tests

`mvn install` covers the unit tests. The mandatory end-to-end gate lives
in a separate repository and runs against the installed artifacts:

```sh
cd ~/git/keymaster-e2e-test && mvn test
```

See [keymaster-e2e-test](https://github.com/DarkWebDivingClub/keymaster-e2e-test).

## Packaging

The Debian packaging is **not on `master`** — it lives on the
`packaging/ubuntu/resolute` branch, which carries `debian/`. Building
the package from a `master` checkout cannot work.

```sh
git checkout packaging/ubuntu/resolute
git merge master
dpkg-buildpackage -b -us -uc
```

That produces `keymaster-desktop`, which installs `km-daemon` and
`km-cli` plus a systemd user service. See
`~/git/net.h3/doc/wow/branching-and-versioning.md` for the branch model.

## Further reading

| Document | Topic |
|---|---|
| [doc/ARCHITECTURE.md](doc/ARCHITECTURE.md) | Overall architecture |
| [doc/SSH.md](doc/SSH.md) | SSH agent and key export |
| [doc/GPG.md](doc/GPG.md) | OpenPGP certificates and the GPG agent |
| [doc/NOSTR.md](doc/NOSTR.md) | Nostr signing and transport |
| [doc/BITCOIN.md](doc/BITCOIN.md) | Bitcoin key derivation |
| [doc/PKCS11.md](doc/PKCS11.md) | PKCS#11 exploration |
| [doc/service-handler-design.md](doc/service-handler-design.md) | Service handler design |

## License

This project is licensed under the GNU General Public License v3.0 only
(`GPL-3.0-only`), as declared in `pom.xml`.
