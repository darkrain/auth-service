# Releases

The repository uses Semantic Versioning. `VERSION` is the release version.
Develop each release on `release/<version>` and tag its accepted source as
`v<version>`. Never move a published tag or replace published release assets.
Patch versions fix compatible behavior; minor versions add compatible features;
major versions change the supported contract incompatibly.

Build release artifacts only from the clean tagged tree. Consumers pin an exact
release version; checksums and image digests verify its immutable contents.
Production runtime configuration and secrets are not release artifacts.
