## Releases

### Release cadence

**No regular release cadence this is experimental software with ongoing research and development**.

### Versioning

Refer to the [specs](./specs/) folder for specifics about incremental upgrades for each version. Each version upgrade is not completed in one PR. Once a version spec is implemented, completed, and tested a separate PR should be submitted to update the versioning accross the repository. Finally, tag the final commit on Github with its version name.

### Details

When a new version is released all docker and docker-compose files should be updated to the latest version. After docker is updated, internal node infrastruture should be restarted using the new version release.

### PRs

All branches should be as descriptive as possible. PRs should have a general description and a reference to any tests that were run which developing the changes. Please run `cargo fmt` and `cargo clippy` prior to submitting a PR else github CI will fail.
