# Heavily inspired by Lighthouse: https://github.com/sigp/lighthouse/blob/693886b94176faa4cb450f024696cb69cda2fe58/Makefile
# &
# Reth: https://github.com/paradigmxyz/reth/blob/d00992e8112e05b7db1ba61d18a5083ef4aa7c1c/Makefile

.DEFAULT_GOAL := help

GIT_SHA ?= $(shell git rev-parse HEAD)
GIT_TAG ?= $(shell git describe --tags --abbrev=0 2>/dev/null || echo "latest")
BIN_DIR = "dist/bin"

CARGO_TARGET_DIR ?= target
DOCKER_IMAGE_NAME ?= ghcr.io/sovanetwork/sova-reth
PROFILE ?= release

# Extra flags for Cargo
CARGO_INSTALL_EXTRA_FLAGS ?=

##@ Help

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "Usage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Build

.PHONY: install
install: ## Build and install the sova-reth binary under `~/.cargo/bin`.
	cargo install --path bin/sova --bin sova-reth --force \
		$(CARGO_INSTALL_EXTRA_FLAGS)

.PHONY: build
build: ## Build the sova-reth binary into `target` directory.
	cargo build --bin sova-reth --release

# Builds the sova-reth binary natively.
build-native-%:
	cargo build --bin sova-reth --target $* --release

# The following commands use `cross` to build a cross-compile.
#
# These commands require that:
#
# - `cross` is installed (`cargo install cross`).
# - Docker is running.
# - The current user is in the `docker` group.
#
# The resulting binaries will be created in the `target/` directory.

# For aarch64, set the page size for jemalloc.
# When cross compiling, we must compile jemalloc with a large page size,
# otherwise it will use the current system's page size which may not work
# on other systems. JEMALLOC_SYS_WITH_LG_PAGE=16 tells jemalloc to use 64-KiB
# pages. See: https://github.com/paradigmxyz/reth/issues/6742
build-aarch64-unknown-linux-gnu: export JEMALLOC_SYS_WITH_LG_PAGE=16

# Note: The additional rustc compiler flags are for intrinsics needed by MDBX.
# See: https://github.com/cross-rs/cross/wiki/FAQ#undefined-reference-with-build-std
build-%:
	RUSTFLAGS="-C link-arg=-lgcc -Clink-arg=-static-libgcc" \
		cross build --bin sova-reth --target $* --release

# Unfortunately we can't easily use cross to build for Darwin because of licensing issues.
# If we wanted to, we would need to build a custom Docker image with the SDK available.
#
# Note: You must set `SDKROOT` and `MACOSX_DEPLOYMENT_TARGET`. These can be found using `xcrun`.
#
# `SDKROOT=$(xcrun -sdk macosx --show-sdk-path) MACOSX_DEPLOYMENT_TARGET=$(xcrun -sdk macosx --show-sdk-platform-version)`
build-x86_64-apple-darwin:
	$(MAKE) build-native-x86_64-apple-darwin
build-aarch64-apple-darwin:
	$(MAKE) build-native-aarch64-apple-darwin

# Create a `.tar.gz` containing a binary for a specific target.
define tarball_release_binary
	cp $(CARGO_TARGET_DIR)/$(1)/$(PROFILE)/$(2) $(BIN_DIR)/$(2)
	cd $(BIN_DIR) && \
		tar -czf sova-reth-$(GIT_TAG)-$(1)$(3).tar.gz $(2) && \
		rm $(2)
endef

# The current git tag will be used as the version in the output file names. You
# will likely need to use `git tag` and create a semver tag (e.g., `v0.2.3`).
#
# Note: This excludes macOS tarballs because of SDK licensing issues.
.PHONY: build-release-tarballs
build-release-tarballs: ## Create a series of `.tar.gz` files in the BIN_DIR directory, each containing a `sova-reth` binary for a different target.
	[ -d $(BIN_DIR) ] || mkdir -p $(BIN_DIR)
	$(MAKE) build-x86_64-unknown-linux-gnu
	$(call tarball_release_binary,"x86_64-unknown-linux-gnu","sova-reth","")
	$(MAKE) build-aarch64-unknown-linux-gnu
	$(call tarball_release_binary,"aarch64-unknown-linux-gnu","sova-reth","")

##@ Housekeeping

.PHONY: fmt
fmt: ## Check formatting
	cargo fmt --all --check

.PHONY: clippy
clippy: ## Run clippy
	cargo clippy -- -D warnings

.PHONY: clean-data
clean-data: ## Remove the data directory
	rm -rf ./data

.PHONY: check-udeps
check-udeps: ## Check for unused dependencies in the crate graph
	cargo +nightly udeps --workspace --all-features --all-targets

##@ Docker

# Note: This requires a buildx builder with emulation support. For example:
#
# `docker run --privileged --rm tonistiigi/binfmt --install amd64,arm64`
# `docker buildx create --use --driver docker-container --name cross-builder`
.PHONY: docker-build-push
docker-build-push: ## Build and push a cross-arch Docker image tagged with the latest git tag.
	$(call docker_build_push,$(GIT_TAG),$(GIT_TAG))

# Note: This requires a buildx builder with emulation support. For example:
#
# `docker run --privileged --rm tonistiigi/binfmt --install amd64,arm64`
# `docker buildx create --use --driver docker-container --name cross-builder`
.PHONY: docker-build-push-git-sha
docker-build-push-git-sha: ## Build and push a cross-arch Docker image tagged with the latest git sha.
	$(call docker_build_push,$(GIT_SHA),$(GIT_SHA))

# Note: This requires a buildx builder with emulation support. For example:
#
# `docker run --privileged --rm tonistiigi/binfmt --install amd64,arm64`
# `docker buildx create --use --driver docker-container --name cross-builder`
.PHONY: docker-build-push-latest
docker-build-push-latest: ## Build and push a cross-arch Docker image tagged with the latest git tag and `latest`.
	$(call docker_build_push,$(GIT_TAG),latest)

# Note: This requires a buildx builder with emulation support. For example:
#
# `docker run --privileged --rm tonistiigi/binfmt --install amd64,arm64`
# `docker buildx create --use --name cross-builder`
.PHONY: docker-build-push-nightly
docker-build-push-nightly: ## Build and push cross-arch Docker image tagged with the latest git tag with a `-nightly` suffix, and `latest-nightly`.
	$(call docker_build_push,nightly,nightly)

# Create a cross-arch Docker image with the given tags and push it
define docker_build_push
	$(MAKE) build-x86_64-unknown-linux-gnu
	mkdir -p $(BIN_DIR)/amd64
	cp $(CARGO_TARGET_DIR)/x86_64-unknown-linux-gnu/$(PROFILE)/sova-reth $(BIN_DIR)/amd64/sova-reth

	$(MAKE) build-aarch64-unknown-linux-gnu
	mkdir -p $(BIN_DIR)/arm64
	cp $(CARGO_TARGET_DIR)/aarch64-unknown-linux-gnu/$(PROFILE)/sova-reth $(BIN_DIR)/arm64/sova-reth

	docker buildx build --file ./Dockerfile.cross . \
		--platform linux/amd64,linux/arm64 \
		--tag $(DOCKER_IMAGE_NAME):$(1) \
		--tag $(DOCKER_IMAGE_NAME):$(2) \
		--provenance=false \
		--push
endef

##@ Run

.PHONY: run-sova-regtest
run-sova-regtest: ## Compile and run sova-reth in dev mode using bitcoin regtest and accompanying services
	if [ "$(clean)" = "clean" ]; then $(MAKE) clean-data; fi
	$(MAKE) build && ./target/release/sova-reth node \
	--chain dev \
	--btc-network "regtest" \
	--network-url "http://127.0.0.1" \
	--btc-rpc-username "user" \
	--btc-rpc-password "password" \
	--network-signing-url "http://127.0.0.1:5555" \
	--network-utxo-url "http://127.0.0.1:5557" \
	--sentinel-url "http://[::1]:50051" \
	--sentinel-confirmation-threshold 6 \
	--http \
	--http.addr "127.0.0.1" \
	--http.port 8545 \
	--ws \
	--ws.addr "127.0.0.1" \
	--ws.port 8546 \
	--http.api all \
	--authrpc.addr "127.0.0.1" \
	--authrpc.port 8551 \
	--datadir ./data \
	--log.stdout.filter debug \
	--dev

.PHONY: run-sova-mainnet-regtest
run-sova-mainnet-regtest: ## Compile and run sova-reth in mainnet mode using bitcoin regtest and accompanying services
	if [ "$(clean)" = "clean" ]; then $(MAKE) clean-data; fi
	$(MAKE) build && ./target/release/sova-reth node \
	--chain sova \
	--btc-network "regtest" \
	--network-url "http://127.0.0.1" \
	--btc-rpc-username "user" \
	--btc-rpc-password "password" \
	--network-signing-url "http://127.0.0.1:5555" \
	--network-utxo-url "http://127.0.0.1:5557" \
	--sentinel-url "http://[::1]:50051" \
	--sentinel-confirmation-threshold 6 \
	--addr "0.0.0.0" \
	--port 30303 \
	--discovery.addr "0.0.0.0" \
	--discovery.port 30303 \
	--http \
	--http.addr "127.0.0.1" \
	--http.port 8545 \
	--ws \
	--ws.addr "127.0.0.1" \
	--ws.port 8546 \
	--http.api all \
	--authrpc.addr "127.0.0.1" \
	--authrpc.port 8551 \
	--datadir ./data \
	--log.stdout.filter info