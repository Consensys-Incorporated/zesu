SPEC_TEST_DIR = spec-tests

ZIG_BUILD_CMD = zig build

ARGS ?=

UNAME_S := $(shell uname -s)

# blst and mcl are built from source at these commits. mcl: tag v4.20. blst has
# had no release since v0.3.17 and CI has been building master, so this is the
# newest master commit at least 7 days old; move to the next release when it ships.
BLST_COMMIT = 4f72b303888fd02d402a786eeb3d35ac38263ac2
MCL_COMMIT = 828c95660fdc9bffd351f069b2c4c20beebe2060

.PHONY: install-deps install-brew-deps install-apt-deps check-deps check-os \
        spec-tests state-tests blockchain-tests fetch-fixtures

check-deps:
	@echo "Checking dependencies..."
	@command -v zig >/dev/null 2>&1 || (echo "zig not found" && exit 1)
	@(pkg-config --exists libsecp256k1 2>/dev/null || \
	  test -f /opt/homebrew/lib/libsecp256k1.a || \
	  test -f /opt/homebrew/lib/libsecp256k1.dylib || \
	  test -f /usr/local/lib/libsecp256k1.a || \
	  test -f /usr/lib/libsecp256k1.so || \
	  test -f /usr/lib/x86_64-linux-gnu/libsecp256k1.so) || \
	  (echo "libsecp256k1 not found" && exit 1)
	@(test -f /opt/homebrew/lib/libblst.a || \
	  test -f /usr/local/lib/libblst.a || \
	  test -f /usr/lib/libblst.a) || \
	  (echo "libblst not found" && exit 1)
	@(test -f /opt/homebrew/lib/libmcl.a || \
	  test -f /opt/homebrew/lib/libmcl.dylib || \
	  test -f /usr/local/lib/libmcl.so || \
	  test -f /usr/local/lib/libmcl.a || \
	  test -f /usr/lib/libmcl.a) || \
	  (echo "libmcl not found" && exit 1)
	@echo "All dependencies satisfied."

install-deps: check-os
	@if $(MAKE) check-deps --no-print-directory >/dev/null 2>&1; then \
		echo "All dependencies already satisfied, skipping installation."; \
	else \
		if [ "$(UNAME_S)" = "Darwin" ]; then \
			$(MAKE) install-brew-deps --no-print-directory; \
		elif command -v apt-get >/dev/null 2>&1; then \
			$(MAKE) install-apt-deps --no-print-directory; \
		else \
			echo "Unsupported Linux package manager. Please install dependencies manually."; \
			exit 1; \
		fi \
	fi

check-os:
	@echo "Detected OS: $(UNAME_S)"

install-brew-deps:
	@echo "Installing dependencies via Homebrew..."
	@command -v brew >/dev/null 2>&1 || (echo "Homebrew not found: https://brew.sh" && exit 1)
	brew install secp256k1 openssl || true
	@if [ ! -f /opt/homebrew/lib/libblst.a ] && [ ! -f /usr/local/lib/libblst.a ]; then \
		echo "Building blst from source..."; \
		if [ -d /tmp/blst ]; then git -C /tmp/blst fetch --quiet origin; else git clone --quiet https://github.com/supranational/blst.git /tmp/blst; fi; \
		git -C /tmp/blst checkout --quiet $(BLST_COMMIT) || exit 1; \
		cd /tmp/blst && ./build.sh; \
		sudo cp libblst.a /opt/homebrew/lib/ 2>/dev/null || cp libblst.a /usr/local/lib/; \
		sudo cp bindings/blst.h bindings/blst_aux.h /opt/homebrew/include/ 2>/dev/null || cp bindings/blst.h bindings/blst_aux.h /usr/local/include/; \
	else echo "blst already installed"; fi
	@if [ ! -f /opt/homebrew/lib/libmcl.a ] && [ ! -f /usr/local/lib/libmcl.a ]; then \
		echo "Building mcl from source..."; \
		if [ -d /tmp/mcl ]; then git -C /tmp/mcl fetch --quiet origin; else git clone --quiet https://github.com/herumi/mcl.git /tmp/mcl; fi; \
		git -C /tmp/mcl checkout --quiet $(MCL_COMMIT) || exit 1; \
		cd /tmp/mcl && make -j$$(sysctl -n hw.ncpu 2>/dev/null || echo 4); \
		sudo cp lib/libmcl.a /opt/homebrew/lib/ 2>/dev/null || cp lib/libmcl.a /usr/local/lib/; \
		sudo cp -r include/mcl /opt/homebrew/include/ 2>/dev/null || cp -r include/mcl /usr/local/include/; \
	else echo "mcl already installed"; fi

install-apt-deps:
	@echo "Installing dependencies via apt..."
	sudo apt-get update -qq
	sudo apt-get install -y libsecp256k1-dev libssl-dev build-essential git cmake
	@if [ ! -f /usr/local/lib/libblst.a ] && [ ! -f /usr/lib/libblst.a ]; then \
		echo "Building blst from source..."; \
		if [ -d /tmp/blst ]; then git -C /tmp/blst fetch --quiet origin; else git clone --quiet https://github.com/supranational/blst.git /tmp/blst; fi; \
		git -C /tmp/blst checkout --quiet $(BLST_COMMIT) || exit 1; \
		cd /tmp/blst && ./build.sh; \
		sudo cp libblst.a /usr/local/lib/; \
		sudo cp bindings/blst.h bindings/blst_aux.h /usr/local/include/; \
	else echo "blst already installed"; fi
	@if [ ! -f /usr/local/lib/libmcl.so ] && [ ! -f /usr/lib/libmcl.so ]; then \
		echo "Building mcl from source..."; \
		if [ -d /tmp/mcl ]; then git -C /tmp/mcl fetch --quiet origin; else git clone --quiet https://github.com/herumi/mcl.git /tmp/mcl; fi; \
		git -C /tmp/mcl checkout --quiet $(MCL_COMMIT) || exit 1; \
		cd /tmp/mcl && make -j$$(nproc 2>/dev/null || echo 4); \
		sudo rm -f /usr/local/lib/libmcl.a; \
		sudo cp lib/libmcl.so /usr/local/lib/; \
		sudo cp -r include/mcl /usr/local/include/; \
		sudo ldconfig; \
	else echo "mcl already installed"; fi

fetch-fixtures:
	@$(ZIG_BUILD_CMD) fetch-fixtures

# Build and run all spec tests (state + blockchain)
spec-tests: fetch-fixtures
	@$(ZIG_BUILD_CMD) install
	@./zig-out/bin/spec-test-runner \
		--fixtures $(SPEC_TEST_DIR)/fixtures/state_tests \
		$(ARGS)
	@./zig-out/bin/blockchain-test-runner \
		--fixtures $(SPEC_TEST_DIR)/fixtures/blockchain_tests \
		$(ARGS)

# State tests only
state-tests: fetch-fixtures
	@$(ZIG_BUILD_CMD) install
	@./zig-out/bin/spec-test-runner --fixtures $(SPEC_TEST_DIR)/fixtures/state_tests $(ARGS)

# Blockchain tests only
blockchain-tests: fetch-fixtures
	@$(ZIG_BUILD_CMD) install
	@./zig-out/bin/blockchain-test-runner --fixtures $(SPEC_TEST_DIR)/fixtures/blockchain_tests $(ARGS)
