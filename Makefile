# Targets:
#   make bpf         - compile bpf/aidt.bpf.o (default)
#   make skel        - generate bpf/aidt.skel.rs and bpf/aidt.skel.h
#   make all         - bpf + skel
#   make verify      - load the program and dump verifier output (needs sudo)
#   make inspect     - llvm-objdump + bpftool btf dump on the built .o
#   make sections    - show ELF sections of the built .o
#   make clean       - remove generated artifacts
#   make vmlinux     - regenerate bpf/vmlinux.h from the running kernel
#
# Requirements (install once on the build host):
#   clang >= 10, llvm        (apt: clang llvm)
#   libbpf headers           (apt: libbpf-dev)   - for <bpf/bpf_helpers.h>
#   bpftool                  (apt: linux-tools-common, or build from source)
#   libbpf-cargo binary      (cargo install libbpf-cargo) - for Rust skeleton
#

CLANG       ?= clang
LLVM_STRIP  ?= llvm-strip
BPFTOOL     ?= bpftool
LIBBPF_CARGO ?= cargo libbpf

BPF_DIR      := bpf
BPF_SRC      := $(BPF_DIR)/aidt.bpf.c
BPF_HDRS     := $(BPF_DIR)/aidt.bpf.h $(BPF_DIR)/vmlinux.h
BPF_OBJ      := $(BPF_DIR)/aidt.bpf.o
SKEL_RS      := $(BPF_DIR)/aidt.skel.rs
SKEL_H       := $(BPF_DIR)/aidt.skel.h

UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),x86_64)
    ARCH       := x86
    BPF_ARCH_D := -D__TARGET_ARCH_x86
else ifeq ($(UNAME_M),aarch64)
    ARCH       := arm64
    BPF_ARCH_D := -D__TARGET_ARCH_arm64
else ifeq ($(UNAME_M),arm64)
    ARCH       := arm64
    BPF_ARCH_D := -D__TARGET_ARCH_arm64
else
    $(error Unsupported architecture: $(UNAME_M))
endif

BPF_CFLAGS := \
    -target bpf \
    -g -O2 \
    -Wall -Werror \
    -mcpu=v3 \
    -fno-stack-protector \
    $(BPF_ARCH_D) \
    -I$(BPF_DIR) \
    -I/usr/include

.PHONY: all build compile bpf skel clean verify inspect sections vmlinux help

all: compile

build:
	@echo "  DOCKER BUILD ai-proc-detector-builder"
	@docker build -t ai-proc-detector-builder -f docker/Dockerfile.build .

compile:
	@echo "  DOCKER RUN make vmlinux bpf skel"
	@mkdir -p .cargo-registry
	@docker run --rm -v $(PWD):/workspace -v $(PWD)/.cargo-registry:/usr/local/cargo/registry -v /sys/kernel/btf/vmlinux:/sys/kernel/btf/vmlinux:ro ai-proc-detector-builder make vmlinux bpf skel  userspace

userspace:
	@cargo build --release

test:
	@echo "  CARGO TEST"
	@cargo test

bpf: $(BPF_OBJ)

skel: $(SKEL_RS)

$(BPF_DIR)/vmlinux.h:
	@test -r /sys/kernel/btf/vmlinux || { \
	    echo "ERROR: /sys/kernel/btf/vmlinux not found/readable." >&2; \
	    echo "Your kernel may not have BTF enabled (CONFIG_DEBUG_INFO_BTF)." >&2; \
	    exit 1; \
	}
	@echo "  VMLINUX $@"
	@$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

vmlinux: $(BPF_DIR)/vmlinux.h

$(BPF_OBJ): $(BPF_SRC) $(BPF_HDRS)
	@echo "  CLANG   $@"
	@$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "  STRIP   $@   (debug only, keep BTF)"
	@$(LLVM_STRIP) -g $@
	@$(BPFTOOL) btf dump file $@ format c > /dev/null \
	    || { echo "ERROR: $@ has no BTF - did clang -g get dropped?" >&2; exit 1; }
	@echo "  OK      $@ ($$(stat -c %s $@) bytes)"

$(SKEL_RS): $(BPF_OBJ)
	@echo "  SKEL-RS $@"
	@echo "  (using $(LIBBPF_CARGO) gen)"
	@$(LIBBPF_CARGO) gen --object $(BPF_OBJ) > $@.tmp
	@sed -i '/let opts = if self.obj_builder.ne(&ObjectBuilder::default()) {/,/};/c\            let opts = self.obj_builder.as_libbpf_object().as_ptr().cast_const();' $@.tmp
	@sed -i '/use libbpf_rs::ObjectBuilder;/d' $@.tmp
	@mv $@.tmp $@

verify: $(BPF_OBJ)
	@echo "  VERIFY  $(BPF_OBJ)"
	@sudo $(BPFTOOL) prog loadall $(BPF_OBJ) /sys/fs/bpf/aidt-verify-tmp \
	    autoattach 2>&1 | tee /tmp/aidt-verifier.log; \
	    rm -rf /sys/fs/bpf/aidt-verify-tmp; \
	    echo "  log -> /tmp/aidt-verifier.log"

inspect: $(BPF_OBJ)
	@echo "=== llvm-objdump -d (BPF instructions) ==="
	@llvm-objdump -d $(BPF_OBJ) | head -80
	@echo ""
	@echo "=== bpftool btf dump (CO-RE types referenced) ==="
	@$(BPFTOOL) btf dump file $(BPF_OBJ) | head -40
	@echo ""
	@echo "=== llvm-readelf --sections ==="
	@llvm-readelf --sections $(BPF_OBJ) | grep -E '(Name|tracepoint|\.maps|license)'

sections: $(BPF_OBJ)
	@llvm-readelf --sections $(BPF_OBJ)

clean:
	@rm -f $(BPF_OBJ) $(SKEL_RS) $(SKEL_H) /tmp/aidt-verifier.log
	@echo "  CLEAN"

run:

help:
	@grep -E '^[a-z-]+:.*?##' $(MAKEFILE_LIST) || \
	    awk '/^# {2}make/' $(MAKEFILE_LIST)
