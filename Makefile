# fxstore — a content-addressed build store for fixpoint-linux.
#
# Builds the fxstore CLI (fxstore) from:
#   - this repo's source: fxstore/{main,packageset,derivation,closure,store,build}.c
#   - the datalog-dafsa engine + vendored dafsa (git submodule, vendor/datalog-dafsa)
#   - the dhall-c interpreter core (git submodule, vendor/dhall-c)
#
# Initialize the submodules first:
#     git submodule update --init --recursive
#
# Override the dependency paths with:
#     make DATALOG=/path/to/datalog-dafsa DHALLC=/path/to/dhall-c
#
# Requires the cosmocc toolchain (Cosmopolitan).

DATALOG ?= $(CURDIR)/vendor/datalog-dafsa
DHALLC  ?= $(CURDIR)/vendor/dhall-c

# dhall-c interpreter core sources (link directly, in dhall-c's own order;
# exclude its entry-point/extra TUs: main/wasm/bench/lsp and json.c which only
# LSP links).  Mirrors datalog-dafsa Makefile CORE_SRCS.
CORE_SRCS = $(DHALLC)/src/arena.c $(DHALLC)/src/lexer.c \
            $(DHALLC)/src/parser.c $(DHALLC)/src/ast.c \
            $(DHALLC)/src/normalize.c $(DHALLC)/src/typecheck.c \
            $(DHALLC)/src/builtins.c $(DHALLC)/src/serialize.c \
            $(DHALLC)/src/import.c $(DHALLC)/src/bignum.c \
            $(DHALLC)/src/sha256.c $(DHALLC)/src/ssrf.c $(DHALLC)/src/http.c

# datalog-dafsa engine + vendored dafsa sources (from datalog-dafsa Makefile
# DLP_ENGINE_SRCS), excluding the TUs that carry their own entry points
# (dl_cli.c main, lsp.c main, playground-wasm.c wasm entry).  Compiled from
# source with cosmocc (the gcc-built .o files are not cosmo-safe to reuse).
ENGINE_SRCS = $(DATALOG)/src/intern.c $(DATALOG)/src/termstore.c \
              $(DATALOG)/src/relation.c $(DATALOG)/src/vrelation.c \
              $(DATALOG)/src/tupleset.c $(DATALOG)/src/parser.c \
              $(DATALOG)/src/compiler.c $(DATALOG)/src/vm.c \
              $(DATALOG)/src/snapshot.c $(DATALOG)/src/regexwalk.c \
              $(DATALOG)/src/permindex.c $(DATALOG)/src/util.c \
              $(DATALOG)/src/dl.c $(DATALOG)/src/iter.c \
              $(DATALOG)/src/magic.c $(DATALOG)/src/topdown.c \
              $(DATALOG)/src/analyze.c $(DATALOG)/src/schema.c \
              $(DATALOG)/src/typecheck.c $(DATALOG)/src/json.c \
              $(DATALOG)/src/txnwal.c \
              $(DATALOG)/vendor/dafsa.c $(DATALOG)/vendor/dafsa_state.c \
              $(DATALOG)/vendor/dafsa_core.c $(DATALOG)/vendor/dafsa_persist.c \
              $(DATALOG)/vendor/dafsa_view.c $(DATALOG)/vendor/dafsa_crc32.c \
              $(DATALOG)/vendor/dafsa_wal.c $(DATALOG)/vendor/dafsa_build.c \
              $(DATALOG)/vendor/dafsa_rank.c $(DATALOG)/vendor/dafsa_view_rank.c

FX_SRCS = main.c packageset.c derivation.c closure.c store.c build.c

# Use := (not ?=) so the environment's CC=cc does not override cosmocc.
COSMOCC := cosmocc
CFLAGS = -std=c11 -O2 -g -Wall -Wextra \
         -I$(DHALLC)/src -I$(DATALOG)/vendor -I$(DATALOG)/src

all: fxstore

fxstore: $(FX_SRCS) fxstore.h
	$(COSMOCC) $(CFLAGS) -o fxstore $(FX_SRCS) $(ENGINE_SRCS) $(CORE_SRCS)

# Golden end-to-end test: scaffold, build, query, gc into a temp store.
fxstore-golden: fxstore
	@tests/fxstore_golden.sh ./fxstore

test: fxstore-golden

clean:
	rm -f fxstore fxstore.aarch64.elf fxstore.com.dbg

.PHONY: all clean test fxstore-golden
