LLC ?= llc
CLANG ?= clang
GOCMD := go
GOBUILD := $(GOCMD) build
GOCLEAN := $(GOCMD) clean

XDP_SOURCE := src/datapath/bpf/upf.c
XDP_BINARY := build/upf.elf

CLANG_INCLUDE = -I ./include -I /usr/include/bpf/
GO_SOURCE := src/control/main.go
GO_BINARY := main

all: build_bpf build_go

build_bpf:$(XDP_BINARY)

build_go: $(GO_BINARY)

$(XDP_BINARY): $(XDP_SOURCE)
	@mkdir build
	$(CLANG) $(CLANG_INCLUDE) -O2 -target bpf -c $^  -o $@

$(GO_BINARY): $(GO_SOURCE)
	cd src/control && $(GOBUILD)  -v -o $@ && mv $@ ../../build

clean:
	rm -f build/$(GO_BINARY)
	rm -f $(XDP_BINARY)