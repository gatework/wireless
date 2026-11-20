# Shared gates come from the published go-standards; see standard.mk.
include standard.mk

CHECK_EXTRA := modverify

.PHONY: modverify build corpus fuzz
modverify:
	$(GO) mod verify

build:
	$(GO) build -o bin/wireless ./cmd/wireless

# Private corpus: real snapshots kept outside the repository.
corpus:
	WIRELESS_CORPUS="$(WIRELESS_CORPUS)" $(GO) test -count=1 -run '^TestPrivateCorpus$$' -v ./vendors/h3c

fuzz:
	$(GO) test -run '^$$' -fuzz FuzzDecode -fuzztime 60s ./vendors/h3c
