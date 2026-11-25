.PHONY: check verify-release-tag

check:
	./scripts/check

verify-release-tag:
	./scripts/check --verify-release-tag "$(TAG)"
