.PHONY: bump-version help

help:
	@echo "Available targets:"
	@echo "  bump-version VERSION=x.y.z  - Bump version, commit, tag, and push"
	@echo "  help                        - Show this help message"

bump-version:
	@if [ -z "$(VERSION)" ]; then \
		echo "Error: VERSION is required. Usage: make bump-version VERSION=x.y.z"; \
		exit 1; \
	fi
	@echo "Bumping version to $(VERSION)..."
	@sed -i.bak 's/^version = ".*"/version = "$(VERSION)"/' Cargo.toml && rm Cargo.toml.bak
	@cargo update -p moat
	@git add Cargo.toml Cargo.lock
	@git commit -m "chore: bump version to $(VERSION)"
	@git tag v$(VERSION)
	@git push origin tag v$(VERSION)
	@echo "Version bumped to $(VERSION) and pushed successfully!"

