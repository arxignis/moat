.PHONY: release help

help:
	@echo "Available targets:"
	@echo "  release VERSION=x.y.z      - Release moat: bump version, commit, tag vx.y.z, and push"
	@echo "  help                             - Show this help message"

release:
	@if [ -z "$(VERSION)" ]; then \
		echo "Error: VERSION is required. Usage: make release VERSION=x.y.z"; \
		exit 1; \
	fi
	@echo "Releasing moat version $(VERSION)..."
	@sed -i.bak 's/^VERSION=.*$$/VERSION=$(VERSION)/' install.sh && rm install.sh.bak
	@sed -i.bak 's/^version = ".*"/version = "$(VERSION)"/' Cargo.toml && rm Cargo.toml.bak
	@cargo update -p moat
	@git add Cargo.toml Cargo.lock install.sh
	@git commit -m "chore: release moat $(VERSION)"
	@git tag v$(VERSION)
	@git push origin main
	@git push origin tag v$(VERSION)
	@echo "Moat version $(VERSION) released successfully!"
