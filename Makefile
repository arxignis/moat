.PHONY: release-moat release-chart release-controller help

help:
	@echo "Available targets:"
	@echo "  release-moat VERSION=x.y.z      - Release moat: bump version, commit, tag v*, and push"
	@echo "  release-chart VERSION=x.y.z      - Release chart: bump version, commit, tag chart/v*, and push"
	@echo "  release-controller VERSION=x.y.z - Release controller: commit, tag controller/v*, and push"
	@echo "  help                             - Show this help message"

release-moat:
	@if [ -z "$(VERSION)" ]; then \
		echo "Error: VERSION is required. Usage: make release-moat VERSION=x.y.z"; \
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

release-chart:
	@if [ -z "$(VERSION)" ]; then \
		echo "Error: VERSION is required. Usage: make release-chart VERSION=x.y.z"; \
		exit 1; \
	fi
	@echo "Releasing chart version $(VERSION)..."
	@sed -i.bak 's/^version: .*/version: $(VERSION)/' moat-operator/helm/Chart.yaml && rm moat-operator/helm/Chart.yaml.bak
	@sed -i.bak 's/^appVersion: .*/appVersion: "$(VERSION)"/' moat-operator/helm/Chart.yaml && rm moat-operator/helm/Chart.yaml.bak
	@sed -i.bak '/- name: moat$$/,/repository:/ s/^    version: .*/    version: $(VERSION)/' moat-operator/helm/Chart.yaml && rm moat-operator/helm/Chart.yaml.bak
	@sed -i.bak 's/^version: .*/version: $(VERSION)/' moat-operator/helm/charts/moat/Chart.yaml && rm moat-operator/helm/charts/moat/Chart.yaml.bak
	@sed -i.bak 's/^appVersion: .*/appVersion: "$(VERSION)"/' moat-operator/helm/charts/moat/Chart.yaml && rm moat-operator/helm/charts/moat/Chart.yaml.bak
	@git add moat-operator/helm/Chart.yaml moat-operator/helm/charts/moat/Chart.yaml
	@git commit -m "chore: release chart $(VERSION)"
	@git tag chart/v$(VERSION)
	@git push origin main
	@git push origin tag chart/v$(VERSION)
	@echo "Chart version $(VERSION) released successfully!"

release-controller:
	@if [ -z "$(VERSION)" ]; then \
		echo "Error: VERSION is required. Usage: make release-controller VERSION=x.y.z"; \
		exit 1; \
	fi
	@echo "Releasing controller version $(VERSION)..."
	@git commit --allow-empty -m "chore: release controller $(VERSION)"
	@git tag controller/v$(VERSION)
	@git push origin main
	@git push origin tag controller/v$(VERSION)
	@echo "Controller version $(VERSION) released successfully!"
