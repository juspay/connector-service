# Release Makefile
# Handles version bumping, changelog generation, and release preparation
# Uses git-cliff for changelog generation and conventional commits for versioning

.PHONY: help version changelog bump-version generate-changelog prepare-release check-git-cliff

# Default target
.DEFAULT_GOAL := help

# Configuration
CLIFF_CONFIG ?= cliff.toml
CHANGELOG_FILE ?= CHANGELOG.md
GIT_CLIFF ?= git-cliff

# Version extraction from git tags
CURRENT_VERSION := $(shell git describe --tags --abbrev=0 2>/dev/null || echo "v0.0.0")
CURRENT_VERSION_NO_V := $(subst v,,$(CURRENT_VERSION))

help: ## Show this help message
	@echo "Release Makefile - Available targets:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-30s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Current version: $(CURRENT_VERSION)"

check-git-cliff: ## Verify git-cliff is installed
	@which $(GIT_CLIFF) > /dev/null 2>&1 || (echo "Error: git-cliff is not installed. Install it with: cargo install git-cliff" && exit 1)

version: check-git-cliff ## Show current version and suggest next versions
	@echo "Current version: $(CURRENT_VERSION)"
	@echo ""
	@echo "Suggested next versions based on conventional commits:"
	@echo "  Major (breaking changes): $$(git-cliff --bumped-version --bump major 2>/dev/null || echo 'v0.1.0')"
	@echo "  Minor (features):         $$(git-cliff --bumped-version --bump minor 2>/dev/null || echo 'v0.1.0')"
	@echo "  Patch (fixes):            $$(git-cliff --bumped-version --bump patch 2>/dev/null || echo 'v0.1.0')"

changelog: check-git-cliff ## Generate changelog for unreleased changes
	@echo "Generating changelog for unreleased changes..."
	@$(GIT_CLIFF) --config $(CLIFF_CONFIG) --unreleased

generate-changelog: check-git-cliff ## Generate full changelog and save to file
	@echo "Generating full changelog to $(CHANGELOG_FILE)..."
	@$(GIT_CLIFF) --config $(CLIFF_CONFIG) -o $(CHANGELOG_FILE)
	@echo "Changelog generated successfully."

bump-version: check-git-cliff ## Bump version (use BUMP=major|minor|patch, default: patch)
	$(eval BUMP_TYPE ?= patch)
	$(eval NEW_VERSION := $(shell $(GIT_CLIFF) --bumped-version --bump $(BUMP_TYPE) 2>/dev/null || echo 'v0.1.0'))
	@echo "Bumping version: $(CURRENT_VERSION) -> $(NEW_VERSION)"
	@echo ""
	@echo "Next steps:"
	@echo "  1. Review the changes: git log $(CURRENT_VERSION)..HEAD --oneline"
	@echo "  2. Generate changelog: make generate-changelog"
	@echo "  3. Create and push tag: make tag VERSION=$(NEW_VERSION)"

tag: ## Create and push a git tag (use VERSION=vX.Y.Z)
	$(if $(VERSION),,$(error VERSION is required. Usage: make tag VERSION=v1.2.3))
	@echo "Creating tag $(VERSION)..."
	@git tag -a $(VERSION) -m "Release $(VERSION)"
	@echo "Tag $(VERSION) created."
	@echo "Push the tag with: git push origin $(VERSION)"

prepare-release: check-git-cliff ## Full release preparation (generate changelog + suggest version)
	@echo "Preparing release..."
	@echo ""
	@echo "=== Current Version ==="
	@echo "$(CURRENT_VERSION)"
	@echo ""
	@echo "=== Unreleased Changes ==="
	@$(GIT_CLIFF) --config $(CLIFF_CONFIG) --unreleased
	@echo ""
	@echo "=== Suggested Next Versions ==="
	@echo "  Major: $$(git-cliff --bumped-version --bump major 2>/dev/null || echo 'v0.1.0')"
	@echo "  Minor: $$(git-cliff --bumped-version --bump minor 2>/dev/null || echo 'v0.1.0')"
	@echo "  Patch: $$(git-cliff --bumped-version --bump patch 2>/dev/null || echo 'v0.1.0')"
	@echo ""
	@echo "Next steps:"
	@echo "  1. Run: make generate-changelog"
	@echo "  2. Review and commit CHANGELOG.md changes"
	@echo "  3. Run: make tag VERSION=vX.Y.Z"

preview-release: check-git-cliff ## Preview what the release would look like
	@echo "=== Release Preview ==="
	@echo ""
	@echo "Version: $$(git-cliff --bumped-version 2>/dev/null || echo 'v0.1.0')"
	@echo ""
	@echo "=== Changelog ==="
	@$(GIT_CLIFF) --config $(CLIFF_CONFIG) --unreleased
