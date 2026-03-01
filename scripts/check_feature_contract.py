#!/usr/bin/env python3
"""Feature contract drift guard.

Exits non-zero if the feature contract matrix, config schema, or runtime
code have drifted out of sync with each other.
"""

import sys
import os

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

REQUIRED_FILES = [
    "docs/FEATURE_CONTRACT_MATRIX.yaml",
    "docs/FEATURE_CONTRACT_MATRIX.md",
    "crates/wicket-config/src/lib.rs",
    "crates/wicket-core/src/routing.rs",
    "crates/wicket-core/src/proxy.rs",
    "crates/wicket-controller/src/reconcilers/config_generator.rs",
]

# Features whose statuses are pinned; update here when promoting a feature.
EXPECTED_STATUSES = {
    "path_regex_match": "Unsupported",
    "request_response_header_modifiers": "Unsupported",
    "per_route_timeout": "Unsupported",
}

VALID_STATUSES = {"GA", "Beta", "Unsupported"}


def read(rel_path: str) -> str:
    return open(os.path.join(REPO_ROOT, rel_path)).read()


def main() -> int:
    errors: list[str] = []

    # ── 1. Required files exist ──────────────────────────────────────────────
    for rel in REQUIRED_FILES:
        if not os.path.isfile(os.path.join(REPO_ROOT, rel)):
            errors.append(f"Required file missing: {rel}")

    if errors:
        # Can't proceed with content checks if files are absent.
        for e in errors:
            print(f"ERROR: {e}")
        return 1

    # ── 2. Parse YAML statuses (plain-text; no yaml dep) ────────────────────
    yaml_text = read("docs/FEATURE_CONTRACT_MATRIX.yaml")
    feature_statuses: dict[str, str] = {}
    current_feature: str | None = None
    for line in yaml_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("feature:"):
            current_feature = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("status:") and current_feature is not None:
            status = stripped.split(":", 1)[1].strip()
            feature_statuses[current_feature] = status
            current_feature = None

    # ── 3. Validate statuses are legal values ────────────────────────────────
    for feature, status in feature_statuses.items():
        if status not in VALID_STATUSES:
            errors.append(
                f"Feature '{feature}' has invalid status '{status}' "
                f"(must be one of {sorted(VALID_STATUSES)})"
            )

    # ── 4. Enforce pinned expected statuses ──────────────────────────────────
    for feature, expected in EXPECTED_STATUSES.items():
        actual = feature_statuses.get(feature)
        if actual is None:
            errors.append(
                f"Feature '{feature}' not found in FEATURE_CONTRACT_MATRIX.yaml"
            )
        elif actual != expected:
            errors.append(
                f"Feature '{feature}' status is '{actual}', expected '{expected}' — "
                f"update EXPECTED_STATUSES in this script if the feature was promoted"
            )

    # ── 5. Schema drift: RouteMatch must have deny_unknown_fields ────────────
    config_src = read("crates/wicket-config/src/lib.rs")
    # Find the RouteMatch struct block and check the attribute appears before it.
    struct_decl = "struct RouteMatch"
    if struct_decl not in config_src:
        errors.append(
            "crates/wicket-config/src/lib.rs: 'struct RouteMatch' not found"
        )
    else:
        # The attribute must appear in the 200 characters immediately before
        # the struct declaration (covers derive + serde lines).
        struct_idx = config_src.index(struct_decl)
        window = config_src[max(0, struct_idx - 200):struct_idx]
        if '#[serde(deny_unknown_fields)]' not in window:
            errors.append(
                "crates/wicket-config/src/lib.rs: RouteMatch is missing "
                "'#[serde(deny_unknown_fields)]' — schema drift guard broken"
            )

    # ── 6. Validation errors for unsupported filters and timeout ─────────────
    if "uses 'filters' which is not yet supported" not in config_src:
        errors.append(
            "crates/wicket-config/src/lib.rs: missing validation error "
            "\"uses 'filters' which is not yet supported\""
        )
    if "uses 'timeout' which is not yet supported" not in config_src:
        errors.append(
            "crates/wicket-config/src/lib.rs: missing validation error "
            "\"uses 'timeout' which is not yet supported\""
        )

    # ── 7. routing.rs must NOT contain PathMatcher::Regex ────────────────────
    routing_src = read("crates/wicket-core/src/routing.rs")
    if "PathMatcher::Regex" in routing_src:
        errors.append(
            "crates/wicket-core/src/routing.rs: contains 'PathMatcher::Regex' — "
            "path_regex_match is Unsupported; update the matrix/status before "
            "wiring runtime support"
        )

    # ── 8. proxy.rs must NOT contain filter execution markers ────────────────
    proxy_src = read("crates/wicket-core/src/proxy.rs")
    filter_markers = ["request_headers", "response_headers", "url_rewrite", "mirror"]
    found_markers = [m for m in filter_markers if m in proxy_src]
    if found_markers:
        errors.append(
            f"crates/wicket-core/src/proxy.rs: contains route filter execution "
            f"marker(s) {found_markers} — request_response_header_modifiers is "
            f"Unsupported; update the matrix/status before wiring runtime support"
        )

    # ── 9. Markdown lockstep rule ─────────────────────────────────────────────
    md_text = read("docs/FEATURE_CONTRACT_MATRIX.md")
    if "must be kept in lockstep" not in md_text:
        errors.append(
            "docs/FEATURE_CONTRACT_MATRIX.md: missing lockstep rule sentence "
            "('must be kept in lockstep')"
        )

    # ── Result ────────────────────────────────────────────────────────────────
    if errors:
        for e in errors:
            print(f"ERROR: {e}")
        return 1

    print("Feature contract guard passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
