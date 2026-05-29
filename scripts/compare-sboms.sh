#!/usr/bin/env bash
# ABOUTME: Compares the package coverage of kunnus, trivy, and syft CycloneDX SBOMs for one image.
# ABOUTME: Emits a Markdown report (per-ecosystem unique counts, OS component, and any kunnus gap) to stdout.
set -euo pipefail

if [ "$#" -ne 4 ]; then
	echo "usage: $0 <image-label> <kunnus.json> <trivy.json> <syft.json>" >&2
	exit 2
fi

label="$1"
declare -A sbom=([kunnus]="$2" [trivy]="$3" [syft]="$4")
tools=(kunnus trivy syft)

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

# normalize emits one canonical "pkg:<purl>" per line, deduplicated, so the
# tools compare on package identity rather than cosmetic encoding. It strips
# qualifiers, decodes the namespace separator (%2F) and Debian epoch (%3A), and
# drops the Go module "v" prefix — the differences we already know are
# representational, not coverage.
normalize() {
	jq -r '.components[]? | .purl // empty' "$1" |
		sed -E 's/\?.*//; s/%2[Ff]/\//g; s/%3[Aa]/:/g; s#(pkg:golang/[^@]+)@v#\1@#' |
		sort -u
}

os_component() {
	jq -r '[.components[]? | select(.type == "operating-system") | "\(.name) \(.version)"] | first // "—"' "$1"
}

ecosystem_of() { sed -E 's#^pkg:([^/]+)/.*#\1#'; }

for t in "${tools[@]}"; do
	normalize "${sbom[$t]}" >"$workdir/$t.purls"
done

# Union of ecosystems seen by any tool.
ecosystems="$(cat "$workdir"/*.purls | ecosystem_of | sort -u)"

{
	echo "### \`$label\`"
	echo
	echo "OS component — kunnus: \`$(os_component "${sbom[kunnus]}")\` · trivy: \`$(os_component "${sbom[trivy]}")\` · syft: \`$(os_component "${sbom[syft]}")\`"
	echo
	echo "| ecosystem | kunnus | trivy | syft |"
	echo "|---|---:|---:|---:|"

	count_in() { grep -cE "^pkg:$1/" "$workdir/$2.purls" || true; }

	while read -r eco; do
		[ -n "$eco" ] || continue
		printf '| %s | %s | %s | %s |\n' "$eco" \
			"$(count_in "$eco" kunnus)" "$(count_in "$eco" trivy)" "$(count_in "$eco" syft)"
	done <<<"$ecosystems"

	printf '| **total (unique)** | **%s** | **%s** | **%s** |\n' \
		"$(wc -l <"$workdir/kunnus.purls" | tr -d ' ')" \
		"$(wc -l <"$workdir/trivy.purls" | tr -d ' ')" \
		"$(wc -l <"$workdir/syft.purls" | tr -d ' ')"
	echo

	# Gap signal: packages BOTH trivy and syft report but kunnus does not — the
	# most credible "kunnus is missing something" indicator, since it requires
	# two independent tools to agree.
	comm -12 "$workdir/trivy.purls" "$workdir/syft.purls" >"$workdir/both_others.purls"
	comm -13 "$workdir/kunnus.purls" "$workdir/both_others.purls" >"$workdir/gap.purls"
	gap="$(wc -l <"$workdir/gap.purls" | tr -d ' ')"
	echo "Packages in **both trivy and syft but not kunnus**: ${gap}"
	if [ "$gap" -gt 0 ]; then
		echo
		echo '<details><summary>show</summary>'
		echo
		echo '```'
		head -50 "$workdir/gap.purls"
		echo '```'
		echo '</details>'
	fi
	echo
} # report to stdout
