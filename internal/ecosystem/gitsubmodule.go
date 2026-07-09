// ABOUTME: Git-submodule ecosystem — projects vendoring dependencies as submodules declared in .gitmodules.
// ABOUTME: Detection only; components come from the kunnus-native internal/gitsubmodule extractor the mode wires in (no scalibr plugin exists).
package ecosystem

// gitsubmodule detects projects that vendor dependencies as git submodules by
// the superproject's .gitmodules file. scalibr's misc/gitrepo extractor does
// walk submodules, but it triggers on .git directories (which fswalk skips on
// every kunnus walk), needs DirectFS capabilities repo mode doesn't grant,
// emits the scanned repo itself as a package, and drops the GitHub owner
// namespace from its names — so this entry sets NativeExtractor instead:
// mode/repo appends internal/gitsubmodule.New() when this ecosystem is
// detected — the same split as modustoolbox.
var gitsubmodule = Ecosystem{
	Name:            "gitsubmodule",
	Filenames:       []string{".gitmodules"},
	NativeExtractor: true,
}
