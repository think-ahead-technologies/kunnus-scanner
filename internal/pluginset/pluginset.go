// ABOUTME: The sorted, deduplicated union of scalibr plugin-name lists.
// ABOUTME: One primitive shared by every registry fan-out so plugin selection cannot drift on ordering or dupes.
package pluginset

import "slices"

// Union returns the deduplicated, sorted union of the given plugin-name lists.
// Empty input yields a non-nil empty slice. Every registry fan-out
// (ecosystem.PluginsFor, ecosystem.AllInstalledPlugins, osfamily.LinuxPluginsFor,
// and the container plugin merge) routes through here so the must-dedup-and-sort
// invariant lives in exactly one place.
func Union(lists ...[]string) []string {
	seen := make(map[string]struct{})
	for _, list := range lists {
		for _, name := range list {
			seen[name] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}
