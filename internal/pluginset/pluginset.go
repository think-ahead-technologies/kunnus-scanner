// ABOUTME: The sorted, deduplicated set algebra over scalibr plugin-name lists.
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

// Without returns the plugin names in list that do not appear in remove,
// deduplicated and sorted like Union. It is how a mode drops plugins another
// signal made redundant (ecosystem.Survey's superseded set) while keeping the
// selection in the one canonical shape.
func Without(list []string, remove []string) []string {
	if len(remove) == 0 {
		return Union(list)
	}
	out := make([]string, 0, len(list))
	for _, name := range list {
		if !slices.Contains(remove, name) {
			out = append(out, name)
		}
	}
	return Union(out)
}
