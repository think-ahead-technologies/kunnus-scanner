// ABOUTME: Lua ecosystem. Detected via .rockspec files; scanned by scalibr's lua/luarocks.
// ABOUTME: Lua is common on embedded networking gear (OpenWrt, MikroTik), industrial routers, and scripting hooks in PLC firmware.
package ecosystem

import (
	"github.com/google/osv-scalibr/extractor/filesystem/language/lua/luarocks"
)

var lua = Ecosystem{
	Name:             "lua",
	FilenameSuffixes: []string{".rockspec"},
	ScalibrPlugins:   []string{luarocks.Name},
}
