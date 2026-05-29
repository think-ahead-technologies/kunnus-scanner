package = "mylib"
version = "1.0-1"
source = {
   url = "git://github.com/example/mylib",
   tag = "v1.0"
}
description = {
   summary = "A fixture rock for kunnus e2e tests",
   license = "MIT"
}
dependencies = {
   "lua >= 5.1",
   "luasocket >= 3.0"
}
build = {
   type = "builtin",
   modules = {
      mylib = "src/mylib.lua"
   }
}
