#!/bin/bash
# 把 MFShim.dylib 追加进 launchd 的 DYLD_INSERT_LIBRARIES（保序、去重、幂等）
ENV_NAME="DYLD_INSERT_LIBRARIES"
SHIM="/var/jb/usr/lib/MFShim.dylib"
OLD=$(/var/jb/bin/launchctl getenv "$ENV_NAME" 2>/dev/null)
case ":$OLD:" in
  *":$SHIM:"*) exit 0 ;;
esac
if [ -z "$OLD" ]; then
  /var/jb/bin/launchctl setenv "$ENV_NAME" "$SHIM"
else
  /var/jb/bin/launchctl setenv "$ENV_NAME" "$OLD:$SHIM"
fi
