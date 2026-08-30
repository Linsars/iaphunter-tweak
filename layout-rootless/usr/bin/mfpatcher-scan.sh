#!/bin/bash
# 开机时全设备扫描: 所有解密 app binary weakify + 重签
MFPATCHER="/var/jb/usr/lib/mfpatcher"
[ -x "$MFPATCHER" ] || exit 0
find /var/containers/Bundle/Application -maxdepth 3 -type f 2>/dev/null | while read -r f; do
    "$MFPATCHER" "$f" 2>/dev/null
done
