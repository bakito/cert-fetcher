#!/bin/bash

#upx -q dist/${1}*/*

# ignore darwin; see https://github.com/upx/upx/issues/222
find dist -type d -name "darwin*" -prune -o -type f -exec upx {} \;

