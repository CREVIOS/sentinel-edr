#!/usr/bin/env bash
set -euo pipefail

./node_modules/.bin/tsc -b
NO_COLOR=1 FORCE_COLOR=0 TERM=dumb CI=1 node ./node_modules/vite/bin/vite.js build --logLevel silent
