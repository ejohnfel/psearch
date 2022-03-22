#!/usr/bin/env bash

BINFOLDER=/srv/storage/projects/scripts/psearch

pushd "${BINFOLDER}" > /dev/null

./dhcp.py --silent extract last4days

popd > /dev/null
