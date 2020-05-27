#!/usr/bin/env bash

set -o errexit
set -o pipefail

RESULT="$(./encrypt | ./decrypt)"

test "${RESULT}" = "Hello, world!"