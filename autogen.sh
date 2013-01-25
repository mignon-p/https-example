#!/bin/bash

#
# Force everything to the abspath of this script
#
srcdir=$(cd $(dirname $0) && pwd)

autoreconf --verbose --install --force $srcdir
