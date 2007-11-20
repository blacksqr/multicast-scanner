#!/bin/sh
# the next line restarts using tclsh \
exec tclsh "$0" "$@"

# Copyright (c) 2007 by Todd J Martin <todd.martin@acm.org>

lappend auto_path [pwd]
set ipRange [list 224.0.0.10 224.0.0.13]
set portRange [list 8000 8005]

package require mcastscan

set statusList [mcastscan::multicastScan $ipRange $portRange 10]

foreach {key status} $statusList {
    puts "$key = $status"
}
