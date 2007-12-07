#!/bin/sh
# the next line restarts using tclsh \
exec tclsh "$0" "$@"

# Copyright (c) 2007 by Todd J Martin <todd.martin@acm.org>

lappend auto_path [pwd]
package require mcastscan
set ipRange [mcastscan::expandIpList [list 224.0.0.10 224.0.0.11]]
set portRange [mcastscan::expandPortList [list 8000 8001]]

package require mcastscan

proc printUpdate {key status} {
    puts "$key = $status"
}

set statusList [mcastscan::multicastScan $ipRange $portRange 10 printUpdate]

foreach {key status} $statusList {
    puts "$key = $status"
}
