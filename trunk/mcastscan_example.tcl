#!/bin/sh
# the next line restarts using tclsh \
exec tclsh "$0" "$@"

# Copyright (c) 2007 by Todd J Martin <todd.martin@acm.org>

# If you run this on Linux and see lots of errors, it is likely because of
# kernel limits for the maximum number of groups a socket can join and how much
# memory the networking subsystem can use.  These commands (run as root)
# increase these limits and allow this script to run:
#   /sbin/sysctl -w net.ipv4.igmp_max_memberships=2000
#   /sbin/sysctl -w net.core.optmem_max=102400

lappend auto_path [pwd]
package require mcastscan
set ipRange [mcastscan::expandIpList [list 224.0.0.1 224.0.7.1]]
set portRange [mcastscan::expandPortList [list 7534 7535]]

package require mcastscan

proc printUpdate {key status} {
    if {![string equal $status "timeout"]} {
	puts "Update: $key = $status"
    }
}

set statusList [mcastscan::multicastScan $ipRange $portRange 10 printUpdate]

puts "\nFinal Results\n-------------"
foreach {key status} $statusList {
    if {![string equal $status "timeout"]} {
	puts "$key = $status"
    }
}
