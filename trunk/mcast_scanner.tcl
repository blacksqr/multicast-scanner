#!/bin/sh
# the next line restarts using tclsh \
exec tclsh "$0" "$@"

# Copyright (c) 2007 by Todd J Martin <todd.martin@acm.org>


package provide mcastscan 1.0
package require udp

namespace eval mcastscan {
    variable listeningSocketArray
    variable trafficStatus
    variable timeoutIdArray
    array set listeningSocketArray {}
    array set trafficStatus {}
    array set timeoutIdArray {}

    namespace export multicastScan
}

proc mcastscan::expandPortList {portList} {
    set startPort [lindex $portList 0]
    set endPort [lindex $portList 1]
    set retList [list]
    for {set i $startPort} {$i <= $endPort} {incr i} {
	lappend retList $i
    }
    return $retList
}

proc mcastscan::ipToHex {ip} {
    set ipList [split $ip .]
    set ipList [lrange [concat $ipList 0 0 0] 0 3]
    binary scan [binary format c4 $ipList] H8 x
    return 0x$x
}

proc mcastscan::hexToIp {hexIp} {
    set ipList {}
    set bin [binary format I [expr {$hexIp}]]
    binary scan $bin c4 octets
    foreach octet $octets {
	lappend ipList [expr {$octet & 0xFF}]
    }
    return [join $ipList .]
}

proc mcastscan::expandIpList {ipList} {
    set startIp [ipToHex [lindex $ipList 0]]
    set endIp [ipToHex [lindex $ipList 1]]
    set retList {}
    for {set i $startIp} {$i <= $endIp} {incr i} {
	# The pointless string length call is actually necessary.  Some
	# versions of Tcl (I saw it on 8.4.2) have a bug where incr will cause
	# i to become a negative number and the loop run for a long time.
	# Causing i's string representation to be updated prevents this from
	# happening.
	string length $i
	lappend retList [hexToIp $i]
    }
    return $retList
}

proc mcastscan::getTrafficKey {sock} {
    set trafficKey $::mcastscan::listeningSocketArray($sock)
    return $trafficKey
}

proc mcastscan::closeSocket {sock} {
    set trafficKey [getTrafficKey $sock]
    unset ::mcastscan::listeningSocketArray($sock)
    close $sock
}

proc mcastscan::socketListener {sock} {
    set trafficKey [getTrafficKey $sock]
    set ::mcastscan::trafficStatus($trafficKey) "traffic"
    after cancel $::mcastscan::timeoutIdArray($sock)
    unset ::mcastscan::timeoutIdArray($sock)
    closeSocket $sock
}

proc mcastscan::timeout {sock} {
    set trafficKey [getTrafficKey $sock]
    set ::mcastscan::trafficStatus($trafficKey) "timeout"
    unset ::mcastscan::timeoutIdArray($sock)
    closeSocket $sock
}

proc mcastscan::checkForTraffic {ip port timeout} {
    set socketStatus [catch {
	set s [udp_open $port]
	fconfigure $s -mcastadd $ip
    } err]
    if {$socketStatus != 0} {
	set ::mcastscan::trafficStatus(${ip}:$port) "error"
	return error
    }
    set ::mcastscan::listeningSocketArray($s) ${ip}:$port
    fileevent $s readable [list ::mcastscan::socketListener $s]
    set afterId [after [expr {$timeout * 1000}] [list ::mcastscan::timeout $s]]
    set ::mcastscan::timeoutIdArray($s) $afterId
    set ::mcastscan::trafficStatus(${ip}:$port) "waiting"
}

# Returns a list like this:  trafficKey status [trafficKey status ...]
# trafficKey is a string like this: ip:port (e.g. 224.0.0.10:7000)
# status is one of the following strings:
#    error - the socket for that key could not be created
#    timeout - the timeout expired before any traffic was detected
#    traffic - data was detected on the socket
proc mcastscan::multicastScan {ipRange portRange {timeout 10}} {
    set ipList [expandIpList $ipRange]
    set portList [expandPortList $portRange]

    foreach ip $ipList {
	foreach port $portList {
	    if {[checkForTraffic $ip $port $timeout] != "error"} {
		vwait ::mcastscan::trafficStatus(${ip}:$port)
	    }
	}
    }

    foreach trafficKey [array names ::trafficStatus] {
	puts "$trafficKey = $::trafficStatus($trafficKey)"
    }
    return [array get ::mcastscan::trafficStatus]
}
