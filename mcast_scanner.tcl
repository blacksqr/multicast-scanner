#!/bin/sh
# the next line restarts using tclsh \
exec tclsh "$0" "$@"

# Copyright (c) 2007 by Todd J Martin <todd.martin@acm.org>


package provide mcastscan 1.0
package require udp

namespace eval mcastscan {
    # The listeningSocketArray stores the UDP ports we are listening to indexed
    # by the socket descriptor
    variable listeningSocketArray
    # The openPortArray stores the open sockets indexed by the UDP port number
    variable openPortArray
    variable trafficStatus
    variable timeoutIdArray
    variable statusUpdateProc
    variable scannerStatus
    array set listeningSocketArray {}
    array set openPortArray {}
    array set trafficStatus {}
    array set timeoutIdArray {}
    set statusUpdateProc ""
    set scannerStatus ""

    namespace export multicastScan expandIpList expandPortList
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

proc mcastscan::getTrafficKey {sock ip} {
    set port $::mcastscan::listeningSocketArray($sock)
    return ${ip}:$port
}

proc mcastscan::closeSocket {sock} {
    set port $::mcastscan::listeningSocketArray($sock)
    unset ::mcastscan::listeningSocketArray($sock)
    unset ::mcastscan::openPortArray($port)
    close $sock
}

proc mcastscan::socketListener {sock} {
    set d [read $sock]
    set ip [fconfigure $sock -dstip]
    set trafficKey [getTrafficKey $sock $ip]
    if {![string equal $::mcastscan::trafficStatus($trafficKey) "waiting"]} {
        # We have already received and counted traffic for this group, so just ignore this and move on
	return
    }
    set ::mcastscan::trafficStatus($trafficKey) "traffic"
    after cancel $::mcastscan::timeoutIdArray(${sock}:$ip)
    unset ::mcastscan::timeoutIdArray(${sock}:$ip)
    fconfigure $sock -mcastdrop $ip
    if {![llength [fconfigure $sock -mcastgroups]]} {
	closeSocket $sock
    }
}

proc mcastscan::timeout {sock ip} {
    set trafficKey [getTrafficKey $sock $ip]
    set ::mcastscan::trafficStatus($trafficKey) "timeout"
    unset ::mcastscan::timeoutIdArray(${sock}:$ip)
    fconfigure $sock -mcastdrop $ip
    if {![llength [fconfigure $sock -mcastgroups]]} {
	closeSocket $sock
    }
}

proc mcastscan::checkForTraffic {ip port timeout} {
    if {[info exists ::mcastscan::openPortArray($port)]} {
	set s $::mcastscan::openPortArray($port)
    } else {
	set socketStatus [catch {
	    set s [udp_open $port]
	    set ::mcastscan::openPortArray($port) $s
	} err]
	if {$socketStatus != 0} {
	    set ::mcastscan::trafficStatus(${ip}:$port) "error"
	    return error
	}
	set ::mcastscan::listeningSocketArray($s) $port
	fileevent $s readable [list ::mcastscan::socketListener $s]
    }
    set socketStatus [catch {
	fconfigure $s -mcastadd $ip
    } err]
    if {$socketStatus != 0} {
	set ::mcastscan::trafficStatus(${ip}:$port) "error"
	return error
    }

    set afterId [after [expr {$timeout * 1000}] [list ::mcastscan::timeout $s $ip]]
    set ::mcastscan::timeoutIdArray(${s}:$ip) $afterId
    set ::mcastscan::trafficStatus(${ip}:$port) "waiting"
}

proc doStatusCallout {key status} {
    if {[string length $::mcastscan::statusUpdateProc] && 
	    [llength [info procs $::mcastscan::statusUpdateProc]]} {
	catch {uplevel #0 $::mcastscan::statusUpdateProc $key $status}
    }
}

proc checkTrafficStatus {statusArray key op} {
    upvar $statusArray arr
    doStatusCallout $key $arr($key)

    # Check through all of the status elements to see if anything is still in
    # the "waiting" state.  If there is nothing, then we are done
    set stillWaiting 0
    foreach {key val} [array get arr] {
	if {[string equal $val "waiting"]} {
	    set stillWaiting 1
	    break
	}
    }
    if {!$stillWaiting} {
	set ::mcastscan::scannerStatus "done"
    }
}

# Returns a list like this:  trafficKey status [trafficKey status ...]
# trafficKey is a string like this: ip:port (e.g. 224.0.0.10:7000)
# status is one of the following strings:
#    error - the socket for that key could not be created
#    timeout - the timeout expired before any traffic was detected
#    traffic - data was detected on the socket
proc mcastscan::multicastScan {ipList portList {timeout 10} {statusUpdateProc ""}} {
    set waitCount 0
    set ::mcastscan::statusUpdateProc $statusUpdateProc
    foreach ip $ipList {
	foreach port $portList {
	    if {[checkForTraffic $ip $port $timeout] != "error"} {
		incr waitCount
	    }
	}
    }

    if {$waitCount} {
	trace add variable ::mcastscan::trafficStatus write checkTrafficStatus
	vwait ::mcastscan::scannerStatus
	trace remove variable ::mcastscan::trafficStatus write checkTrafficStatus
    }

    set resultList [array get ::mcastscan::trafficStatus]
    array unset ::mcastscan::trafficStatus
    return $resultList
}
