#!/bin/bash
#

#
# Usage : bt.segstart.sh <pid> <addr>
#

bt_get_segment_start()
{
	local pid
	local addr
	local start
	local end

	pid=$1
	addr=$2

	grep ' ..x. ' /proc/${pid}/maps | awk '{ print $1 }' | sed -e '1,$s/-/ /' | while read start end
	do
		if [[ $addr -ge 0x$start && $addr -le 0x$end ]]
		then
			echo 0x$start
			return 0
		fi
	done

	return 2;
}

bt_get_segment_start $1 $2
