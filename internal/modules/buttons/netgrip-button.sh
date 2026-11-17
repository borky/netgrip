#!/bin/sh
# netgrip-managed-button
#
# Runs the actions NetGrip assigns to the router's physical buttons. NetGrip
# installs and updates this file, but nothing here needs NetGrip running:
# the actions are meant to recover a router whose panel or network is
# broken. It runs only when a button is pressed (nothing stays running in
# between, apart from the timer of an action that undoes itself later).
#
# Called as:
#   rc <button> <reserved>  by /etc/rc.button/<button> (the wrappers NetGrip
#                           installs), with procd's ACTION, SEEN and TYPE
#   seen                    by /etc/hotplug.d/button/ (to learn the buttons)
#   fire <button> <seq>     by itself, when a double/triple press window ends
#   act <button> <pattern> <action> <target> <minutes>
#   revert <iface> <token> <minutes> <button>
#   boot                    by /etc/init.d/netgrip-buttons, before networking
#   uninstall               when NetGrip is removed: everything back as it was
#
# <reserved>: holds this long or longer always go to the original script
# (the reset button's factory reset); 0 when nothing is reserved.

STATE=${NGB_STATE:-/tmp/netgrip-buttons}
ETC=${NGB_ETC:-/etc/netgrip/buttons}
SELF=${NGB_SELF:-/usr/libexec/netgrip-button}
LEDS=${NGB_LEDS:-/sys/class/leds}
INITD=${NGB_INITD:-/etc/init.d}
RCDIR=${NGB_RCDIR:-/etc/rc.button}
HOOK=${NGB_HOOK:-/etc/hotplug.d/button/00-netgrip}
# Seconds between the releases of a double or triple press. Whole seconds:
# busybox sleep may not take fractions.
WINDOW=1
# Holds start at this many seconds; anything shorter is a press.
HOLD_MIN=2
# Seconds in a minute (tests shorten it).
MINUTE=${NGB_MINUTE:-60}

mkdir -p "$STATE" 2>/dev/null

now_cs() {
	local u rest
	read u rest < /proc/uptime
	u="${u%%.*}${u##*.}"
	# No leading zero: shell arithmetic would read it as octal.
	while [ "${#u}" -gt 1 ] && [ "${u#0}" != "$u" ]; do u="${u#0}"; done
	echo "$u"
}

log() {
	logger -t netgrip-button "$*" 2>/dev/null
}

# event <button> <pattern> <action> <detail> <result>: one line per action
# for the panel and its notifications; the oldest lines are dropped.
event() {
	printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$(now_cs)" "$(date +%s)" "$1" "$2" "$3" "$4" "$5" >> "$STATE/events"
	local n
	n=$(wc -l < "$STATE/events")
	if [ "$n" -gt 100 ]; then
		tail -n 50 "$STATE/events" > "$STATE/events.tmp" && mv "$STATE/events.tmp" "$STATE/events"
	fi
	log "$1 $2: $3 $4 $5"
}

# take/drop <name>: one lock at a time per process. flock is released when
# the process ends, whatever happens; busybox's lock applet (the fallback)
# is not, so it is only used where flock is missing.
if command -v flock >/dev/null 2>&1; then
	take() { eval "exec 8>\"\$STATE/$1.lock\""; flock 8; }
	drop() { flock -u 8; exec 8>&-; }
	try_take() { eval "exec 7>\"\$STATE/$1.lock\""; flock -n 7; }
	try_drop() { exec 7>&-; }
else
	take() { lock "$STATE/$1.lock"; }
	drop() { lock -u "$STATE/$1.lock"; }
	try_take() { lock -n "$STATE/$1.lock"; }
	try_drop() { lock -u "$STATE/$1.lock"; }
fi

# spawn: run this script again, detached from procd's button handler, which
# waits for the wrapper and handles the next press only after it.
spawn() {
	if command -v setsid >/dev/null 2>&1; then
		setsid "$SELF" "$@" </dev/null >/dev/null 2>&1 &
	else
		"$SELF" "$@" </dev/null >/dev/null 2>&1 &
	fi
}

record_seen() {
	[ -n "$BUTTON" ] || return 0
	: > "$STATE/seen.$BUTTON"
	printf '%s %s %s %s %s\n' "$(date +%s)" "$BUTTON" "${ACTION:--}" "${SEEN:-0}" "${TYPE:--}" > "$STATE/last.tmp" &&
		mv "$STATE/last.tmp" "$STATE/last"
}

# The assigned actions, one per line, written by NetGrip:
#   <button> <press|hold> <count|seconds> <action> <target|-> <minutes>
actions_for() {
	[ -f "$ETC/actions" ] || return 0
	awk -v b="$1" '$1 == b' "$ETC/actions"
}

max_press() {
	actions_for "$1" | awk 'BEGIN { m = 0 } $2 == "press" && $3 > m { m = $3 } END { print m }'
}

has_holds() {
	actions_for "$1" | awk '$2 == "hold" { f = 1 } END { exit !f }'
}

press_line() {
	actions_for "$1" | awk -v n="$2" '$2 == "press" && $3 == n { print; exit }'
}

# The hold with the longest time not longer than the one held.
hold_line() {
	actions_for "$1" | awk -v s="$2" '$2 == "hold" && $3 <= s && $3 > best { best = $3; line = $0 } END { if (line != "") print line }'
}

forward() {
	[ -f "$ETC/orig/$B" ] && exec /bin/sh "$ETC/orig/$B"
	exit 0
}

blink() {
	local led="$1" l trig bri max saved f kv i
	[ -n "$led" ] || return 0
	l="$LEDS/$led"
	[ -w "$l/trigger" ] || return 0
	try_take led || return 0
	trig=$(sed -n 's/.*\[\([^]]*\)\].*/\1/p' "$l/trigger")
	bri=$(cat "$l/brightness")
	max=$(cat "$l/max_brightness" 2>/dev/null)
	saved=""
	for f in device_name link rx tx interval; do
		[ -f "$l/$f" ] && saved="$saved $f=$(cat "$l/$f")"
	done
	if echo timer > "$l/trigger" 2>/dev/null; then
		echo 100 > "$l/delay_on"
		echo 100 > "$l/delay_off"
		sleep 2
	else
		echo none > "$l/trigger" 2>/dev/null
		for i in 1 2; do
			echo "${max:-1}" > "$l/brightness"
			sleep 1
			echo 0 > "$l/brightness"
			sleep 1
		done
	fi
	echo "${trig:-none}" > "$l/trigger"
	for kv in $saved; do
		echo "${kv#*=}" > "$l/${kv%%=*}" 2>/dev/null
	done
	[ "$trig" = none ] && echo "$bri" > "$l/brightness"
	try_drop led
}

# run_line <pattern> <line>: the action of one assigned line, detached.
run_line() {
	set -- "$1" $2
	spawn act "$2" "$1" "$5" "$6" "$7"
}

cmd_rc() {
	B="$1"
	local reserved="${2:-0}" s max line cs n last seq rest
	record_seen
	# A switch (a slider, not a button) reports its position: untouched.
	[ -n "$TYPE" ] && forward
	case "$ACTION" in
	released) ;;
	timeout)
		# procd's "still held" call. The reset button uses it to show
		# that letting go now resets the router; on a button with holds
		# assigned, the original's long-press action must not run.
		if [ "$reserved" -gt 0 ] || ! has_holds "$B"; then
			forward
		fi
		exit 0
		;;
	*) forward ;;
	esac
	s="${SEEN:-0}"
	if [ "$s" -ge "$HOLD_MIN" ]; then
		rm -f "$STATE/clicks.$B"
		[ "$reserved" -gt 0 ] && [ "$s" -ge "$reserved" ] && forward
		line=$(hold_line "$B" "$s")
		[ -n "$line" ] || forward
		set -- $line
		run_line "hold$3" "$line"
		exit 0
	fi
	max=$(max_press "$B")
	[ "$max" -gt 0 ] || forward
	cs=$(now_cs)
	take "clicks.$B"
	n=0
	last=0
	[ -f "$STATE/clicks.$B" ] && read n last seq rest < "$STATE/clicks.$B"
	if [ $((cs - last)) -le $((WINDOW * 100 + 20)) ]; then
		n=$((n + 1))
	else
		n=1
	fi
	echo "$n $cs $cs" > "$STATE/clicks.$B"
	drop "clicks.$B"
	if [ "$n" -ge "$max" ]; then
		rm -f "$STATE/clicks.$B"
		fire_count "$n"
		exit 0
	fi
	spawn fire "$B" "$cs"
	exit 0
}

# fire_count <n>: the press pattern ended with n presses.
fire_count() {
	local line
	line=$(press_line "$B" "$1")
	if [ -n "$line" ]; then
		run_line "press$1" "$line"
	elif [ "$1" -eq 1 ]; then
		# A single press nobody assigned does what it always did.
		export BUTTON="$B" ACTION=released SEEN=0
		forward
	else
		log "$B pressed $1 times: nothing assigned"
	fi
}

cmd_fire() {
	B="$1"
	local seq="$2" n last cur rest
	sleep "$WINDOW"
	take "clicks.$B"
	cur=""
	[ -f "$STATE/clicks.$B" ] && read n last cur rest < "$STATE/clicks.$B"
	if [ "$cur" != "$seq" ]; then
		# Another press came, or a hold ended it: that one decides.
		drop "clicks.$B"
		exit 0
	fi
	rm -f "$STATE/clicks.$B"
	drop "clicks.$B"
	fire_count "$n"
}

# set_disabled <iface> <0|1|->: "-" removes the option. Uses its own change
# directory, so changes someone else left pending are not committed with it.
set_disabled() {
	local t="$STATE/uci" radio
	mkdir -p "$t"
	if [ "$2" = "-" ]; then
		uci -q -t "$t" delete "wireless.$1.disabled"
	else
		uci -q -t "$t" set "wireless.$1.disabled=$2"
	fi
	uci -q -t "$t" commit wireless || return 1
	[ "${3:-}" = norestart ] && return 0
	radio=$(uci -q get "wireless.$1.device")
	wifi reconf $radio 2>/dev/null || wifi up $radio
}

state_word() {
	[ "$1" = 1 ] && echo off || echo on
}

act_wifi() {
	local b="$1" p="$2" s="$3" m="$4" rec cur new tok prev rest until
	rec="$ETC/timed/$s"
	take wifi
	if [ "$(uci -q get "wireless.$s")" != wifi-iface ]; then
		drop wifi
		event "$b" "$p" wifi_toggle "$s" "failed: no such Wi-Fi network"
		return
	fi
	if [ -f "$rec" ]; then
		# A timed toggle is running: a press ends it now.
		read prev tok rest < "$rec"
		rm -f "$rec" "$STATE/hold/$s"
		set_disabled "$s" "$prev"
		drop wifi
		event "$b" "$p" wifi_toggle "$s $(state_word "$prev") 0" ended
		return
	fi
	cur=$(uci -q get "wireless.$s.disabled")
	if [ "$cur" = 1 ]; then new=0; else new=1; fi
	mkdir -p "$STATE/hold"
	tok=$(cat /proc/sys/kernel/random/uuid)
	until=0
	if [ "$m" -gt 0 ]; then
		mkdir -p "$ETC/timed"
		echo "${cur:--} $tok" > "$rec"
		until=$(($(date +%s) + m * MINUTE))
	fi
	# Tells NetGrip's Wi-Fi schedule to leave this network alone meanwhile.
	echo "$until $tok" > "$STATE/hold/$s"
	if ! set_disabled "$s" "$new"; then
		rm -f "$rec" "$STATE/hold/$s"
		drop wifi
		event "$b" "$p" wifi_toggle "$s $(state_word "$new") $m" failed
		return
	fi
	drop wifi
	[ "$m" -gt 0 ] && spawn revert "$s" "$tok" "$m" "$b"
	event "$b" "$p" wifi_toggle "$s $(state_word "$new") $m" ok
}

cmd_revert() {
	local s="$1" tok="$2" m="$3" b="$4" rec prev cur rest
	rec="$ETC/timed/$s"
	sleep $((m * MINUTE))
	take wifi
	cur=""
	[ -f "$rec" ] && read prev cur rest < "$rec"
	if [ "$cur" != "$tok" ]; then
		drop wifi
		exit 0
	fi
	rm -f "$rec" "$STATE/hold/$s"
	set_disabled "$s" "$prev"
	drop wifi
	event "$b" timer wifi_toggle "$s $(state_word "$prev") $m" reverted
}

act_firewall() {
	if "$INITD/firewall" restart >/dev/null 2>&1; then
		event "$1" "$2" firewall_restart - ok
	else
		event "$1" "$2" firewall_restart - failed
	fi
}

# The services that give access to the router: SSH, the web servers LuCI
# may use, and the NetGrip panel. Only those installed and enabled: one
# that was turned off on purpose stays off.
act_access() {
	local svc done="" failed=""
	for svc in dropbear uhttpd nginx netgrip; do
		[ -x "$INITD/$svc" ] || continue
		"$INITD/$svc" enabled 2>/dev/null || continue
		if "$INITD/$svc" restart >/dev/null 2>&1; then
			done="$done,$svc"
		else
			failed="$failed,$svc"
		fi
	done
	done="${done#,}"
	failed="${failed#,}"
	if [ -n "$failed" ]; then
		event "$1" "$2" access_restart "${done:--}" "failed: $failed"
	else
		event "$1" "$2" access_restart "${done:--}" ok
	fi
}

cmd_act() {
	local b="$1" p="$2" a="$3" target="$4" m="$5" led=""
	[ -f "$ETC/led" ] && read led < "$ETC/led"
	blink "$led" &
	case "$a" in
	wifi_toggle) act_wifi "$b" "$p" "$target" "${m:-0}" ;;
	firewall_restart) act_firewall "$b" "$p" ;;
	access_restart) act_access "$b" "$p" ;;
	*) event "$b" "$p" "$a" - "failed: unknown action" ;;
	esac
	wait
}

# At boot, before networking starts: a network a button turned on or off
# for a limited time goes back as it was (the timer died with the reboot).
cmd_boot() {
	local rec s prev tok rest
	for rec in "$ETC"/timed/*; do
		[ -f "$rec" ] || continue
		s="${rec##*/}"
		read prev tok rest < "$rec"
		rm -f "$rec"
		[ "$(uci -q get "wireless.$s")" = wifi-iface ] || continue
		set_disabled "$s" "$prev" norestart
		event boot timer wifi_toggle "$s $(state_word "$prev") 0" reverted
	done
}

# Everything back as it was before NetGrip: timed toggles end now, each
# button gets its original script back, and NetGrip's files go.
cmd_uninstall() {
	local rec s prev tok rest f b
	for rec in "$ETC"/timed/*; do
		[ -f "$rec" ] || continue
		s="${rec##*/}"
		read prev tok rest < "$rec"
		rm -f "$rec"
		[ "$(uci -q get "wireless.$s")" = wifi-iface ] && set_disabled "$s" "$prev"
	done
	for f in "$RCDIR"/*; do
		[ -f "$f" ] && grep -q netgrip-managed-button "$f" || continue
		b="${f##*/}"
		if [ -f "$ETC/orig/$b" ]; then
			cp "$ETC/orig/$b" "$f.netgrip-tmp" && chmod 755 "$f.netgrip-tmp" && mv "$f.netgrip-tmp" "$f"
		else
			rm -f "$f"
		fi
	done
	rm -f "$HOOK"
	rmdir "${HOOK%/*}" 2>/dev/null
	if [ -f "$INITD/netgrip-buttons" ]; then
		"$INITD/netgrip-buttons" disable 2>/dev/null
		rm -f "$INITD/netgrip-buttons"
	fi
	rm -rf "$ETC" "$STATE"
	rm -f "$SELF"
}

cmd="$1"
[ $# -gt 0 ] && shift
case "$cmd" in
rc) cmd_rc "$@" ;;
seen) record_seen ;;
fire) cmd_fire "$@" ;;
act) cmd_act "$@" ;;
revert) cmd_revert "$@" ;;
boot) cmd_boot ;;
uninstall) cmd_uninstall ;;
*)
	echo "usage: $0 rc|seen|fire|act|revert|boot|uninstall" >&2
	exit 1
	;;
esac
