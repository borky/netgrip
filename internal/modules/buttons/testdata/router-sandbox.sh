#!/bin/sh
# Run on a router (as root), from a workstation:
#   cat internal/modules/buttons/netgrip-button.sh | ssh root@ROUTER "cat > /tmp/ngbtest-runner.sh"
#   cat internal/modules/buttons/testdata/router-sandbox.sh | ssh root@ROUTER "cat > /tmp/ngbtest-harness.sh; MODE=minimal NGB_MINUTE=4 sh /tmp/ngbtest-harness.sh"
# It touches nothing outside /tmp/ngbtest and checks that at the end (H, H2).
# Sandbox test of netgrip-button on the router's busybox ash with the real
# uci on a throwaway config directory (every uci write here uses its own -t
# directory). Only wifi, logger and init scripts are fakes. MODE=minimal
# keeps only basic busybox applets on the PATH.
R=/tmp/ngbtest
rm -rf $R; mkdir -p $R/bin $R/etc/orig $R/initd $R/state $R/config $R/rc $R/rom $R/w.d
REAL_MD5=$(/bin/busybox md5sum /etc/config/wireless | /bin/busybox cut -d' ' -f1); REAL_UCI=$(/bin/busybox ls -l --full-time /tmp/.uci/ | /bin/busybox md5sum)
cp /tmp/ngbtest-runner.sh $R/runner; chmod 755 $R/runner
export NGB_STATE=$R/state NGB_ETC=$R/etc NGB_SELF=$R/runner NGB_LEDS=$R/leds NGB_INITD=$R/initd NGB_MINUTE=${NGB_MINUTE:-4}
export NGB_CONFIG=$R/config NGB_RCDIR=$R/rc NGB_ROMRC=$R/rom NGB_HOOK=$R/hook/00-netgrip
printf '#!/bin/sh\necho "wifi $*" >> /tmp/ngbtest/log\n' > $R/bin/wifi
printf '#!/bin/sh\n:\n' > $R/bin/logger
for s in firewall dropbear netgrip; do
  printf '#!/bin/sh\n[ "$1" = enabled ] && exit 0\necho "initd %s $1" >> /tmp/ngbtest/log\n' $s > $R/initd/$s
done
chmod 755 $R/bin/* $R/initd/*
if [ "${MODE:-}" = minimal ]; then
	for a in mkdir rm cat cp mv chmod ls sleep date wc tail sed grep awk readlink ps cut id; do ln -s /bin/busybox $R/bin/$a; done
	ln -s /sbin/uci $R/bin/uci
	export PATH=$R/bin
else
	for a in awk sed grep; do ln -s /bin/busybox $R/bin/$a; done
	export PATH=$R/bin:$PATH
fi
echo "MODE=${MODE:-busybox} MINUTE=$NGB_MINUTE"
L=$R/log; : > $L
cat > $R/config/wireless <<'W'
config wifi-device 'radio9'
	option type 'mac80211'

config wifi-iface 'wl1'
	option device 'radio9'
	option mode 'ap'
	option ssid 'Sandbox'
	option key 'not-a-real-key'
	option disabled '1'
W
chmod 600 $R/config/wireless
printf '#!/bin/sh\necho "ORIG reset $ACTION $SEEN" >> /tmp/ngbtest/log\n[ "$ACTION" = pressed ] && return 5\nreturn 0\n' > $R/etc/orig/reset
chmod 755 $R/etc/orig/reset
u() { /sbin/uci -q -c $R/config -t $R/w.d "$@"; }
dis() { u get wireless.wl1.disabled; }
ev() { BUTTON=$1 ACTION=$2 SEEN=$3 $R/runner rc $1 $4; echo $?; }
press() { ev $1 pressed 0 $2 >/dev/null; ev $1 released ${3:-0} $2 >/dev/null; }
ok() { if eval "$2"; then echo "PASS $1"; else echo "FAIL $1"; fi; }
M=$NGB_MINUTE

printf 'reset press 2 wifi_toggle wl1 1\nreset hold 2 firewall_restart - 0\n' > $R/etc/actions
echo "== A slow single press forwarded with SEEN=1"
press reset 5 1; sleep 3; ok A 'grep -q "ORIG reset released 1" $L'; : > $L
echo "== B double press toggles on for a while, then back"
press reset 5; press reset 5; sleep 3
ok B '[ "$(dis)" = 0 ]'
ok B2 'grep -q "option key '"'"'not-a-real-key'"'"'" $R/config/wireless'
ok B3 'ls -l $R/config/wireless | grep -q "^-rw-------"'
ok B4 'grep -q "wifi reconf radio9" $L'
ok B7 '! ps w | grep -q "[r]unner act"'
ok B8 '! ls -d $R/state/wl.* >/dev/null 2>&1'
sleep $((M + 2)); ok B6 '[ "$(dis)" = 1 ]'; : > $L
echo "== C extra press absorbed"
press reset 5; press reset 5; press reset 5; sleep 3; ok C '! grep -q "ORIG reset released" $L'; sleep $((M + 2)); : > $L
echo "== D holds"
ev reset released 3 0 >/dev/null; sleep 1; ok D 'grep -q "initd firewall restart" $L'; : > $L
ev reset released 9 0 >/dev/null; sleep 1; ok D2 'grep -q "ORIG reset released 9" $L'
echo "== J switch on, off after the time"
printf 'reset press 1 wifi_on wl1 1\n' > $R/etc/actions; rm -f $R/state/quiet.reset
u set wireless.wl1.disabled=1; u commit wireless
press reset 5; sleep 1; ok J '[ "$(dis)" = 0 ]'
sleep $((M / 2)); press reset 5; sleep 1; ok J2 '[ "$(dis)" = 0 ]'
sleep $((M / 2 + 1)); ok J3 '[ "$(dis)" = 0 ]'
sleep $((M / 2 + 1)); ok J4 '[ "$(dis)" = 1 ]'
u set wireless.wl1.disabled=0; u commit wireless
sleep 2; press reset 5; sleep $((M + 2)); ok J5 '[ "$(dis)" = 1 ]'
ok J6 'grep -q "	wifi_on	" $R/state/events'
ok J7 '[ ! -f $R/etc/timed/wl1 ] && ! ls $R/state/hold/wl1 >/dev/null 2>&1'
echo "== K switch on during a timed toggle: the toggle's original state comes back"
printf 'reset press 1 wifi_toggle wl1 3\nreset hold 2 wifi_on wl1 1\n' > $R/etc/actions; rm -f $R/state/quiet.reset
u set wireless.wl1.disabled=0; u commit wireless
press reset 5; sleep 2; ok K '[ "$(dis)" = 1 ]'
ev reset released 2 5 >/dev/null; sleep 1; ok K2 '[ "$(dis)" = 0 ]'
sleep $((M + 2)); ok K3 '[ "$(dis)" = 0 ]'
ok K4 '[ ! -f $R/etc/timed/wl1 ]'
echo "== L quarantine pause: a request for NetGrip (the sandbox's own state dir: the real NetGrip never sees it)"
printf 'reset press 1 quarantine_pause - 45\n' > $R/etc/actions; rm -f $R/state/quiet.reset
echo /usr/sbin/netgrip > $R/etc/daemon   # the real NetGrip runs there
press reset 5; sleep 1
ok L 'ls $R/state/request.* >/dev/null 2>&1 && grep -q "^quarantine_pause 45 reset press1 [0-9]*$" $R/state/request.*'
ok L2 '! ls $R/state/.request.* >/dev/null 2>&1'
rm -f $R/state/request.*
echo /nonexistent/netgrip > $R/etc/daemon   # NetGrip "not running"
sleep 2; press reset 5; sleep 1
ok L3 '! ls $R/state/request.* >/dev/null 2>&1 && grep -q "	quarantine_pause	-	failed: NetGrip is not running" $R/state/events'
echo "== M a state directory someone else could write is recreated"
chmod 777 $R/state; BUTTON=reset ACTION=released SEEN=0 $R/runner seen
ok M 'ls -ldn $R/state | grep -q "^drwxr-xr-x"'
echo "== G uninstall"
printf '#!/bin/sh\n# netgrip-managed-button\n' > $R/rc/reset; mkdir -p $R/hook; echo x > $R/hook/00-netgrip
$R/runner uninstall
ok G 'grep -q ORIG $R/rc/reset && [ ! -f $R/runner ] && [ ! -d $R/etc ] && [ ! -f $R/hook/00-netgrip ]'
echo "== H real config and pending changes untouched"
ok H '[ "$(/bin/busybox md5sum /etc/config/wireless | /bin/busybox cut -d" " -f1)" = "$REAL_MD5" ]'
ok H2 '[ "$(/bin/busybox ls -l --full-time /tmp/.uci/ | /bin/busybox md5sum)" = "$REAL_UCI" ]'
cd /; rm -rf $R /tmp/ngbtest-runner.sh /tmp/ngbtest-harness.sh
