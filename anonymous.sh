#!/bin/sh

# BackBox Script for Anonymous Internet Navigation
#
# This script is intended to set up your BackBox machine to guarantee 
# anonymity through Tor. Additionally, the script takes further steps to 
# prevent data leakage by killing dangerous processes, changing MAC 
# address and IP information and so on.
#
# Author: Raffaele Forte <raffaele@backbox.org>
# Version: 1.7

# The UID under which Tor runs as (varies from system to system)
TOR_UID="debian-tor"

# Tor's TransPort
TRANS_PORT="9040"

# Tor's DNSPort
DNS_PORT="9053"

# Tor's VirtualAddrNetworkIPv4
VIRT_ADDR="10.192.0.0/10"

# LAN destinations that shouldn't be routed through Tor
# Check reserved block.
NON_TOR="127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"

# Other IANA reserved blocks (These are not processed by tor and dropped by default)
RESV_IANA="0.0.0.0/8 100.64.0.0/10 169.254.0.0/16 192.0.0.0/24 192.0.2.0/24 192.88.99.0/24 198.18.0.0/15 198.51.100.0/24 203.0.113.0/24 224.0.0.0/3"

# List of process names that should be killed, separated by spaces
TO_KILL="chrome dropbox firefox pidgin skype thunderbird xchat"

# List of BleachBit cleaners, separated by spaces
BLEACHBIT_CLEANERS="bash.history system.cache system.clipboard system.custom system.recent_documents system.rotated_logs system.tmp system.trash"

# Overwrite files to hide contents
OVERWRITE="true"

# The default local hostname
REAL_HOSTNAME="backbox"

# Include default options, if any
if [ -f /etc/default/backbox-anonymous ] ; then
	. /etc/default/backbox-anonymous
fi

# General-purpose Yes/No prompt function
ask() {
	while true; do
		if [ "${2:-}" = "Y" ]; then
			prompt="Y/n"
			default=Y
		elif [ "${2:-}" = "N" ]; then
			prompt="y/N"
			default=N
		else
			prompt="Ok"
			default=OK
		fi
 
		# Ask the question
		echo
		read -p "$1 [$prompt] > " REPLY
 
		# Default?
		if [ -z "$REPLY" ]; then
			REPLY=$default
		fi
 
		# Check if the reply is valid
		case "$REPLY" in
			Y*|y*) return 0 ;;
			N*|n*) return 1 ;;
			O*|o*) return 1 ;;
		esac
	done
}

# Change the wlp2s0 interface MAC Address
change_mac() {
        case $1 in
        "start")
                echo "Cambiando la direccion MAC"
                sudo ifconfig wlp2s0 down
                sudo service network-manager stop
                sudo macchanger -a wlp2s0
                sudo service network-manager restart
                ;;
        "stop")
                echo "Reestableciendo la direccion MAC"
                sudo ifconfig wlp2s0 down
                sudo service network-manager stop
                sudo macchanger -p wlp2s0
                sudo service network-manager restart
                ;;
        *)
                echo "Opciones: start|stop"
                ;;
        esac
}

# Change the local hostname
change_hostname() {
	
	echo

	CURRENT_HOSTNAME=$(hostname)

	clean_dhcp

	RANDOM_HOSTNAME=$(shuf -n 1 /etc/dictionaries-common/words | sed -r 's/[^a-zA-Z]//g' | awk '{print tolower($0)}')

	NEW_HOSTNAME=${1:-$RANDOM_HOSTNAME}

	echo "$NEW_HOSTNAME" > /etc/hostname
	sed -i 's/127.0.1.1.*/127.0.1.1\t'"$NEW_HOSTNAME"'/g' /etc/hosts

	echo " * Starting hostname service"
	systemctl start hostname 2>/dev/null
	hostnamectl set-hostname "$NEW_HOSTNAME"
	to_sleep

	if [ -f "$HOME/.Xauthority" ] ; then
		su "$SUDO_USER" -c "xauth -n list | grep -v $CURRENT_HOSTNAME | cut -f1 -d\ | xargs -i xauth remove {}"
		su "$SUDO_USER" -c "xauth add $(xauth -n list | tail -1 | sed 's/^.*\//'$NEW_HOSTNAME'\//g')"
		echo " * X authority file updated"
	fi
	
	avahi-daemon --kill 2>/dev/null

	echo " * Hostname changed to $NEW_HOSTNAME"
}

# Check Tor configs
check_configs() {

	grep -q -x 'RUN_DAEMON="yes"' /etc/default/tor
	if [ $? -ne 0 ]; then
		echo "\n[!] Please add the following to your '/etc/default/tor' and restart the service:\n"
		echo ' RUN_DAEMON="yes"\n'
		exit 1
	fi

	grep -q -x 'VirtualAddrNetwork 10.192.0.0/10' /etc/tor/torrc
	VAR1=$?

	grep -q -x 'TransPort 9040' /etc/tor/torrc
	VAR2=$?

	grep -q -x 'DNSPort 9053' /etc/tor/torrc
	VAR3=$?

	grep -q -x 'AutomapHostsOnResolve 1' /etc/tor/torrc
	VAR4=$?

	if [ $VAR1 -ne 0 ] || [ $VAR2 -ne 0 ] || [ $VAR3 -ne 0 ] || [ $VAR4 -ne 0 ]; then
		echo "\n[!] Please add the following to your '/etc/tor/torrc' and restart service:\n"
		echo ' VirtualAddrNetwork 10.192.0.0/10'
		echo ' TransPort 9040'
		echo ' DNSPort 9053'
		echo ' AutomapHostsOnResolve 1\n'
		exit 1
	fi
}

# Check if this environment runs from a LiveCD or USB Stick
check_livecd() {
	grep -q -x 'backbox:x:999:999:Live session user,,,:/home/backbox:/bin/bash' /etc/passwd
	if [ $? -eq 0 ]; then
		echo " * Loading system_tor AppArmor profile into the kernel"
		apparmor_parser -r /etc/apparmor.d/system_tor -C
	fi
}

# Make sure that only root can run this script
check_root() {
	if [ "$(id -u)" -ne 0 ]; then
		echo "\n[!] This script must run as root\n" >&2
		exit 1
	fi
}

# Release DHCP address
clean_dhcp() {
	dhclient -r
	rm -f /var/lib/dhcp/dhclient*
	echo " * DHCP address released"
}

flush_iptables() {
	# Don't lock yourself out after the flush
	iptables -P INPUT ACCEPT
	iptables -P OUTPUT ACCEPT
	# flush iptables
	iptables -F
	iptables -t nat -F
	echo " * Deleted all iptables rules"
}

# Kill processes at startup
kill_process() {
	if [ "$TO_KILL" != "" ]; then
		killall -q $TO_KILL
		echo "\n * Killed processes to prevent leaks"
	fi
}

# BackBox implementation of Transparently Routing Traffic Through Tor
# https://trac.torproject.org/projects/tor/wiki/doc/TransparentProxy
redirect_to_tor() {
	
	echo

	if ! [ -f /etc/network/iptables.rules ]; then
		iptables-save > /etc/network/iptables.rules
		echo " * Saved iptables rules"
	fi

	flush_iptables

	# nat .onion addresses
	iptables -t nat -A OUTPUT -d $VIRT_ADDR -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j REDIRECT --to-ports $TRANS_PORT

	# nat dns requests to Tor
	iptables -t nat -A OUTPUT -d 127.0.0.1/32 -p udp -m udp --dport 53 -j REDIRECT --to-ports $DNS_PORT

	# don't nat the Tor process, the loopback, or the local network
	iptables -t nat -A OUTPUT -m owner --uid-owner $TOR_UID -j RETURN
	iptables -t nat -A OUTPUT -o lo -j RETURN

	for _lan in $NON_TOR; do
		iptables -t nat -A OUTPUT -d $_lan -j RETURN
	done

	for _iana in $RESV_IANA; do
		iptables -t nat -A OUTPUT -d $_iana -j RETURN
	done

	# redirect whatever fell thru to Tor's TransPort
	iptables -t nat -A OUTPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j REDIRECT --to-ports $TRANS_PORT

	# *filter INPUT
	iptables -A INPUT -m state --state ESTABLISHED -j ACCEPT
	iptables -A INPUT -i lo -j ACCEPT

	iptables -A INPUT -j DROP

	# *filter FORWARD
	iptables -A FORWARD -j DROP

	# *filter OUTPUT
	iptables -A OUTPUT -m state --state INVALID -j DROP

	iptables -A OUTPUT -m state --state ESTABLISHED -j ACCEPT

	# allow Tor process output
	iptables -A OUTPUT -m owner --uid-owner $TOR_UID -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -m state --state NEW -j ACCEPT

	# allow loopback output
	iptables -A OUTPUT -d 127.0.0.1/32 -o lo -j ACCEPT

	# tor transproxy magic
	iptables -A OUTPUT -d 127.0.0.1/32 -p tcp -m tcp --dport $TRANS_PORT --tcp-flags FIN,SYN,RST,ACK SYN -j ACCEPT

	# allow access to lan hosts in $NON_TOR
	for _lan in $NON_TOR; do
		iptables -A OUTPUT -d $_lan -j ACCEPT
	done

	# Log & Drop everything else.
	iptables -A OUTPUT -j LOG --log-prefix "Dropped OUTPUT packet: " --log-level 7 --log-uid
	iptables -A OUTPUT -j DROP

	# Set default policies to DROP
	iptables -P INPUT DROP
	iptables -P FORWARD DROP
	iptables -P OUTPUT DROP
}

# BleachBit cleaners to delete unnecessary files to preserve anonymity
run_bleachbit() {
	if [ "$OVERWRITE" = "true" ] ; then
		echo -n "\n * Deleting and overwriting unnecessary files... "
		bleachbit -o -c $BLEACHBIT_CLEANERS >/dev/null
	else
		echo -n "\n * Deleting unnecessary files... "
		bleachbit -c $BLEACHBIT_CLEANERS >/dev/null
	fi

	echo "Done!"
}

to_sleep() {
	sleep 3
}

warning() {
	echo "\n[!] WARNING! This is a simple script that prevents most common system data"
	echo "    leaks. Your coumputer behaviour is the key to guarantee you strong privacy"
	echo "    protection and anonymity."
	
	echo "\n[i] Please edit /etc/default/backbox-anonymous with your custom values."
}

do_start() {
	check_configs
	check_root
	
	warning

	echo "\n[i] Starting anonymous mode"
	
	if ask "Do you want to kill running processes to prevent leaks?" Y; then
		kill_process
	else
		echo
	fi

	check_livecd
	
	if ask "Do you want transparent routing through Tor?" Y; then
		redirect_to_tor
	else
		echo
	fi

	echo -n "\nChangeing MAC address via Network-Manager."
	change_mac start
	
	if ask "Do you want to change the local hostname? It will cause disconnection" Y; then
		read -p "Type it or press Enter for a random one > " CHOICE

		echo -n "\n * Stopping network-manager service"
		systemctl stop network-manager 2>/dev/null
		to_sleep

		if [ "$CHOICE" = "" ]; then
			change_hostname
		else
			change_hostname "$CHOICE"
		fi
		
		echo " * Starting network-manager service"
		systemctl start network-manager 2>/dev/null
		to_sleep
	else
		echo
	fi

	echo " * Restarting tor service"
	systemctl restart tor 2>/dev/null
	to_sleep
	echo
	
	if [ ! -e /var/run/tor/tor.pid ]; then
		echo "\n[!] Tor is not running! Quitting...\n"
		exit 1
	fi
}

do_stop() {

	check_root

	echo "\n[i] Stopping anonymous mode"
	
	if ask "Do you want to kill running processes to prevent leaks?" Y; then
		kill_process
	else
		echo
	fi
	
	flush_iptables

	if [ -f /etc/network/iptables.rules ]; then
		iptables-restore < /etc/network/iptables.rules
		rm /etc/network/iptables.rules
		echo " * Restored iptables rules"
	fi

	echo -n "\nMAC address cannot be changed. Change it manually via Network-Manager."
	ask "Type Ok or press Enter when you are done"
	change_mac stop
	if ask "Do you want to change the local hostname? It will cause disconnection" Y; then
		read -p "Type it or press Enter to restore default [$REAL_HOSTNAME] > " CHOICE

		echo -n "\n * Stopping network-manager service"
		systemctl stop network-manager 2>/dev/null
		to_sleep

		if [ "$CHOICE" = "" ]; then
			change_hostname $REAL_HOSTNAME
		else
			change_hostname "$CHOICE"
		fi

		echo " * Starting network-manager service"
		systemctl start network-manager 2>/dev/null
		to_sleep
	fi
	
	if [ "$DISPLAY" ]; then
		if ask "Delete unnecessary files to preserve your anonymity?" Y; then
			run_bleachbit
		fi
	fi

	echo
}

do_status() {

	echo "\n[i] Showing anonymous status\n"

	ifconfig -a | grep "encap:Ethernet" | awk '{print " * " $1, $5}'

	CURRENT_HOSTNAME=$(hostname)
	echo " * Hostname $CURRENT_HOSTNAME"
	
	HTML=$(curl -s https://check.torproject.org/?lang=en_US)
	IP=$(echo "$HTML" | egrep -m1 -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')

	echo "$HTML" | grep -q "Congratulations. This browser is configured to use Tor."

	if [ $? -ne 0 ]; then
		echo " * IP $IP"
		echo " * Tor OFF\n"
		exit 3
	else
		echo " * IP $IP"
		echo " * Tor ON\n"
	fi
}

case "$1" in
	start)
		do_start
	;;
	stop)
		do_stop
	;;
	status)
		do_status
	;;
	*)
		echo "Usage: $0 {start|stop|status}" >&2
		exit 3
	;;
esac

exit 0
