#!/bin/bash

DIR="$(cd "$(dirname "$0")" && pwd)"
MY_PATH=$DIR/nftables.sh

NETFILTER_MARK=255
IPROUTE2_TABLE_ID=100

#FWI=$(uci -q get firewall.myproxy.path 2>/dev/null)


gen_nftset() {
	local nftset_name="${1}"; shift
	local ip_type="${1}"; shift
	mkdir -p $TMP_PATH2/nftset

	cat > "$TMP_PATH2/nftset/$nftset_name" <<-EOF
		define $nftset_name = {$@}
		add set inet myproxy $nftset_name { type $ip_type; flags interval; auto-merge; }	
		add element inet myproxy $nftset_name \$$nftset_name
	EOF
	nft -f "$TMP_PATH2/nftset/$nftset_name"
	# rm "$TMP_PATH2/nftset/$nftset_name"
}

add_firewall_rule() {
	local tcp_proxy_way=$(config_t_get global proxy_mode redirect)
	echolog "proxy mode = $tcp_proxy_way" 
	local __nft=""

	# ip route replace default dev utun table "$IPROUTE2_TABLE_ID"
	# ip rule del fwmark "$NETFILTER_MARK" lookup "$IPROUTE2_TABLE_ID" > /dev/null 2> /dev/null
	# ip rule add fwmark "$NETFILTER_MARK" lookup "$IPROUTE2_TABLE_ID"
	# ip route add local 0.0.0.0/0 dev lo table "$IPROUTE2_TABLE_ID"
	ip route add local default dev lo table 100
	ip rule add fwmark 1 table 100

	nft 'add table inet myproxy'
	nft 'flush table inet myproxy'
	gen_nftset "LOCAL_SUBNET" ipv4_addr "127.0.0.0/8, 224.0.0.0/4, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12"
	if [ "$tcp_proxy_way" = "redirect" ]; then
		# __nft=$(cat <<- EOF
		# 	define LOCAL_SUBNET = {127.0.0.0/8, 224.0.0.0/4, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12}
		# 	table myproxy
		# 	flush table myproxy
		# 	table myproxy {
		# 	    # chain proxy {
        # 		# 	ip daddr \$LOCAL_SUBNET counter accept
        # 		# 	mark 0xff counter return
        # 		# 	ip protocol tcp redirect to :$REDIR_PORT 
        # 		# 	ip protocol udp tproxy to :$REDIR_PORT  meta mark set 1
    	# 		# }

		# 		  chain output {
		# 		    type nat hook output priority filter; policy accept;
		# 		    ip daddr \$LOCAL_SUBNET return
		# 		    ip protocol tcp redirect to :$REDIR_PORT 
		# 		  }
		# 		  chain prerouting {
		# 		    type nat hook prerouting priority dstnat; policy accept;
		# 		    ip protocol tcp redirect to :$REDIR_PORT 
		# 		    ip protocol udp redirect to :$REDIR_PORT 
		# 		  }
    	# 		# chain output {
        # 		# 	type route hook output priority 0; policy accept;
        # 		# 	ip daddr \$LOCAL_SUBNET counter accept
        # 		# 	meta mark 255 return
        # 		# 	ip protocol tcp meta mark set 1
        # 		# 	ip protocol udp meta mark set 1
        # 		# 	jump proxy
    	# 		# }
    	# 		# chain filter {
        #         #     type filter hook prerouting priority -150 ;
        #         #     # meta l4proto tcp socket transparent 1 meta mark set 1  accept
        #         #     jump proxy
        #         # }		
		# 	}			
		# EOF
		# )

		nft 'add chain inet myproxy MY_OUTPUT'
		nft 'add rule inet myproxy MY_OUTPUT ip daddr @LOCAL_SUBNET counter accept'
		nft 'add rule inet myproxy MY_OUTPUT meta mark 0x000000ff counter return'
		nft add rule inet myproxy MY_OUTPUT ip protocol tcp counter redirect to :${REDIR_PORT}

		nft 'add chain inet myproxy nat_output {type nat hook output priority filter - 1; policy accept;} '
		nft 'add rule inet myproxy nat_output ip protocol tcp counter jump MY_OUTPUT '

		nft 'add chain inet myproxy MY_DIVERT'
		nft 'add rule inet myproxy MY_DIVERT meta l4proto tcp socket transparent 1 meta mark set 0x00000001 counter accept'

		nft 'add chain inet myproxy MY_REDIRECT'

		nft 'add chain inet myproxy MY_RULE'
		nft 'add rule inet myproxy MY_RULE meta mark set ct mark counter '
		nft 'add rule inet myproxy MY_RULE meta mark 0x00000001 counter return '
		nft 'add rule inet myproxy MY_RULE tcp flags syn / fin,syn,rst,ack meta mark set meta mark & 0x00000001 | 0x00000001 counter  '
		nft 'add rule inet myproxy MY_RULE meta l4proto udp ct state new meta mark set meta mark & 0x00000001 | 0x00000001 counter'
		nft 'add rule inet myproxy MY_RULE ct mark set meta mark counter '

		nft 'add chain inet myproxy MY_MANGLE'
		nft 'add rule inet myproxy MY_MANGLE ip daddr @LOCAL_SUBNET counter return'
		nft 'add rule inet myproxy  ip protocol udp udp dport 53 counter return'
		nft 'add rule inet myproxy MY_MANGLE udp dport { 80, 443 } ip daddr 198.18.0.0/16 counter drop'

		nft 'add chain inet myproxy MY_OUTPUT_MANGLE'
		nft 'add rule inet myproxy MY_OUTPUT_MANGLE  ip daddr @LOCAL_SUBNET counter return'
		nft 'add rule inet myproxy MY_OUTPUT_MANGLE  meta mark 0x000000ff counter return'
		nft 'add rule inet myproxy MY_OUTPUT_MANGLE  ip protocol udp ip daddr 198.18.0.0/16 udp dport { 80, 443 } counter drop'

		nft 'add chain inet myproxy MYPROXY'
		nft 'add rule inet myproxy MYPROXY ip daddr @LOCAL_SUBNET counter return'
		nft add rule inet myproxy MYPROXY ip protocol tcp ip daddr 198.18.0.0/16 counter redirect to :${REDIR_PORT}
		nft add rule inet myproxy MYPROXY ip protocol tcp counter redirect to :${REDIR_PORT}

		nft 'add chain inet myproxy mangle_output {type route hook output priority mangle; policy accept;}'
		nft 'add rule inet myproxy mangle_output oif "lo" counter return'
		nft 'add rule inet myproxy mangle_output meta mark 0x00000001 counter return'

		nft 'add chain inet myproxy mangle_prerouting {type filter hook prerouting priority mangle; policy accept;}'
		nft 'add rule inet myproxy mangle_prerouting counter jump MY_DIVERT'
		nft 'add rule inet myproxy mangle_prerouting meta nfproto ipv4 counter jump MY_MANGLE'

		nft 'add chain inet myproxy dstnat { type nat hook prerouting priority dstnat; policy accept;} '
		nft 'add rule inet myproxy dstnat jump MY_REDIRECT'
		nft 'add rule inet myproxy dstnat ip protocol tcp counter jump MYPROXY'

	elif [ "$tcp_proxy_way" = "tproxy" ]; then
		echolog "tproxy mode..."
		nft 'add chain inet myproxy proxy {type filter hook prerouting priority 0; policy accept;}'
		nft 'add rule inet myproxy proxy ip protocol != { tcp, udp } accept'
		nft 'add rule inet myproxy proxy ip daddr @LOCAL_SUBNET accept'
		nft 'add rule inet myproxy proxy mark 0xff counter return'
		nft add rule myproxy proxy meta l4proto {tcp, udp} mark set 1 tproxy to :${REDIR_PORT} counter accept

		nft 'add chain inet myproxy ouput {type route hook output priority 0; policy accept;}'
		nft 'add rule inet myproxy ouput ip daddr @LOCAL_SUBNET accept'
		nft 'add rule inet myproxy ouput mark 255 counter return'
		nft 'add rule inet myproxy ouput meta l4proto {tcp, udp} mark set 1 counter accept'

		nft 'add chain inet myproxy filter {type filter hook prerouting priority -150 ;}'
		nft 'add rule inet myproxy filter meta l4proto tcp socket transparent 1 meta mark set 1  accept'
	else 
		echolog "tun mode..."
		nft 'add chain inet myproxy local {type route hook output priority 0; policy accept;}'
		nft 'add rule inet myproxy local ip protocol != { tcp, udp } accept'
		nft 'add rule inet myproxy local ip daddr @LOCAL_SUBNET accept'
		nft 'add rule inet myproxy local ct state new ct mark set 255 counter'
		nft 'add rule inet myproxy local ct mark 255 mark set 255 counter'

		nft 'add chain inet myproxy forward {type filter hook prerouting priority 0; policy accept;}'
		nft 'add rule inet myproxy forward ip protocol != { tcp, udp } accept'
		nft 'add rule inet myproxy forward iifname "utun" accept'
		nft 'add rule inet myproxy forward ip daddr @LOCAL_SUBNET accept'
		nft 'add rule inet myproxy forward mark set 255'

	fi
}

del_firewall_rule() {
	
	# ip route del default dev utun table "$IPROUTE2_TABLE_ID"
	# ip rule del fwmark "$NETFILTER_MARK" lookup "$IPROUTE2_TABLE_ID"
	# ip route del local 0.0.0.0/0 dev lo table "$IPROUTE2_TABLE_ID" 2>/dev/null
	ip route del local default dev lo table 100
	ip rule del table 100

	nft delete table inet myproxy
	# nft -f - << EOF
	# 	flush table clash
	# 	delete table clash
	# EOF
}

start() {
	add_firewall_rule
	# gen_include
}

stop() {
	del_firewall_rule
	# flush_include
}



arg1=$1
shift
case $arg1 in
stop)
	stop
	;;
start)
	start
	;;
*) ;;
esac
