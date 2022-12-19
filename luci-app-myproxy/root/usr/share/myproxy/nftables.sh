#!/bin/bash

DIR="$(cd "$(dirname "$0")" && pwd)"
MY_PATH=$DIR/nftables.sh

NETFILTER_MARK=255
IPROUTE2_TABLE_ID=100

FWI=$(uci -q get firewall.myproxy.path 2>/dev/null)


gen_nftset() {
	local nftset_name="${1}"; shift
	local ip_type="${1}"; shift
	mkdir -p $TMP_PATH2/nftset

	cat > "$TMP_PATH2/nftset/$nftset_name" <<-EOF
		define $nftset_name = {$@}
		add set myproxy $nftset_name { type $ip_type; flags interval; auto-merge; }	
		add element myproxy $nftset_name \$$nftset_name
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

	nft 'add table myproxy'
	nft 'flush table myproxy'
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

		nft 'add chain myproxy proxy '
		nft 'add rule myproxy proxy ip protocol != { tcp, udp } accept '
		nft 'add rule myproxy proxy ip daddr @LOCAL_SUBNET accept '
		nft 'add rule myproxy proxy mark 0xff counter return'
		nft add rule myproxy proxy ip protocol tcp redirect to :${REDIR_PORT}

		nft 'add chain myproxy ouput {type nat hook output priority filter; policy accept;}'
		nft 'add rule myproxy ouput goto proxy'

		nft 'add chain myproxy prerouting {type nat hook prerouting priority dstnat; policy accept;}'
		nft 'add rule myproxy prerouting goto proxy'

		nft 'add chain myproxy filter'
		nft 'add rule myproxy filter ip protocol != { tcp, udp } accept'
		nft 'add rule myproxy filter ip daddr @LOCAL_SUBNET accept'
		nft 'add rule myproxy filter mark 0xff counter return'

		nft 'add chain myproxy udpoutpout {type route hook output priority mangle; policy accept;}'
		nft 'add rule myproxy udpoutpout jump filter'
		nft 'add rule myproxy udpoutpout ip protocol udp mark set 255'

		nft 'add chain myproxy udprout {type filter hook prerouting priority mangle; policy accept;}'
		nft 'add rule myproxy udprout jump filter'
		nft add rule myproxy udprout ip protocol udp tproxy to :${REDIR_PORT}


	elif [ "$tcp_proxy_way" = "tproxy" ]; then
		# __nft=$(cat <<- EOF
		# 	define LOCAL_SUBNET = {127.0.0.0/8, 224.0.0.0/4, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12}
		# 	table myproxy
		# 	flush table myproxy
		# 	table myproxy {
    	# 		chain proxy {
        # 			type filter hook prerouting priority 0; policy accept;
        # 			ip daddr \$LOCAL_SUBNET  accept
        #             mark 0xff counter return
        # 			meta l4proto {tcp, udp} mark set 1 tproxy to :$REDIR_PORT counter accept
    	# 		}
    	# 		chain output {
        # 			type route hook output priority 0; policy accept;
        # 			ip daddr \$LOCAL_SUBNET  accept
        # 			mark 255 counter return
        #             meta l4proto {tcp, udp} mark set 1 counter accept
    	# 		}		
        #         chain filter {
        #             type filter hook prerouting priority -150 ;
        #             meta l4proto tcp socket transparent 1 meta mark set 1  accept
        #         }
		# 	}		
		# EOF
		# )
		echolog "tproxy mode..."
		nft 'add chain myproxy proxy {type filter hook prerouting priority 0; policy accept;}'
		nft 'add rule myproxy proxy ip protocol != { tcp, udp } accept'
		nft 'add rule myproxy proxy ip daddr @LOCAL_SUBNET accept'
		nft 'add rule myproxy proxy mark 0xff counter return'
		nft add rule myproxy proxy meta l4proto {tcp, udp} mark set 1 tproxy to :${REDIR_PORT} counter accept

		nft 'add chain myproxy ouput {type route hook output priority 0; policy accept;}'
		nft 'add rule myproxy ouput ip daddr @LOCAL_SUBNET accept'
		nft 'add rule myproxy ouput mark 255 counter return'
		nft 'add rule myproxy ouput meta l4proto {tcp, udp} mark set 1 counter accept'

		nft 'add chain myproxy filter {type filter hook prerouting priority -150 ;}'
		nft 'add rule myproxy filter meta l4proto tcp socket transparent 1 meta mark set 1  accept'
	else 
		# __nft=$(cat <<- EOF
		# 	define LOCAL_SUBNET = {127.0.0.0/8, 224.0.0.0/4, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12}
		# 	table myproxy
		# 	flush table myproxy
		# 	table myproxy {
		# 	    chain local {
		# 	        type route hook output priority 0; policy accept;
			        
		# 	        ip protocol != { tcp, udp } counter accept
			        
			        
		# 	        ip daddr \$LOCAL_SUBNET counter accept
			        
		# 	        ct state new ct mark set $NETFILTER_MARK counter
		# 	        ct mark $NETFILTER_MARK mark set $NETFILTER_MARK counter
		# 	    }
			    
		# 	    chain forward {
		# 	        type filter hook prerouting priority 0; policy accept;
			        
		# 	        ip protocol != { tcp, udp } counter accept 
			    
			        
		# 	        ip daddr \$LOCAL_SUBNET counter accept
			        
		# 	        mark set $NETFILTER_MARK 
		# 	    }
		# 	}			
		# EOF
		# )
		echolog "tun mode..."
		nft 'add chain myproxy local {type route hook output priority 0; policy accept;}'
		nft 'add rule myproxy local ip protocol != { tcp, udp } accept'
		nft 'add rule myproxy local ip daddr @LOCAL_SUBNET accept'
		nft 'add rule myproxy local ct state new ct mark set 255 counter'
		nft 'add rule myproxy local ct mark 255 mark set 255 counter'

		nft 'add chain myproxy forward {type filter hook prerouting priority 0; policy accept;}'
		nft 'add rule myproxy forward ip protocol != { tcp, udp } accept'
		nft 'add rule myproxy forward iifname "utun" accept'
		nft 'add rule myproxy forward ip daddr @LOCAL_SUBNET accept'
		nft 'add rule myproxy forward mark set 255'

	fi
		# echo "" > $FWI
		# cat <<-EOF >> $FWI
			# ${__nft}
		# EOF
		# nft 'add table myproxy'
		# gen_nftset "LOCAL_SUBNET" ipv4_addr '127.0.0.0/8, 224.0.0.0/4, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12'
		# nft -f - << EOF

		# EOF		

		# nft -f $FWI
}

del_firewall_rule() {
	
	# ip route del default dev utun table "$IPROUTE2_TABLE_ID"
	# ip rule del fwmark "$NETFILTER_MARK" lookup "$IPROUTE2_TABLE_ID"
	# ip route del local 0.0.0.0/0 dev lo table "$IPROUTE2_TABLE_ID" 2>/dev/null
	ip route del local default dev lo table 100
	ip rule del table 100

	nft delete table myproxy
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
