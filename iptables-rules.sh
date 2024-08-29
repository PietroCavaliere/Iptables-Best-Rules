#!/bin/bash

#Author: Pietro Cavaliere
#Version: 0.1

# Find installed iptables binaries
find_iptables_versions() {
    iptables_paths=$(compgen -c | grep '^iptables')
    echo "Found iptables versions:"
    echo "$iptables_paths"
}

# Function to select an iptables version
select_iptables_version() {
    echo "Select the iptables version you want to use:"
    echo "$iptables_paths" | nl
    echo "Enter the number of the version you want to select:"
    read -r version_number
    
    selected_iptables=$(echo "$iptables_paths" | sed -n "${version_number}p")
    echo "You have selected: $selected_iptables"
}

# Function to reset iptables configurations
reset_iptables() {
    echo "Do you want to reset all iptables configurations? (y/N)"
    read -r reset_choice
    
    case $reset_choice in
        [yY][eE][sS]|[yY])
            echo "Resetting iptables configurations..."
            sudo $selected_iptables -F
            sudo $selected_iptables -X
            sudo $selected_iptables -t nat -F
            sudo $selected_iptables -t nat -X
            sudo $selected_iptables -t mangle -F
            sudo $selected_iptables -t mangle -X
            sudo $selected_iptables -P INPUT DROP
            sudo $selected_iptables -P FORWARD DROP
            sudo $selected_iptables -P OUTPUT ACCEPT
            sudo $selected_iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
            echo "Configurations reset."
            ;;
        *)
            echo "No changes made."
            ;;
    esac
}

# Function to accept connections on specific ports
accept_ports() {
    echo "Enter the ports you want to accept (format: 22,23,24,25):"
    read -r ports
    
    IFS=',' read -ra port_array <<< "$ports"
    
    for port in "${port_array[@]}"; do
        echo "Accepting connections on port $port"
        sudo $selected_iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
    done
    
    echo "The following ports have been configured to accept connections: $ports"
}

# Function to accept local traffic
accept_local_traffic() {
    echo "Configuring acceptance of local traffic..."
    sudo $selected_iptables -A INPUT -i lo -j ACCEPT
    sudo $selected_iptables -A OUTPUT -o lo -j ACCEPT
    echo "Local traffic accepted."
}

# Function to load basic firewall configurations
load_basic_firewall_config() {
    echo "Do you want to load basic firewall configurations? (y/N)"
    read -r load_choice
    
    case $load_choice in
        [yY][eE][sS]|[yY])
            echo "Loading basic firewall configurations..."
            
            # Limit TCP SYN packet rate
            sudo $selected_iptables -A INPUT -p tcp --tcp-flags FIN,SYN,RST,ACK SYN -m limit --limit 10/sec --limit-burst 20 -j ACCEPT

            # Log and drop port-scan attempts
            sudo $selected_iptables -A INPUT -m recent --name portscan --set -j LOG --log-prefix "Portscan:"
            sudo $selected_iptables -A FORWARD -m recent --name portscan --set -j LOG --log-prefix "Portscan:"
            sudo $selected_iptables -A INPUT -m recent --name portscan --set -j DROP
            sudo $selected_iptables -A FORWARD -m recent --name portscan --set -j DROP

            sudo $selected_iptables -A INPUT -m psd --psd-weight-threshold 25 --psd-delay-threshold 300 --psd-lo-ports-weight 3 --psd-hi-ports-weight 1 -j LOG --log-prefix "Port Scan Detected: "
            sudo $selected_iptables -A INPUT -m psd --psd-weight-threshold 25 --psd-delay-threshold 300 --psd-lo-ports-weight 3 --psd-hi-ports-weight 1 -j DROP

            # Reject TCP packets on all ports with reset
            sudo $selected_iptables -A INPUT -p tcp --dport 1:65535 -j REJECT --reject-with tcp-reset

            # Drop ICMP echo-request (ping) and other unnecessary ICMP types
            sudo $selected_iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
            sudo $selected_iptables -A INPUT -p icmp --icmp-type address-mask-request -j DROP
            sudo $selected_iptables -A INPUT -p icmp --icmp-type timestamp-request -j DROP
            sudo $selected_iptables -A INPUT -p icmp --icmp-type echo-request length 1000:65535 -j DROP
            sudo $selected_iptables -A INPUT -p icmp --icmp-type 8 -j DROP
            sudo $selected_iptables -A INPUT -p icmp --icmp-type redirect -j DROP
            sudo $selected_iptables -A OUTPUT -p icmp --icmp-type echo-reply -j DROP

            # Protection against invalid packets
            sudo $selected_iptables -A INPUT -m state --state INVALID -j DROP
            sudo $selected_iptables -A FORWARD -m state --state INVALID -j DROP
            sudo $selected_iptables -A OUTPUT -m state --state INVALID -j DROP

            # Block invalid TCP flag combinations
            sudo $selected_iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
            sudo $selected_iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
            sudo $selected_iptables -A INPUT -p tcp --tcp-flags ALL FIN -j DROP
            sudo $selected_iptables -A INPUT -p tcp --tcp-flags ALL FIN,URG,PSH -j DROP
            sudo $selected_iptables -A INPUT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
            sudo $selected_iptables -A INPUT -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG/NONE -j DROP
            sudo $selected_iptables -A INPUT -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG/FIN,SYN,RST,PSH,ACK,URG -j DROP
            sudo $selected_iptables -A INPUT -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG/FIN -j DROP
            sudo $selected_iptables -A INPUT -p tcp --tcp-flags ACK ACK -j DROP
            sudo $selected_iptables -A INPUT -p tcp --tcp-flags FIN,SYN,RST,ACK SYN --dport 80 -m connlimit --connlimit-above 10 --connlimit-mask 32 -j DROP
            sudo $selected_iptables -A INPUT -p tcp --tcp-flags FIN,SYN,RST,ACK SYN --dport 80 -m connlimit --connlimit-above 20 --connlimit-mask 32 -j REJECT --reject-with icmp-port-unreachable

            # Drop various attacks with specific TCP flag combinations
            sudo $selected_iptables -A INPUT -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
            sudo $selected_iptables -A INPUT -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN -j DROP
            sudo $selected_iptables -A INPUT -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,PSH,URG -j DROP
            sudo $selected_iptables -A INPUT -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,RST,PSH,ACK,URG -j DROP
            sudo $selected_iptables -A INPUT -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
            sudo $selected_iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
            sudo $selected_iptables -A INPUT -p tcp --destination-port 8080 -j DROP

            # Drop non-SYN TCP packets in NEW state
            sudo $selected_iptables -t mangle -A PREROUTING -p tcp ! --syn -m state --state NEW -j DROP
            sudo $selected_iptables -t mangle -A PREROUTING -m conntrack --ctstate INVALID -j DROP
            sudo $selected_iptables -t mangle -A PREROUTING -p tcp ! --syn -m conntrack --ctstate NEW -j DROP
            sudo $selected_iptables -t mangle -A PREROUTING -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -j DROP
            sudo $selected_iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
            sudo $selected_iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
            sudo $selected_iptables -t mangle -A PREROUTING -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
            sudo $selected_iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
            sudo $selected_iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,ACK FIN -j DROP
            sudo $selected_iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,URG URG -j DROP
            sudo $selected_iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,FIN FIN -j DROP
            sudo $selected_iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,PSH PSH -j DROP
            sudo $selected_iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL ALL -j DROP
            sudo $selected_iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL NONE -j DROP
            sudo $selected_iptables -t mangle -A PREROUTING -f -j DROP

            # Drop packets used for port scans
            sudo $selected_iptables -A INPUT -p tcp --tcp-flags ACK,FIN FIN -j DROP
            sudo $selected_iptables -A INPUT -p tcp --tcp-flags ACK,PSH PSH -j DROP
            sudo $selected_iptables -A INPUT -p tcp --tcp-flags ACK,URG URG -j DROP
            sudo $selected_iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
            sudo $selected_iptables -A INPUT -p tcp --tcp-flags ALL FIN -j DROP
            sudo $selected_iptables -A INPUT -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
            sudo $selected_iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
            sudo $selected_iptables -A INPUT -p tcp --tcp-flags ALL SYN,FIN -j DROP
            sudo $selected_iptables -A INPUT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
            sudo $selected_iptables -A INPUT -p tcp --tcp-flags ALL URG,PSH,FIN -j DROP
            sudo $selected_iptables -A INPUT -p tcp --tcp-flags ALL URG,PSH,SYN,FIN -j DROP
            sudo $selected_iptables -A INPUT -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
            sudo $selected_iptables -A INPUT -p tcp --tcp-flags SYN,ACK SYN,ACK -m state --state NEW -j DROP
            sudo $selected_iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
            sudo $selected_iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP

            # Limit SYN and UDP connections
            sudo $selected_iptables -A INPUT -p udp -j DROP
            sudo $selected_iptables -A INPUT -p tcp --tcp-flags SYN,RST,ACK,SYN -m limit --limit avg 10/sec burst 20 -j ACCEPT
            sudo $selected_iptables -A INPUT -p tcp --syn --dport 80 -m connlimit --connlimit-above 10 --connlimit-mask 32 -j DROP
            sudo $selected_iptables -A INPUT -p tcp --syn --dport 80 -m connlimit --connlimit-above 20 --connlimit-mask 32 -j REJECT
            sudo $selected_iptables -A INPUT -p tcp --tcp-flags RST RST -m limit --limit 2/second --limit-burst 2 -j ACCEPT
            sudo $selected_iptables -A INPUT -p tcp --syn -m limit --limit 10/second --limit-burst 20 -j ACCEPT
            sudo $selected_iptables -A INPUT -p tcp --syn -j DROP
            sudo $selected_iptables -A INPUT -p tcp -m state --state NEW -m limit --limit 50/second --limit-burst 50 -j ACCEPT

            # Limit UDP traffic to prevent flood attacks
            sudo $selected_iptables -A INPUT -p udp -m limit --limit 10/sec --limit-burst 20 -j ACCEPT
            sudo $selected_iptables -A INPUT -p udp -j DROP

            # Drop invalid packets
            sudo $selected_iptables -A INPUT -m conntrack --ctstate INVALID -j LOG --log-prefix "Invalid Packet: "
            sudo $selected_iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
            sudo $selected_iptables -A FORWARD -m state --state INVALID -j DROP
            sudo $selected_iptables -A OUTPUT -m state --state INVALID -j DROP

            # Block private and reserved IP ranges
            sudo $selected_iptables -A INPUT -s 10.0.0.0/8 -j DROP
            sudo $selected_iptables -A INPUT -s 169.254.0.0/16 -j DROP
            sudo $selected_iptables -A INPUT -s 172.16.0.0/12 -j DROP
            sudo $selected_iptables -A INPUT -s 240.0.0.0/5 -j DROP
            sudo $selected_iptables -A INPUT -s 0.0.0.0/8 -j DROP

            # Block multicast and broadcast addresses
            sudo $selected_iptables -A INPUT -d 224.0.0.0/4 -j DROP
            sudo $selected_iptables -A INPUT -d 240.0.0.0/5 -j DROP

            sudo $selected_iptables -A INPUT -s 169.254.0.0/16 -j DROP
            sudo $selected_iptables -A OUTPUT -s 169.254.0.0/16 -j DROP
            sudo $selected_iptables -A INPUT -s 127.0.0.0/8 -j DROP
            sudo $selected_iptables -A OUTPUT -s 127.0.0.0/8 -j DROP
            sudo $selected_iptables -A INPUT -s 224.0.0.0/4 -j DROP
            sudo $selected_iptables -A OUTPUT -s 224.0.0.0/4 -j DROP
            sudo $selected_iptables -A INPUT -d 224.0.0.0/4 -j DROP
            sudo $selected_iptables -A OUTPUT -d 224.0.0.0/4 -j DROP
            sudo $selected_iptables -A INPUT -s 240.0.0.0/5 -j DROP
            sudo $selected_iptables -A OUTPUT -s 240.0.0.0/5 -j DROP
            sudo $selected_iptables -A INPUT -d 240.0.0.0/5 -j DROP
            sudo $selected_iptables -A OUTPUT -d 240.0.0.0/5 -j DROP
            sudo $selected_iptables -A INPUT -s 0.0.0.0/8 -j DROP
            sudo $selected_iptables -A OUTPUT -s 0.0.0.0/8 -j DROP
            sudo $selected_iptables -A INPUT -d 0.0.0.0/8 -j DROP
            sudo $selected_iptables -A OUTPUT -d 0.0.0.0/8 -j DROP
            sudo $selected_iptables -A INPUT -d 239.255.255.0/24 -j DROP
            sudo $selected_iptables -A OUTPUT -d 239.255.255.0/24 -j DROP
            sudo $selected_iptables -A INPUT -d 255.255.255.255 -j DROP
            sudo $selected_iptables -A OUTPUT -d 255.255.255.255 -j DROP

            # Limit HTTP connections on port 80
            sudo $selected_iptables -A INPUT -p tcp --syn --dport 80 -m connlimit --connlimit-above 10 --connlimit-mask 32 -j DROP
            sudo $selected_iptables -A INPUT -p tcp --syn --dport 80 -m connlimit --connlimit-above 20 --connlimit-mask 32 -j REJECT

            # Drop specific DHCP and DNS traffic
            sudo $selected_iptables -A INPUT -p udp --sport 68 --dport 67 -j DROP
            sudo $selected_iptables -A INPUT -p udp --sport 53 -m state --state ESTABLISHED -j ACCEPT

            # Rate limit SSH connections
            sudo $selected_iptables -A INPUT -p tcp --dport ssh -m state --state NEW -m recent --set --name DEFAULT --mask 255.255.255.255 --rsource
            sudo $selected_iptables -A INPUT -p tcp --dport ssh -m state --state NEW -m recent --update --seconds 60 --hitcount 5 --rttl --name DEFAULT --mask 255.255.255.255 --rsource -j DROP

            # Additional protections (e.g., dropping INVALID packets)
            sudo $selected_iptables -A INPUT -m state --state INVALID -j DROP

            # Limit RST packets to avoid Smurf attacks
            sudo $selected_iptables -A INPUT -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/second --limit-burst 2 -j ACCEPT

            # Manage recent connections and repeated attacks
            sudo $selected_iptables -A INPUT -p tcp --dport 21534 -m state --state NEW -m recent --set
            sudo $selected_iptables -A INPUT -p tcp --dport 21534 -m state --state NEW -m recent --update --seconds 60 --hitcount 5 -j DROP

            # Drop ICMP packets with abnormal sizes (Ping of Death)
            sudo $selected_iptables -A INPUT -p icmp --icmp-type echo-request -m length --length 1000:65535 -j DROP

            # Drop fragmented packets (fragmentation attacks)
            sudo $selected_iptables -A INPUT -f -m limit --limit 100/sec --limit-burst 100 -j ACCEPT
            sudo $selected_iptables -A INPUT -f -j DROP

            # Drop TCP packets with unusual flag combinations (NULL, XMAS, FIN scans)
            sudo $selected_iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
            sudo $selected_iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
            sudo $selected_iptables -A INPUT -p tcp --tcp-flags ALL FIN -j DROP
            sudo $selected_iptables -A INPUT -p tcp --tcp-flags ACK ACK -j DROP

            # Drop INVALID packets
            sudo $selected_iptables -A INPUT -m state --state INVALID -j DROP
            sudo $selected_iptables -A FORWARD -m state --state INVALID -j DROP
            sudo $selected_iptables -A OUTPUT -m state --state INVALID -j DROP

            # Limit RST traffic
            sudo $selected_iptables -A INPUT -p tcp --tcp-flags RST RST -m limit --limit 2/sec --limit-burst 2 -j ACCEPT

            # Protection against DoS attacks via SSH
            sudo $selected_iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set --name DEFAULT --rsource
            sudo $selected_iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 5 --name DEFAULT --rsource -j DROP

            # Log and drop all other packets
            sudo $selected_iptables -A INPUT -j LOG --log-prefix "Dropped Input: "
            sudo $selected_iptables -A INPUT -j DROP

            # Limit SYN connections
            sudo $selected_iptables -A INPUT -p tcp --syn -m connlimit --connlimit-above 100 --connlimit-mask 24 -j DROP
            sudo $selected_iptables -A INPUT -p tcp --syn -m hashlimit --hashlimit 10/sec --hashlimit-burst 20 --hashlimit-mode srcip --hashlimit-name syn_flood -j ACCEPT

            # Limit connections on port 80
            sudo $selected_iptables -A INPUT -p tcp --dport 80 -m connlimit --connlimit-above 50 --connlimit-mask 32 -j DROP

            # Drop packets with specific strings on UDP port 53 (DNS)
            sudo $selected_iptables -A INPUT -p udp --dport 53 -m string --algo bm --string "any" -j DROP
            sudo $selected_iptables -A INPUT -p udp --dport 53 -m string --algo bm --string "ANY" -j DROP

            # Configure TCP MSS to avoid fragmentation
            sudo $selected_iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
            
            echo "Basic firewall configurations loaded."
            ;;
        *)
            echo "No changes made."
            ;;
    esac
}

# Main script logic
iptables_paths=$(find_iptables_versions | awk '{print $2}' | tail -n +2)

version_count=$(echo "$iptables_paths" | wc -l)

if [ "$version_count" -eq 0 ]; then
    echo "No iptables versions found."
    exit 1
elif [ "$version_count" -eq 1 ]; then
    selected_iptables=$(echo "$iptables_paths")
    echo "Only one version of iptables found, automatically selected: $selected_iptables"
else
    select_iptables_version
fi

# Execute commands using the selected version
echo "Using $selected_iptables to execute iptables commands."

# Ask to reset configurations
reset_iptables

# Ask for ports to accept and configure rules
accept_ports

# Automatically accept local traffic
accept_local_traffic

# Ask to load basic firewall configurations
load_basic_firewall_config