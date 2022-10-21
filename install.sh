#!/bin/bash

#
# Script to simplify installation of modified Shadowsocks
# on Debian/Ubuntu server
#

#
# Set filenames
# 
ssrepo='https://github.com/gfw-report/shadowsocks-rust'
ssversion='v0.0.1-beta'
ssvariant='shadowsocks-v1.15.0-alpha.9.x86_64-unknown-linux-gnu'
ssarchive='tar.xz'
ssdir='/etc/shadowsocks-rust'
ssjson='config.json'
systemdlib='/usr/lib/systemd/system'
systemdservice='shadowsocks-rust'

#
# Check that script is being run as root
#
is_root() {
    if [ 0 == $UID ]; then
        echo "The current user is the root user"
        echo "Entering the installation process"
    else
        echo "The current user is not the root user"
        echo "Please switch to the root user and execute the script again"
        exit 1
    fi
}

#
# Check that script supports the distribution on this system
#
check_system() {
    source '/etc/os-release'
    if [[ "$ID" == "debian" && $VERSION_ID -ge 10 ]]; then
        echo "The current system is Debian $VERSION_ID"
        INS="apt"
        $INS update
    elif [[ "$ID" == "ubuntu" && $(echo "$VERSION_ID" | cut -d '.' -f1) -ge 20 ]]; then
        echo "The current system is Ubuntu $VERSION_ID"
        INS="apt"
        $INS update
    else
        echo -e "$ID $VERSION_ID is not supported"
        exit 1
    fi
}

#
# Install prerequisite software
#
pre_install() {
    apt install -y wget curl tar openssl
}

#
# Install Shadowsocks
#
install_shadowsocks() {
    wget $ssrepo/releases/download/$ssversion/$ssvariant.$ssarchive
    tar xvf $ssvariant.$ssarchive
    cp ssserver /usr/bin/
}

#
# Create server configuration json file
#
create_server_config() {
mkdir -p $ssdir
cat <<EOF > $ssdir/$ssjson
{
    "server": "0.0.0.0",
    "server_port": $server_port,
    "password": "$password",
    "method": "$method"
}
EOF
}

#
# Set up systemd service file
#
create_systemd_service() {
cat <<EOF > $systemdlib/$systemdservice.service
[Unit]
Description=Shadowsocks-rust server
After=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/ssserver -c $ssdir/$ssjson

[Install]
WantedBy=multi-user.target
EOF
}

#
# Start Shadowsocks-rust running as a service
#
start_systemd_service() {
     systemctl enable $systemdservice.service
     systemctl start $systemdservice.service
}

#
# Display closing messages to user
#
closing_messages() {
    echo -e "*************************************************"
    echo -e "   $systemdservice.service has been started"
    echo -e "*************************************************"
    echo -e "1. Open port $server_port in your server firewall"
    echo -e "2. Install software on your client"
    echo -e "3. Configure your client like this:\n" 
    echo -e "{"
    echo -e "    \"server\": \"$server_ip\","
    echo -e "    \"server_port\": $server_port,"
    echo -e "    \"password\": \"$password\","
    echo -e "    \"method\": \"$method\","
    echo -e "    \"local_address\": \"$local_ip\","
    echo -e "    \"local_port\": $local_port,"
    echo -e "}"
}

#
# Mainline
#
is_root
check_system
pre_install
install_shadowsocks

server_ip=$(curl https://ipv4.icanhazip.com)
server_port=$(($RANDOM+10000))
password=$(openssl rand -base64 12)
method='aes-256-gcm'
create_server_config

create_systemd_service
start_systemd_service

local_ip='127.0.0.1'
local_port='10808'
closing_messages
