#!/usr/bin/bash
####################################################################################################
####################################################################################################

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

####################################################################################################
####################################################################################################

# Script tries to harden a default setup of CentOS 7.
# All configuration parameters lie in the beginning of the file, 
# in terms of global variables (Capitalized). Feel free to change
# the configuration according to your needs. Only change if you know
# what you're doing...You have been warned!

####################################################################################################

# CONFIGURATION STARTS HERE

####################################################################################################

APACHE2DFILE='/etc/httpd/conf/httpd.conf'
AUDITDCONF='/etc/audit/auditd.conf'
AUDITRULES='/etc/audit/rules.d/audit.rules'
COREDUMPCONF='/etc/systemd/coredump.conf'
DEFAULTGRUB='/etc/default/grub'
DISABLEFS='/etc/modprobe.d/disablemnt.conf'
DISABLEMOD='/etc/modprobe.d/disablemod.conf'
DISABLENET='/etc/modprobe.d/disablenet.conf'
DISABLEWIRELESS='/etc/modprobe.d/disablewireless.conf'
EXPECT='/usr/bin/expect'
FW_LOCAL='127.0.0.1'
GRUB_PASSPHRASE='password'
GRUB_SUPERUSER='myuser'
GUI='Y'
HOSTSALLOW='/etc/hosts.allow'
HOSTSDENY='/etc/hosts.deny'
JOURNALDCONF='/etc/systemd/journald.conf'
LIMITSCONF='/etc/security/limits.conf'
LOGINDCONF='/etc/systemd/logind.conf'
LOGINDEFS='/etc/login.defs'
LOGROTATE='/etc/logrotate.conf'
MKPASSWD='/usr/bin/grub2-mkpasswd-pbkdf2'
MOD='appletalk bnep bluetooth btusb net-pf-31 soundcore thunderbolt usb-midi'
NPACKAGES='epel-release expect redhat-lsb-core samba ufw'
PACKAGES='httpd mod_qos tcp_wrappers'
PASSWORDAUTH='/etc/pam.d/password-auth'
PASSWORDQUALITY='/etc/security/pwquality.conf'
RKHUNTERCONF='/etc/rkhunter.conf'
SECURITYACCESS='/etc/security/access.conf'
SERVER='Y'
SSHDFILE='/etc/ssh/sshd_config'
SYSCTL='/etc/sysctl.conf'
SYSTEMAUTH='/etc/pam.d/system-auth'
SYSTEMCONF='/etc/systemd/system.conf'
SYSTEMNET='/etc/sysconfig/network'
UFWBEFORERULES='/etc/ufw/before.rules'
UFWDEFAULT='/etc/default/ufw'
UMASKFILES='/etc/bashrc /etc/csh.cshrc /etc/init.d/functions /etc/profile'
USERADD='/etc/default/useradd'
USERCONF='/etc/systemd/user.conf'
UNW_PROT='dccp sctp rds tipc'
UNW_SERVICES='avahi-daemon kdump mdmonitor rhsmcertd smartd'
UNW_FS='cramfs cifs fat freevxfs gfs2 jffs2 hfs hfsplus nfs nfsv3 nfsv4 squashfs udf vfat'
VERBOSE='Y'
VM=''

####################################################################################################

# CONFIGURATION ENDS HERE
# Do not change anything below this line!

####################################################################################################

echo "


                                             LLLLLLLLLLL              iiii
                                             L:::::::::L             i::::i
                                             L:::::::::L              iiii
                                             LL:::::::LL
                                               L:::::L              iiiiiinnnn  nnnnnnnn   uuuuuu    uuuuuu xxxxxxx      xxxxxxx
                                               L:::::L              i:::::n:::nn::::::::nn u::::u    u::::u  x:::::x    x:::::x
                                               L:::::L               i::::n::::::::::::::nnu::::u    u::::u   x:::::x  x:::::x
                                               L:::::L               i::::nn:::::::::::::::u::::u    u::::u    x:::::xx:::::x
                                               L:::::L               i::::i n:::::nnnn:::::u::::u    u::::u     x::::::::::x
                                               L:::::L               i::::i n::::n    n::::u::::u    u::::u      x::::::::x
                                               L:::::L               i::::i n::::n    n::::u::::u    u::::u      x::::::::x
                                               L:::::L         LLLLLLi::::i n::::n    n::::u:::::uuuu:::::u     x::::::::::x
                                             LL:::::::LLLLLLLLL:::::i::::::in::::n    n::::u:::::::::::::::uu  x:::::xx:::::x
                                             L::::::::::::::::::::::i::::::in::::n    n::::nu:::::::::::::::u x:::::x  x:::::x
                                             L::::::::::::::::::::::i::::::in::::n    n::::n uu::::::::uu:::ux:::::x    x:::::x
                                             LLLLLLLLLLLLLLLLLLLLLLLiiiiiiiinnnnnn  dddddddd   uuuuuuuu  uuuxxxxxxx      xxxxxxx
               HHHHHHHHH     HHHHHHHHH                                              d::::::d                                     iiii
               H:::::::H     H:::::::H                                              d::::::d                                    i::::i                                    
               H:::::::H     H:::::::H                                              d::::::d                                     iiii
               HH::::::H     H::::::HH                                              d:::::d
                 H:::::H     H:::::H   aaaaaaaaaaaaa rrrrr   rrrrrrrrr      ddddddddd:::::d    eeeeeeeeeeee   nnnn  nnnnnnnn   iiiiiinnnn  nnnnnnnn      ggggggggg   ggggg
                 H:::::H     H:::::H   a::::::::::::ar::::rrr:::::::::r   dd::::::::::::::d  ee::::::::::::ee n:::nn::::::::nn i:::::n:::nn::::::::nn   g:::::::::ggg::::g
                 H::::::HHHHH::::::H   aaaaaaaaa:::::r:::::::::::::::::r d::::::::::::::::d e::::::eeeee:::::en::::::::::::::nn i::::n::::::::::::::nn g:::::::::::::::::g
                 H:::::::::::::::::H            a::::rr::::::rrrrr::::::d:::::::ddddd:::::de::::::e     e:::::nn:::::::::::::::ni::::nn:::::::::::::::g::::::ggggg::::::gg
                 H:::::::::::::::::H     aaaaaaa:::::ar:::::r     r:::::d::::::d    d:::::de:::::::eeeee::::::e n:::::nnnn:::::ni::::i n:::::nnnn:::::g:::::g     g:::::g
                 H::::::HHHHH::::::H   aa::::::::::::ar:::::r     rrrrrrd:::::d     d:::::de:::::::::::::::::e  n::::n    n::::ni::::i n::::n    n::::g:::::g     g:::::g
                 H:::::H     H:::::H  a::::aaaa::::::ar:::::r           d:::::d     d:::::de::::::eeeeeeeeeee   n::::n    n::::ni::::i n::::n    n::::g:::::g     g:::::g
                 H:::::H     H:::::H a::::a    a:::::ar:::::r           d:::::d     d:::::de:::::::e            n::::n    n::::ni::::i n::::n    n::::g::::::g    g:::::g
               HH::::::H     H::::::Ha::::a    a:::::ar:::::r           d::::::ddddd::::::de::::::::e           n::::n    n::::i::::::in::::n    n::::g:::::::ggggg:::::g
               H:::::::H     H:::::::a:::::aaaa::::::ar:::::r            d:::::::::::::::::de::::::::eeeeeeee   n::::n    n::::i::::::in::::n    n::::ng::::::::::::::::g
               H:::::::H     H:::::::Ha::::::::::aa:::r:::::r             d:::::::::ddd::::d ee:::::::::::::e   n::::n    n::::i::::::in::::n    n::::n gg::::::::::::::g
               HHHHHHHHH     HHHHHHHHH aaaaaaaaaa  aaarrrrrrr              ddddddddd   ddddd   eeeeeeeeeeeeee   nnnnnn    nnnnniiiiiiiinnnnnn    nnnnnn   gggggggg::::::g
                                                                                                                                                                  g:::::g
                                                                                                                                                      gggggg      g:::::g
                                                                                                                                                      g:::::gg   gg:::::g
                                                                                                                                                       g::::::ggg:::::::g
                                                                                                                                                        gg:::::::::::::g
                                                                                                                                                          ggg::::::ggg
                                                                                                                                                             gggggg




"

echo "---------- CentOS 7/8 Apache Web Server Hardening ----------"
####################################################################################################
# Check that we have bare minimum...(OK)

echo "---------- Doing some pre-execution checks ----------"

echo "Installing Needed packages so the script can be executed..."

for pack in $NPACKAGES; do
echo "Installing $pack package..."
    if [[ $VERBOSE == "Y" ]]; then
        yum install -y "$pack"
    else
        yum install -q -y "$pack"
    fi
done

if [ $EUID -ne 0 ]; then
    echo "This script must be run with root privileges..."
    echo
    exit 1
else
    echo "You run the script with root priviliges. Script will continue..."
    echo
fi

if ! lsb_release -i | grep 'CentOS'; then
    echo "Unsupported Operating System. Only CentOS Supported..."
    echo
    exit 1
else
    echo "You run the script at CentOS operating system. Script will continue..."
    echo
fi

if ! [ -x "$(which systemctl)" ]; then
	echo "systemctl required. Unsupported setup..."
    echo
	exit 1
else
    echo "systemctl is OK. Script will continue..."
    echo    
fi

if ! test -f "$UFWDEFAULT"; then
    echo "$UFWDEFAULT firewall config file not found."

    if ! dpkg -l | grep ufw 2> /dev/null 1>&2; then
    	echo 'Please install ufw package to continue.'
    fi
    exit 1
fi

# Check that we have bare minimum end...(OK)
####################################################################################################
# Set paths...(OK)

echo "Setting environment paths..."

sed -i 's/PATH=.*/PATH=\"\/usr\/local\/bin:\/usr\/bin:\/bin"/' /etc/environment

cat > /etc/profile.d/initpath.sh <<EOF
#!/bin/bash

if [[ $EUID -eq 0 ]];
  then
    export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
  else
    export PATH=/usr/local/bin:/usr/bin:/bin
fi
EOF

chown root:root /etc/profile.d/initpath.sh
chmod 0644 /etc/profile.d/initpath.sh

echo "Setting environment paths completed..."

# Set paths end...(OK)
####################################################################################################
# Set apt environment...(OK)

if [[ $VERBOSE == "Y" ]]; then
    APT_ENV='-y'
else
    APT_ENV='-q -y'
fi

APT="yum $APT_ENV"

# Set apt environment end...(OK)
####################################################################################################
# Check if we are running VM...(OK)

if dmidecode -q --type system | grep -i vmware; then
    VM="open-vm-tools"
    echo "The CentOS is running on VMWare VM environment..."
fi

if dmidecode -q --type system | grep -i virtualbox; then
    VM="virtualbox-guest-dkms virtualbox-guest-utils"
    echo "The CentOS is running on VirtualBox VM environment..."
fi

if [ $VM != '' ]; then
    for pack in $VM; do
        $APT install "$pack"
        echo "Installing $pack package..."
    done
fi

# Check if we are running VM end...(OK)
####################################################################################################

echo "---------- End of pre-execution checks & tasks ----------"
echo "---------- Let's start by hardening the system settings ----------"

####################################################################################################
# Chapter 1...(OK)

echo "---------- Chapter 1 - Post installation ----------"

####################################################################################################
# Make sure system is up to date... (OK)

echo "---------- Section 1.1 - Make sure system is up to date ----------"

echo "Updating the package index files..."
$APT update
echo "Upgrading installed packages..."
$APT upgrade

# Make sure system is up to date end... (OK)
####################################################################################################
# Secure Bootloader... (OK)

echo "---------- Section 1.2 - Secure Bootloader ----------"

echo "Securing bootloader with Username: $GRUB_SUPERUSER and Password: $GRUB_PASSPHRASE"

expect_script(){
    cat <<EOF
    log_user 0
    spawn  ${MKPASSWD}
    sleep 0.33
    expect  "Enter password: " {
        send "$GRUB_PASSPHRASE"
        send "\n"
    }
    sleep 0.33
    expect "Reenter password: " {
        send "$GRUB_PASSPHRASE"
        send "\n"
    }
    sleep 0.33
    expect eof {
        puts "\$expect_out(buffer)"
    }
    exit 0
EOF
}

if [ -n "$GRUB_PASSPHRASE" ]; then
    sed -i 's/^GRUB_CMDLINE_LINUX=.*/GRUB_CMDLINE_LINUX="--users $GRUB_SUPERUSER"/' "$DEFAULTGRUB"
    echo "set superusers=$GRUB_SUPERUSER" >> /etc/grub.d/40_custom
    GRUB_PASS=$(expect_script "$1" | $EXPECT | sed -e "/^\r$/d" -e "/^$/d" -e "s/.* \(.*\)/\1/")
    echo "password_pbkdf2 $GRUB_SUPERUSER $GRUB_PASS" >> /etc/grub.d/40_custom
    echo 'export superusers' >> /etc/grub.d/40_custom
    cp /boot/grub2/grub.cfg /boot/grub2/grub.cfg.backup
    grub2-mkconfig -o /boot/grub2/grub.cfg
fi

chown root:root /boot/grub2/grub.cfg
chmod og-rwx /boot/grub2/grub.cfg

# Secure Bootloader end... (OK)
####################################################################################################

echo "---------- Chapter 1 - Completed ----------"

# Chapter 1 end...(OK)
####################################################################################################
# Chapter 2...(OK)

echo "---------- Chapter 2 - File Permissions and Masks ----------"

####################################################################################################
# Restrict Dynamic Mounting and Unmounting of Filesystems... (OK)

echo "---------- Section 2.1 - Restrict Dynamic Mounting and Unmounting of Filesystems ----------"

echo "Disabling file systems..."
for disable in $UNW_FS; do
    if ! grep -q "$disable" "$DISABLEFS" 2> /dev/null; then
        echo "install $disable /bin/true" >> "$DISABLEFS"
        echo "Disabling $disable file system..."
    fi
done

echo "Configuration file for disabled file systems can be found at the directory: $DISABLEFS"

# Restrict Dynamic Mounting and Unmounting of Filesystems end... (OK)
####################################################################################################
# Prevent Users Mounting USB Storage... (OK)

echo "---------- Section 2.2 - Prevent Users Mounting USB Storage ----------"

echo "blacklist usb-storage" >> "$DISABLEMOD"
echo "blacklist firewire-core" >> "$DISABLEMOD"
echo "install usb-storage /bin/true" >> "$DISABLEMOD"
echo "Configuration file for prevention for mounting USB Storage can be found at the directory: $DISABLEMOD"

# Prevent Users Mounting USB Storage end... (OK)
####################################################################################################
# Restrict Programs from Dangerous Execution Patterns... (OK)

echo "---------- Section 2.3 - Restrict Programs from Dangerous Execution Patterns ----------"

echo "Configuring $SYSCTL file..."
echo "This will cover section 2.4 and section 3.3 at once..."

cat > $SYSCTL <<EOF
# sysctl settings are defined through files in
# /usr/lib/sysctl.d/, /run/sysctl.d/, and /etc/sysctl.d/.
#
# Vendors settings live in /usr/lib/sysctl.d/.
# To override a whole file, create a new file with the same in
# /etc/sysctl.d/ and put new settings there. To override
# only specific settings, add a file with a lexically later
# name in /etc/sysctl.d/ and put new settings there.
#
# For more information, see sysctl.conf(5) and sysctl.d(5).

fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 0
kernel.core_uses_pid = 1
kernel.kptr_restrict = 2
kernel.panic = 60
kernel.panic_on_oops = 60
kernel.perf_event_paranoid = 2
kernel.randomize_va_space = 2
kernel.sysrq = 0
kernel.yama.ptrace_scope = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.default.rp_filter= 1
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.ip_forward = 0
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 5
net.ipv4.tcp_timestamps = 0
net.ipv4.conf.all.forwarding = 0
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
net.ipv6.conf.all.use_tempaddr = 2
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_ra = 0
net.ipv6.conf.default.accept_ra_defrtr = 0
net.ipv6.conf.default.accept_ra_pinfo = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.default.autoconf = 0
net.ipv6.conf.default.dad_transmits = 0
net.ipv6.conf.default.max_addresses = 1
net.ipv6.conf.default.router_solicitations = 0
net.ipv6.conf.default.use_tempaddr = 2
net.ipv6.conf.eth0.accept_ra_rtr_pref = 0
net.ipv6.conf.all.forwarding = 0
net.netfilter.nf_conntrack_max = 2000000
net.netfilter.nf_conntrack_tcp_loose = 0
EOF

sed -i '/net.ipv6.conf.eth0.accept_ra_rtr_pref/d' "$SYSCTL"

for i in $(arp -n -a | awk '{print $NF}' | sort | uniq); do
    echo "net.ipv6.conf.$i.accept_ra_rtr_pref = 0" >> "$SYSCTL"
done

echo 1048576 > /sys/module/nf_conntrack/parameters/hashsize

chmod 0600 "$SYSCTL"
systemctl restart systemd-sysctl

if [[ $VERBOSE == "Y" ]]; then
    systemctl status systemd-sysctl --no-pager
    echo
fi

# Restrict Programs from Dangerous Execution Patterns end... (OK)
####################################################################################################
# Set UMASK 027... (OK)
# Old was 077

echo "---------- Section 2.4 - Set UMASK 027 ----------"

echo "UMASK 027 important files..."
for mask in $UMASKFILES; do
    echo "UMASK file $mask..."
    sed -i -e 's/umask 022/umask 027/g' -e 's/umask 002/umask 027/g' "$mask"
done

# Set UMASK 027 end... (OK)
####################################################################################################
# Disable Core Dumps... (OK)

echo "---------- Section 2.5 - Disable Core Dumps ----------"

echo "Disable Core Dumps at $LIMITSCONF file..."
cat > $LIMITSCONF <<EOF
* hard core 0

# 4096 is a good starting point
*      soft   nofile    4096
*      hard   nofile    65536
*      soft   nproc     4096
*      hard   nproc     4096
*      soft   locks     4096
*      hard   locks     4096
*      soft   stack     10240
*      hard   stack     32768
*      soft   memlock   64
*      hard   memlock   64
*      hard   maxlogins 10

# Soft limit 32GB, hard 64GB
*      soft   fsize     33554432
*      hard   fsize     67108864

# Limits for root
root   soft   nofile    4096
root   hard   nofile    65536
root   soft   nproc     4096
root   hard   nproc     4096
root   soft   stack     10240
root   hard   stack     32768
root   soft   fsize     33554432
# End of file
EOF

echo "Disable Core Dumps at $SYSTEMCONF and $USERCONF file..."

sed -i 's/^#DumpCore=.*/DumpCore=no/' "$SYSTEMCONF"
sed -i 's/^#CrashShell=.*/CrashShell=no/' "$SYSTEMCONF"
sed -i 's/^#DefaultLimitCORE=.*/DefaultLimitCORE=0/' "$SYSTEMCONF"
sed -i 's/^#DefaultLimitNOFILE=.*/DefaultLimitNOFILE=4096/' "$SYSTEMCONF"
sed -i 's/^#DefaultLimitNPROC=.*/DefaultLimitNPROC=4096/' "$SYSTEMCONF"

sed -i 's/^#DefaultLimitCORE=.*/DefaultLimitCORE=0/' "$USERCONF"
sed -i 's/^#DefaultLimitNOFILE=.*/DefaultLimitNOFILE=4096/' "$USERCONF"
sed -i 's/^#DefaultLimitNPROC=.*/DefaultLimitNPROC=4096/' "$USERCONF"

systemctl daemon-reload

if test -f "$COREDUMPCONF"; then
    echo "Fixing Systemd/coredump.conf"
    sed -i 's/^#Storage=.*/Storage=none/' "$COREDUMPCONF"

    systemctl restart systemd-journald

    if [[ $VERBOSE == "Y" ]]; then
        systemctl status systemd-journald --no-pager
        echo
    fi
fi

# Disable Core Dumps end... (OK)
####################################################################################################
# Set Security Limits to Prevent DoS... (OK)

echo "---------- Section 2.6 - Set Security Limits to Prevent DoS ----------"

echo "Set Security Limits to Prevent DoS at $LIMITSCONF file..."
echo "We covered section 2.6 at previous section 2.5! $LIMITSCONF is already configured..."

# Set Security Limits to Prevent DoS end... (OK)
####################################################################################################
# Disable Unwanted Services... (OK)

echo "---------- Section 2.7 - Disable Unwanted Services ----------"

echo "Disabling unwanted services..."

for disable in $UNW_SERVICES; do
    echo "Disabling $disable service..."
    systemctl disable $disable
done

# Disable Unwanted Services end... (OK)
####################################################################################################
# Disabling RPC and CUPS...(OK)

echo "Disabling RPC..."
systemctl stop rpcbind.service
systemctl disable rpcbind.service
systemctl mask rpcbind.service
systemctl stop rpcbind.socket
systemctl disable rpcbind.socket
systemctl mask rpcbind.socket

echo "Disabling CUPS..."
systemctl stop cups.service
systemctl disable cups.service
systemctl mask cups.service
systemctl stop cups.socket
systemctl disable cups.socket
systemctl mask cups.socket

# Disabling RPC and CUPS end...(OK)
####################################################################################################
# Lock Down Cron... (OK)

echo "---------- Section 2.8 - Lock Down Cron ----------"

echo "Locking down Cron..."
touch /etc/cron.allow
chmod 600 /etc/cron.allow
awk -F: '{print $1}' /etc/passwd | grep -v root > /etc/cron.deny
echo "Locking down AT..."
touch /etc/at.allow
chmod 600 /etc/at.allow
awk -F: '{print $1}' /etc/passwd | grep -v root > /etc/at.deny

for pathings in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d /etc/crontab; do
    chmod 700 "$pathings"
done

rm /etc/cron.deny 
rm /etc/at.deny 

# Lock Down Cron end... (OK)
####################################################################################################

echo "---------- Chapter 2 - Completed ----------"

# Chapter 2 end...(OK)
####################################################################################################
# Chapter 3...(OK)

echo "---------- Chapter 3 - Firewall and Network Configuration ----------"

####################################################################################################
# Firewall... (OK)

echo "---------- Section 3.1 - Firewall ----------"

echo "Shutdown firewalld.service..."
systemctl stop firewalld.service
systemctl disable firewalld.service
systemctl mask firewalld.service
systemctl daemon-reload
echo "Configuring Uncomplicated Firewall..."

sed -i 's/IPT_SYSCTL=.*/IPT_SYSCTL=\/etc\/sysctl\.conf/' "$UFWDEFAULT"
sed -i 's/IPV6=.*/IPV6=no/' "$UFWDEFAULT"

systemctl enable ufw
systemctl start ufw

cat > $UFWBEFORERULES <<EOF
#
# rules.before
#
# Rules that should be run before the ufw command line added rules. Custom
# rules should be added to one of these chains:
#   ufw-before-input
#   ufw-before-output
#   ufw-before-forward
#

# Don't delete these required lines, otherwise there will be errors
*filter
:ufw-before-input - [0:0]
:ufw-before-output - [0:0]
:ufw-before-forward - [0:0]
:ufw-not-local - [0:0]
:ufw-http - [0:0]
:ufw-http-logdrop - [0:0]
# End required lines


# allow all on loopback
-A ufw-before-input -i lo -j ACCEPT
-A ufw-before-output -o lo -j ACCEPT

# quickly process packets for which we already have a connection
-A ufw-before-input -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A ufw-before-output -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A ufw-before-forward -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# drop INVALID packets (logs these in loglevel medium and higher)
-A ufw-before-input -m conntrack --ctstate INVALID -j ufw-logging-deny
-A ufw-before-input -m conntrack --ctstate INVALID -j DROP

# ok icmp codes for INPUT
-A ufw-before-input -p icmp --icmp-type destination-unreachable -j ACCEPT
-A ufw-before-input -p icmp --icmp-type source-quench -j ACCEPT
-A ufw-before-input -p icmp --icmp-type time-exceeded -j ACCEPT
-A ufw-before-input -p icmp --icmp-type parameter-problem -j ACCEPT
-A ufw-before-input -p icmp --icmp-type echo-request -j ACCEPT

# ok icmp code for FORWARD
-A ufw-before-forward -p icmp --icmp-type destination-unreachable -j ACCEPT
-A ufw-before-forward -p icmp --icmp-type source-quench -j ACCEPT
-A ufw-before-forward -p icmp --icmp-type time-exceeded -j ACCEPT
-A ufw-before-forward -p icmp --icmp-type parameter-problem -j ACCEPT
-A ufw-before-forward -p icmp --icmp-type echo-request -j ACCEPT

# allow dhcp client to work
-A ufw-before-input -p udp --sport 67 --dport 68 -j ACCEPT

#
# ufw-not-local
#
-A ufw-before-input -j ufw-not-local

# if LOCAL, RETURN
-A ufw-not-local -m addrtype --dst-type LOCAL -j RETURN

# if MULTICAST, RETURN
-A ufw-not-local -m addrtype --dst-type MULTICAST -j RETURN

# if BROADCAST, RETURN
-A ufw-not-local -m addrtype --dst-type BROADCAST -j RETURN

# all other non-local packets are dropped
-A ufw-not-local -m limit --limit 3/min --limit-burst 10 -j ufw-logging-deny
-A ufw-not-local -j DROP

### Start HTTP ###

# Enter rule
-A ufw-before-input -p tcp --dport 80   -j ufw-http
-A ufw-before-input -p tcp --dport 443  -j ufw-http

# Limit connections per Class C
-A ufw-http -p tcp --syn -m connlimit --connlimit-above 20 --connlimit-mask 40 -j ufw-http-logdrop

# Limit connections per IP
-A ufw-http -m state --state NEW -m recent --name conn_per_ip --set
-A ufw-http -m state --state NEW -m recent --name conn_per_ip --update --seconds 10 --hitcount 20 -j ufw-http-logdrop

# Limit packets per IP
-A ufw-http -m recent --name pack_per_ip --set
-A ufw-http -m recent --name pack_per_ip --update --seconds 1  --hitcount 20  -j ufw-http-logdrop

# Finally accept
-A ufw-http -j ACCEPT

# Log-A ufw-http-logdrop -m limit --limit 3/min --limit-burst 10 -j LOG --log-prefix "[UFW HTTP DROP] "
-A ufw-http-logdrop -j DROP

### End HTTP ###


# don't delete the 'COMMIT' line or these rules won't be processed
COMMIT
EOF

if [[ $SERVER == "Y" ]]; then
    ufw allow http
fi

ufw logging on
ufw reload

if [[ $VERBOSE == "Y" ]]; then
    systemctl status ufw.service --no-pager
    ufw status verbose
    echo
fi

# Firewall end... (OK)
####################################################################################################
# TCP Wrappers... (OK)

echo "---------- Section 3.2 - TCP Wrappers ----------"

echo "Configuring TCP Wrappers..."

if [[ $SERVER == "Y" ]]; then
    echo "sshd : ALL : ALLOW" > "$HOSTSALLOW"
fi
echo "ALL: LOCAL, 127.0.0.1" >> "$HOSTSALLOW"
echo "ALL: ALL" >> "$HOSTSDENY"
chmod 644 "$HOSTSALLOW"
chmod 644 "$HOSTSDENY"

# TCP Wrappers end... (OK)
####################################################################################################
# Kernel Parameters Which Affect Networking... (OK)

echo "---------- Section 3.3 - Kernel Parameters Which Affect Networking ----------"

echo "We covered section 3.3 at previous section 2.4! $SYSCTL is already configured..."

# Kernel Parameters Which Affect Networking end... (OK)
####################################################################################################
# Kernel Modules Which Affect Networking... (OK)

echo "---------- Section 3.4 - Kernel Modules Which Affect Networking ----------"

echo "Disabling unwanted kernel modules..."

for disable in $MOD; do
    if ! grep -q "$disable" "$DISABLEMOD" 2> /dev/null; then
        echo "install $disable /bin/true" >> "$DISABLEMOD"
        echo "Disabling $disable mod..."
    fi
done

echo "Configuration file for unwanted kernel modules can be found at the directory: $DISABLEMOD"

echo "Disabling unwanted protocols..."
for disable in $UNW_PROT; do
    if ! grep -q "$disable" "$DISABLENET" 2> /dev/null; then
        echo "install $disable /bin/true" >> "$DISABLENET"
        echo "Disabling $disable protocol..."
    fi
done

echo "options ipv6 disable=1" >> "$DISABLENET"

echo "Configuration file for unwanted protocols can be found at the directory: $DISABLENET"

# Kernel Modules Which Affect Networking end... (OK)
####################################################################################################
# Disable Radios... (OK)

echo "---------- Section 3.5 - Disable Radios ----------"

echo "Disabling radios..."
nmcli radio all off

echo "Disabling Wireless Drivers..."
for i in $(find /lib/modules/$(uname -r)/kernel/drivers/net/wireless -name "*.ko" -type f);do
    echo blacklist "$i" >>"$DISABLEWIRELESS";
done

echo "Configuration file for unwanted protocols can be found at the directory: $DISABLEWIRELESS"

# Disable Radios end... (OK)
####################################################################################################
# Disable Zeroconf Networking... (OK)

echo "---------- Section 3.6 - Disable Zeroconf Networking ----------"

echo "Disable Zeroconf Networking at file $SYSTEMNET"
echo "NOZEROCONF=yes" >> "$SYSTEMNET"

# Disable Zeroconf Networking end... (OK)
####################################################################################################
# Disable Interface Usage of IPv6... (OK)

echo "---------- Section 3.7 - Disable Interface Usage of IPv6 ----------"

echo "Disable interface usage of IPv6 at file $SYSTEMNET"
echo "NETWORKING_IPV6=no" >> "$SYSTEMNET"
echo "IPV6INIT=no" >> "$SYSTEMNET"

# Disable Interface Usage of IPv6 end... (OK)
####################################################################################################

echo "---------- Chapter 3 - Completed ----------"

# Chapter 3 end...(OK)
####################################################################################################
# Chapter 4...(OK)

echo "---------- Chapter 4 - System Settings – SELinux ----------"

####################################################################################################
# Check sestatus and grub state enforcing... (OK)

echo "---------- Section 4.1 - Check sestatus and grub state enforcing ----------"

echo "Check sestatus below...By default should be enforcing!"

sestatus

# Check sestatus and grub state enforcing end... (OK)
####################################################################################################
# Delete setroubleshoot... (OK)

echo "---------- Section 4.2 - Delete setroubleshoot ----------"

echo "Removing setroubleshoot..."

$APT erase setroubleshoot
$APT erase abrt

# Delete setroubleshoot... (OK)
####################################################################################################

echo "---------- Chapter 4 - Completed ----------"

# Chapter 4 end...(OK)
####################################################################################################
# Chapter 5...(OK)

echo "---------- Chapter 5 - Account and Access Control ----------"

####################################################################################################
# Delete Unused Accounts and Groups... (OK)

echo "---------- Section 5.1 - Delete Unused Accounts and Groups ----------"

echo "Deleting unused accounts..."
for users in ftp games gnats irc list news uucp; do
    userdel -r "$users" 2> /dev/null
    echo "Deleting $users account..."
done

echo "Deleting unused groups..."
echo "Deleting games group..."
groupdel games

# Delete Unused Accounts and Groups end... (OK)
####################################################################################################
# Disable root... (OK)

echo "---------- Section 5.2 - Disable root ----------"

echo "Disabling root logins..."

sed -i 's/^#+ : root : 127.0.0.1/+ : root : 127.0.0.1/' "$SECURITYACCESS"
echo '' > /etc/securetty

echo "Locking out root account..."

usermod -L root

if [[ $VERBOSE == "Y" ]]; then
    passwd -S root
    echo
fi

# Disable root end... (OK)
####################################################################################################
# Enable Secure (high quality) Password Policy... (OK)

echo "---------- Section 5.3 - Enable Secure (high quality) Password Policy ----------"

echo "Making a strong password policy using authconfig..."

echo "Doing changes to $PASSWORDQUALITY file..."
sed -i 's/# difok.*/difok = 8/g' "$PASSWORDQUALITY"
sed -i 's/# minlen.*/minlen = 14/g' "$PASSWORDQUALITY"
sed -i 's/# dcredit.*/dcredit = -1/g' "$PASSWORDQUALITY"
sed -i 's/# ucredit.*/ucredit = -1/g' "$PASSWORDQUALITY"
sed -i 's/# lcredit.*/lcredit = -1/g' "$PASSWORDQUALITY"
sed -i 's/# ocredit.*/ocredit = -1/g' "$PASSWORDQUALITY"
sed -i 's/# minclass.*/minclass = 1/g' "$PASSWORDQUALITY"
sed -i 's/# maxrepeat.*/maxrepeat = 2/g' "$PASSWORDQUALITY"
sed -i 's/# maxclassrepeat.*/maxclassrepeat = 2/g' "$PASSWORDQUALITY"
sed -i 's/# gecoscheck.*/gecoscheck = 1/g' "$PASSWORDQUALITY"

# Enable Secure (high quality) Password Policy end... (OK)
####################################################################################################
# Set Account Expiration Following Inactivity... (OK)

echo "---------- Section 5.4 - Set Account Expiration Following Inactivity ----------"

echo "Changing INACTIVE parameter at $USERADD file..."
sed -i 's/^INACTIVE.*/INACTIVE=0/' "$USERADD"

# Set Account Expiration Following Inactivity end... (OK)
####################################################################################################
# Secure Password Policy... (OK)

echo "---------- Section 5.5 - Secure Password Policy ----------"

echo "Making Changes to $LOGINDEFS for secure password policy..."
sed -i -e 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 60/' \
  -e 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 7/' \
  -e 's/^PASS_MIN_LEN.*/PASS_MIN_LEN 14/' \
  -e 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 14/' "$LOGINDEFS"

# Secure Password Policy end... (OK)
####################################################################################################
# Log Failed Login Attempts... (OK)

echo "---------- Section 5.6 - Log Failed Login Attempts ----------"

echo "Making Changes to $LOGINDEFS to Log Failed Login Attempts..."
echo "FAILLOG_ENAB yes" >> "$LOGINDEFS"
echo "FAIL_DELAY 4" >> "$LOGINDEFS"

# Log Failed Login Attempts end... (OK)
####################################################################################################
# Ensure Home Directories are Created for New Users... (OK)

echo "---------- Section 5.7 - Ensure Home Directories are Created for New Users ----------"

echo "Making Changes to $LOGINDEFS to Ensure Home Directories are Created for New Users..."
sed -i 's/^CREATE_HOME.*/CREATE_HOME\t\tyes/' "$LOGINDEFS"

# Ensure Home Directories are Created for New Users end... (OK)
####################################################################################################
# Verify All Account Password Hashes are Shadowed... (OK)

echo "---------- Section 5.8 - Verify All Account Password Hashes are Shadowed ----------"

echo "You should see a x after this message if password hashes are shadowed..."
cut -d: -f2 /etc/passwd|uniq

# Verify All Account Password Hashes are Shadowed end... (OK)
####################################################################################################
# Set Deny and Lockout Time for Failed Password Attempts... (OK)

echo "---------- Section 5.9 - Set Deny and Lockout Time for Failed Password Attempts ----------"

echo "Configuring $PASSWORDAUTH and $SYSTEMAUTH files..."

cat > $PASSWORDAUTH <<EOF
# Edited by CentOS Hardening Script... passwordauth

auth        required                                     pam_env.so
auth        required                                     pam_faildelay.so delay=2000000
auth        [default=1 ignore=ignore success=ok]         pam_succeed_if.so uid >= 1000 quiet
auth        [default=1 ignore=ignore success=ok]         pam_localuser.so
auth 		required 									 pam_faillock.so preauth silent deny=3 unlock_time=900 fail_interval=900
auth        sufficient                                   pam_unix.so try_first_pass
auth 		[default=die] 								 pam_faillock.so authfail deny=3 unlock_time=900 fail_interval=900
auth        requisite                                    pam_succeed_if.so uid >= 1000 quiet_success
auth        sufficient                                   pam_sss.so forward_pass
auth        required                                     pam_deny.so

account 	required 									 pam_faillock.so
account     required                                     pam_unix.so
account     sufficient                                   pam_localuser.so
account     sufficient                                   pam_succeed_if.so uid < 1000 quiet
account     [default=bad success=ok user_unknown=ignore] pam_sss.so
account     required                                     pam_permit.so

password    requisite                                    pam_pwquality.so try_first_pass local_users_only retry=3
password    sufficient                                   pam_unix.so sha512 shadow try_first_pass use_authtok remember=5
password    sufficient                                   pam_sss.so use_authtok
password    required                                     pam_deny.so

session     optional                                     pam_keyinit.so revoke
session     required                                     pam_limits.so
-session    optional                                     pam_systemd.so
session     [success=1 default=ignore]                   pam_succeed_if.so service in crond quiet use_uid
session     required                                     pam_unix.so
session     optional                                     pam_sss.so
EOF

cat > $SYSTEMAUTH <<EOF
# Edited by CentOS Hardening Script... systemauth

auth        required                                     pam_env.so
auth        required                                     pam_faildelay.so delay=2000000
auth        sufficient                                   pam_fprintd.so
auth        [default=1 ignore=ignore success=ok]         pam_succeed_if.so uid >= 1000 quiet
auth        [default=1 ignore=ignore success=ok]         pam_localuser.so
auth 		required 									 pam_faillock.so preauth silent deny=3 unlock_time=900 fail_interval=900
auth        sufficient                                   pam_unix.so try_first_pass
auth 		[default=die] 								 pam_faillock.so authfail deny=3 unlock_time=900 fail_interval=900
auth        requisite                                    pam_succeed_if.so uid >= 1000 quiet_success
auth        sufficient                                   pam_sss.so forward_pass
auth        required                                     pam_deny.so

account 	required 									 pam_faillock.so
account     required                                     pam_unix.so
account     sufficient                                   pam_localuser.so
account     sufficient                                   pam_succeed_if.so uid < 1000 quiet
account     [default=bad success=ok user_unknown=ignore] pam_sss.so
account     required                                     pam_permit.so

password    requisite                                    pam_pwquality.so try_first_pass local_users_only retry=3
password    sufficient                                   pam_unix.so sha512 shadow try_first_pass use_authtok remember=5
password    sufficient                                   pam_sss.so use_authtok
password    required                                     pam_deny.so

session     optional                                     pam_keyinit.so revoke
session     required                                     pam_limits.so
-session    optional                                     pam_systemd.so
session     [success=1 default=ignore]                   pam_succeed_if.so service in crond quiet use_uid
session     required                                     pam_unix.so
session     optional                                     pam_sss.so
EOF

echo "Making configurations immutable... $PASSWORDAUTH and $SYSTEMAUTH files..."
chattr +i "$PASSWORDAUTH"
chattr +i "$SYSTEMAUTH"

# Set Deny and Lockout Time for Failed Password Attempts end... (OK)
####################################################################################################
# Multiple Console Screens and Console Locking... (OK)

echo "---------- Section 5.10 - Multiple Console Screens and Console Locking ----------"
for pack in screen vlock; do
    echo "Installing $pack package..."
    $APT install "$pack"
done

# Multiple Console Screens and Console Locking end... (OK)
####################################################################################################
# Disable Ctrl-Alt-Del Reboot Activation... (OK)

echo "---------- Section 5.11 - Disable Ctrl-Alt-Del Reboot Activation ----------"

echo "Disabling Ctrl-Alt-Delete combination..."

systemctl mask ctrl-alt-del.target

if [[ $VERBOSE == "Y" ]]; then
    systemctl status ctrl-alt-del.target --no-pager
    echo
fi

# Disable Ctrl-Alt-Del Reboot Activation end... (OK)
####################################################################################################
# Warning Banners for System Access... (OK)

echo "---------- Section 5.12 - Warning Banners for System Access ----------"

echo "Configuring warning banners for system access..."

for f in /etc/issue /etc/issue.net /etc/motd; do
    TEXT="
    /------------------------------------------------------------------------/
    |                       *** NOTICE TO USERS ***                          |
    |                                                                        |
    | This computer system is the private property of company_name...        |
    | It is for authorized use only.                                         |
    |                                                                        |
    | Users (authorized or unauthorized) have no explicit or implicit        |
    | expectation of privacy.                                                |
    |                                                                        |
    | Any or all uses of this system and all files on this system may be     |
    | intercepted, monitored, recorded, copied, audited, inspected, and      |
    | disclosed to your employer, to authorized site, government, and law    |
    | enforcement personnel, as well as authorized officials of government   |
    | agencies, both domestic and foreign.                                   |
    |                                                                        |
    | By using this system, the user consents to such interception,          |
    | monitoring, recording, copying, auditing, inspection, and disclosure   |
    | at the discretion of such personnel or officials.  Unauthorized or     |
    | improper use of this system may result in civil and criminal penalties |
    | and administrative or disciplinary action, as appropriate. By          |
    | continuing to use this system you indicate your awareness of and       |
    | consent to these terms and conditions of use. LOG OFF IMMEDIATELY if   |
    | you do not agree to the conditions stated in this warning.             |
    /------------------------------------------------------------------------/"
    echo -e "$TEXT" > $f
done

# Warning Banners for System Access end... (OK)
####################################################################################################
# Set Interactive Session Timeout... (OK)

echo "---------- Section 5.13 - Set Interactive Session Timeout ----------"

echo "Setting interactive session timeout at etc/profile file..."

if grep --silent ^TMOUT /etc/profile ; then
        sed -i "s/^TMOUT.*/TMOUT=600/g" /etc/profile
else
        echo -e "\n# Set TMOUT to 600 per security requirements" >> /etc/profile
        echo "TMOUT=600" >> /etc/profile
fi

# Set Interactive Session Timeout end... (OK)
####################################################################################################
# Configure History File Size... (OK)

echo "---------- Section 5.14 - Configure History File Size ----------"

echo "Configuring history file size at etc/profile file..."
sed -i 's/HISTSIZE=.*/HISTSIZE=5000/g' /etc/profile

# Configure History File Size end... (OK)
####################################################################################################

echo "---------- Chapter 5 - Completed ----------"

# Chapter 5 end...(OK)
####################################################################################################
# Chapter 6...(OK)

echo "---------- Chapter 6 - System Accounting with auditd ----------"

####################################################################################################
# Set Interactive Session Timeout... (OK)

echo "---------- Section 6.1 - Configure Logrotate and JournalD ----------"

echo "Configuring logrotate..."

cat > "$LOGROTATE" <<EOF
# see "man logrotate" for details
# rotate log files daily
daily

# keep 7 days worth of backlogs
rotate 7

# create new (empty) log files after rotating old ones
create

# use date as a suffix of the rotated file
dateext

# compressed log files
compress

# use xz to compress
compresscmd /usr/bin/xz
uncompresscmd /usr/bin/unxz
compressext .xz

# packages drop log rotation information into this directory
include /etc/logrotate.d

# no packages own wtmp and btmp -- we'll rotate them here
/var/log/wtmp {
    monthly
    create 0664 root utmp
    minsize 1M
    rotate 1
}

/var/log/btmp {
    missingok
    monthly
    create 0600 root utmp
    rotate 1
}

# system-specific logs may be also be configured here.
EOF

sed -i 's/^#Storage=.*/Storage=persistent/' "$JOURNALDCONF"
sed -i 's/^#SystemMaxFileSize=.*/SystemMaxFileSize=32M/' "$JOURNALDCONF"
sed -i 's/^#SystemKeepFree=.*/SystemKeepFree=512M/' "$JOURNALDCONF"
sed -i 's/^#SystemMaxUse=.*/SystemMaxUse=256M/' "$JOURNALDCONF"
sed -i 's/^#ForwardToSyslog=.*/ForwardToSyslog=yes/' "$JOURNALDCONF"
sed -i 's/^#Compress=.*/Compress=yes/' "$JOURNALDCONF"

logrotate -f /etc/logrotate.conf
systemctl restart systemd-journald

if [[ $VERBOSE == "Y" ]]; then
    systemctl status systemd-journald --no-pager
    echo
fi

####################################################################################################
# Auditd Configuration... (OK)

echo "---------- Section 6.2 - Auditd Configuration ----------"

echo "Installing rsyslog package..."
$APT install rsyslog

echo "Enable rsyslog service..."
systemctl enable rsyslog.service
systemctl start rsyslog.service

if [[ $VERBOSE == "Y" ]]; then
    systemctl status rsyslog.service --no-pager
    echo
fi

echo "Configuring $AUDITDCONF file..."

# Auditd num_logs
if grep -q ^num_logs "$AUDITDCONF"
then
	echo "Number of logs retained already exist..."
	sed -i 's/num_logs.*/num_logs = 10/g' "$AUDITDCONF"
	echo "Default: Replaced the count to 10..."
else
	echo "num_logs = 10" >> "$AUDITDCONF"
	echo "Number of logs retained is added & configured to 10..."
fi

# Auditd max_log_file and max_log_file_action
if grep -q ^max_log_file "$AUDITDCONF"
then
	echo "Max log file size already configured..."
	sed -i '/max_log_file_action/d' "$AUDITDCONF"
	sed -i 's/max_log_file.*/max_log_file = 30/g' "$AUDITDCONF"
	echo "Default:Replaced Max Log File Size 30MB..."
	echo "max_log_file_action = keep_logs" >> "$AUDITDCONF"
	echo "Default : max_log_file_action is set to keep_logs..."
else
	echo "max_log_file = 30" >> "$AUDITDCONF"
	echo "Max Log File Size is Added & configured to 30MB..."
fi

# Auditd space_left and admin_space_left
echo "Configure auditd to email you when space gets low..."
if grep -q ^space_left_action "$AUDITDCONF"
then
	echo "space_left is already configured..."
	sed -i '/admin_space_left_action/d' "$AUDITDCONF"
	sed -i 's/space_left_action.*/space_left_action = email/g' "$AUDITDCONF"
	echo "space_left_action is set to email..."
	echo "admin_space_left_action = halt" >> "$AUDITDCONF"
	echo "admin_space_left_action is set to halt..."
else
	echo "space_left_action = email" >> "$AUDITDCONF"
	echo "space_left_action is set to email..."
fi

# Auditd action_mail_acct
if grep -q ^action_mail_acct "$AUDITDCONF"
then
	sed -i 's/action_mail_acct.*/action_mail_acct = root/g' "$AUDITDCONF"
	echo "action_mail_acct is set to root..."
else
	echo "action_mail_acct = root" >> "$AUDITDCONF"
	echo "action_mail_acct is set to root..."
fi

# Auditd flush
if grep -q ^flush "$AUDITDCONF"
then
	echo "flush already exist..."
	sed -i 's/flush.*/flush = data/g' "$AUDITDCONF"
	echo "Default: flush = data..."
else
	echo "flush = data" >> "$AUDITDCONF"
	echo "Default: flush = data..."
fi

# Auditd Configuration end... (OK)
####################################################################################################
# Auditd Rules... (OK)

echo "---------- Section 6.3 - Auditd Rules ----------"

echo "Configuring $AUDITRULES file..."
echo -e "
## First rule - delete all
-D

## Increase the buffers to survive stress events.
## Make this bigger for busy systems
-b 8192

## Set failure mode to syslog
-f 2

# audit_time_rules - Record attempts to alter time through adjtime
-a always,exit -F arch=b64 -S adjtimex -k audit_time_rules

# audit_time_rules - Record attempts to alter time through settimeofday
-a always,exit -F arch=b64 -S settimeofday -k audit_time_rules

# audit_time_rules - Record Attempts to Alter Time Through stime
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k audit_time_rules

# audit_time_rules - Record Attempts to Alter Time Through clock_settime
-a always,exit -F arch=b64 -S clock_settime -k audit_time_rules

# Record Attempts to Alter the localtime File
-w /etc/localtime -p wa -k audit_time_rules

# Record Events that Modify User/Group Information
# audit_account_changes
-w /etc/group -p wa -k audit_account_changes
-w /etc/passwd -p wa -k audit_account_changes
-w /etc/gshadow -p wa -k audit_account_changes
-w /etc/shadow -p wa -k audit_account_changes
-w /etc/security/opasswd -p wa -k audit_account_changes

# Record Events that Modify the System's Network Environment
# audit_network_modifications
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k audit_network_modifications
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k audit_network_modifications
-w /etc/issue -p wa -k audit_network_modifications
-w /etc/issue.net -p wa -k audit_network_modifications
-w /etc/hosts -p wa -k audit_network_modifications
-w /etc/sysconfig/network -p wa -k audit_network_modifications

#Record Events that Modify the System's Mandatory Access Controls
-w /etc/selinux/ -p wa -k MAC-policy

#Record Events that Modify the System's Discretionary Access Controls - chmod
-a always,exit -F arch=b32 -S chmod -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chmod  -F auid>=500 -F auid!=4294967295 -k perm_mod

#Record Events that Modify the System's Discretionary Access Controls - chown
-a always,exit -F arch=b32 -S chown -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -F auid>=500 -F auid!=4294967295 -k perm_mod

#Record Events that Modify the System's Discretionary Access Controls - fchmod
-a always,exit -F arch=b32 -S fchmod -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S fchmod -F auid>=500 -F auid!=4294967295 -k perm_mod

#Record Events that Modify the System's Discretionary Access Controls - fchmodat
-a always,exit -F arch=b32 -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod

#Record Events that Modify the System's Discretionary Access Controls - fchown
-a always,exit -F arch=b32 -S fchown -F auid>=500 -F auid!=4294967295 -k perm_mod

#Record Events that Modify the System's Discretionary Access Controls - fsetxattr
-a always,exit -F arch=b32 -S fsetxattr -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S fsetxattr -F auid>=500 -F auid!=4294967295 -k perm_mod

#Record Events that Modify the System's Discretionary Access Controls - lchown
-a always,exit -F arch=b32 -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod

#Record Events that Modify the System's Discretionary Access Controls - lremovexattr
-a always,exit -F arch=b32 -S lremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S lremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod

#Record Events that Modify the System's Discretionary Access Controls - fremovexattr
-a always,exit -F arch=b32 -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod

#Record Events that Modify the System's Discretionary Access Controls - fsetxattr
-a always,exit -F arch=b32 -S lsetxattr -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S lsetxattr -F auid>=500 -F auid!=4294967295 -k perm_mod

#Record Events that Modify the System's Discretionary Access Controls - removexattr
-a always,exit -F arch=b32 -S removexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S removexattr -F auid>=500 -F auid!=4294967295 -k perm_mod

#Record Events that Modify the System's Discretionary Access Controls - setxattr
-a always,exit -F arch=b32 -S setxattr -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -F auid>=500 -F auid!=4294967295 -k perm_mod

#Record Attempts to Alter Logon and Logout Events
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins

#Record Attempts to Alter Process and Session Initiation Information
-w /var/run/utmp -p wa -k session
-w /var/log/btmp -p wa -k session
-w /var/log/wtmp -p wa -k session

#Ensure auditd Collects Unauthorized Access Attempts to Files (unsuccessful)
-a always,exit -F arch=b32 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access

#Ensure auditd Collects Information on the Use of Privileged Commands
#
#  Find setuid / setgid programs then modify and uncomment the line below.
#
##  sudo find / -xdev -type f -perm -4000 -o -perm -2000 2>/dev/null
#
# -a always,exit -F path=SETUID_PROG_PATH -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

#Ensure auditd Collects Information on Exporting to Media (successful)
-a always,exit -F arch=b32 -S mount -F auid>=500 -F auid!=4294967295 -k export
-a always,exit -F arch=b64 -S mount -F auid>=500 -F auid!=4294967295 -k export

#Ensure auditd Collects File Deletion Events by User
-a always,exit -F arch=b32 -S rmdir -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete
-a always,exit -F arch=b64 -S rmdir -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete

#Ensure auditd Collects System Administrator Actions
-w /etc/sudoers -p wa -k actions

#Ensure auditd Collects Information on Kernel Module Loading and Unloading
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

-a always,exit -F arch=b32 -S init_module,finit_module,delete_module -F key=modules
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -F key=modules
-w /var/run/faillock -p wa -k logins
-a always,exit -F arch=b32 -S stime -F key=audit_time_rules
# -a always,exit -F arch=b32 -S settimeofday -F key=audit_time_rules
# -a always,exit -F arch=b64 -S settimeofday -F key=audit_time_rules
# -a always,exit -F arch=b32 -S adjtimex -F key=audit_time_rules
# -a always,exit -F arch=b64 -S adjtimex -F key=audit_time_rules
-a always,exit -F arch=b32 -S clock_settime -F a0=0x0 -F key=time-change
-a always,exit -F arch=b64 -S clock_settime -F a0=0x0 -F key=time-change
-a always,exit -F arch=b32 -S fchown -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S fchown -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S setxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S setxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S fsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S fsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S removexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S removexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S lsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S lsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S chmod -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S chmod -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S chown -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S chown -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S fchmod -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S fchmod -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S fchownat -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S fchownat -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S lchown -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S lchown -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S fchmodat -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S fchmodat -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S lremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S lremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S truncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S truncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S unlinkat -F auid>=1000 -F auid!=unset -F key=delete
-a always,exit -F arch=b64 -S unlinkat -F auid>=1000 -F auid!=unset -F key=delete
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=unset -F key=export
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -F key=export
-a always,exit -F arch=b32 -S openat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S openat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S openat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S openat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S open -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S open -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S open -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S open -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S rmdir -F auid>=1000 -F auid!=unset -F key=delete
-a always,exit -F arch=b64 -S rmdir -F auid>=1000 -F auid!=unset -F key=delete
-a always,exit -F arch=b32 -S rename -F auid>=1000 -F auid!=unset -F key=delete
-a always,exit -F arch=b64 -S rename -F auid>=1000 -F auid!=unset -F key=delete
-a always,exit -F arch=b32 -S renameat -F auid>=1000 -F auid!=unset -F key=delete
-a always,exit -F arch=b64 -S renameat -F auid>=1000 -F auid!=unset -F key=delete
-a always,exit -F arch=b32 -S unlink -F auid>=1000 -F auid!=unset -F key=delete
-a always,exit -F arch=b64 -S unlink -F auid>=1000 -F auid!=unset -F key=delete

#Make the auditd Configuration Immutable
-e 2
" >> "$AUDITRULES"

echo "Enable auditd service..."
systemctl enable auditd.service
systemctl start auditd.service

if [[ $VERBOSE == "Y" ]]; then
    systemctl status auditd.service --no-pager
    echo
fi

# Auditd Rules end... (OK)
####################################################################################################
# Enable Kernel Auditing... (OK)

# echo "---------- Section 6.4 - Enable Kernel Auditing ----------"

echo "Enable Kernel auditing..."
sed -i 's/^GRUB_CMDLINE_LINUX=.*/GRUB_CMDLINE_LINUX="audit=1"/' "$DEFAULTGRUB"
grub2-mkconfig -o /boot/grub2/grub.cfg

# Enable Kernel Auditing end... (OK)
####################################################################################################

echo "---------- Chapter 6 - Completed ----------"

# Chapter 6 end...(OK)
####################################################################################################
# Chapter 7...(OK)

echo "---------- Chapter 7 - Software Integrity Checking ----------"

####################################################################################################
# Advanced Intrusion Detection Environment... (OK)

echo "---------- Section 7.1 - Advanced Intrusion Detection Environment ----------"

echo "Installing AIDE..."
$APT install aide && /usr/sbin/aide --init && cp /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz && /usr/sbin/aide --check && bind ^C stuff ^C
echo "AIDE is installed..."
echo "05 4 * * * root /usr/sbin/aide --check" >> /etc/crontab
echo "Configured periodic execution of AIDE, runs every morning at 04:30"

# Advanced Intrusion Detection Environment end... (OK)
####################################################################################################

echo "---------- Chapter 7 - Completed ----------"

# Chapter 7 end...(OK)
####################################################################################################
# Chapter 8...(OK)

echo "---------- Chapter 8 - Logging ----------"

####################################################################################################
# Logwatch...(OK)

echo "---------- Section 8.1 - Logwatch ----------"

echo "Installing logwatch package..."
$APT install logwatch

# Logwatch end...(OK)
####################################################################################################

echo "---------- Chapter 8 - Completed ----------"

# Chapter 8 end...(OK)
####################################################################################################
# Chapter 9...(OK)

echo "---------- Chapter 9 - Security Software ----------"

####################################################################################################
# Malware Scanners ...(OK)

echo "---------- Section 9.1 - Malware Scanners ----------"

echo "Installing malware scanners..."
for pack in rkhunter clamav clamav-update clamd; do
    echo "Installing $pack package..."
    $APT install "$pack"
done

echo "Checking and configuring rootkit hunter..."
rkhunter --update
rkhunter --propupd
sed -i 's/ALLOW_SSH_ROOT_USER=.*/ALLOW_SSH_ROOT_USER=no/g' "$RKHUNTERCONF"

echo "Checking and configuring CLAMAV..."
setsebool -P antivirus_can_scan_system 1
freshclam -v
sed -i 's/#LocalSocket \/run/LocalSocket \/run/g' /etc/clamd.d/scan.conf
sed -i 's/scanner (%i) daemon/scanner daemon/g' /usr/lib/systemd/system/clamd@.service
sed -i 's/\/etc\/clamd.d\/%i.conf/\/etc\/clamd.d\/scan.conf/g' /usr/lib/systemd/system/clamd@.service

systemctl enable clamav-freshclam.service
systemctl start clamav-freshclam.service
if [[ $VERBOSE == "Y" ]]; then
    systemctl status clamav-freshclam.service --no-pager
    echo
fi

# Malware Scanners end...(OK)
####################################################################################################

echo "---------- Chapter 9 - Completed ----------"

# Chapter 9 end...(OK)
####################################################################################################
# Chapter 10...(OK)

echo "---------- Chapter 10 - Process Accounting ----------"

####################################################################################################
# Process Accounting...(OK)

echo "---------- Section 10.1 - Process Accounting ----------"

echo "Installing psacct package..."
$APT install psacct
systemctl enable psacct.service
systemctl start psacct.service
if [[ $VERBOSE == "Y" ]]; then
    systemctl status psacct.service --no-pager
    echo
fi

# Process Accounting end...(OK)
####################################################################################################

echo "---------- Chapter 10 - Completed ----------"

# Chapter 10 end...(OK)
####################################################################################################

echo "---------- Hardening the system settings - Complete ----------"
echo "---------- Let's install and harden other services... ----------"

####################################################################################################
# Configuring SSHD Server... (OK)

echo "Configuring SSHD server..."
echo "$SSHDFILE file location..."

cp "$SSHDFILE" "$SSHDFILE-$(date +%s)"

cat > "$SSHDFILE" <<EOF
# SSH port.
Port 22

# Listen on IPv4 only.
ListenAddress 0.0.0.0

# Protocol version 1 has been exposed.
Protocol 2

#
# OpenSSH cipher-related release notes.
# OpenSSH 6.2: added support for AES-GCM authenticated encryption. 
# The cipher is available as aes128-gcm@openssh.com and aes256-gcm@openssh.com.
# OpenSSH 6.5: added new cipher chacha20-poly1305@openssh.com.
# OpenSSH 6.7: removed unsafe algorithms. CBC ciphers are disabled by default:
# aes128-cbc, aes192-cbc, aes256-cbc, 3des-cbc, blowfish-cbc, cast128-cbc.
# OpenSSH 6.9: promoted chacha20-poly1305@openssh.com to be the default cipher.
#
Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,3des-cbc,aes192-cbc,aes256-cbc

#
# OpenSSH 6.2: added support for the UMAC-128 MAC as umac-128@openssh.com 
# and umac-128-etm@openssh.com. The latter being an encrypt-then-mac mode.
# Do not use umac-64 or umac-64-etm because of a small 64 bit tag size.
# Do not use any SHA1 (e.g. hmac-sha1, hmac-sha1-etm@openssh.com) MACs 
# because of a weak hashing algorithm. 
# Do not use hmac-sha2-256, hmac-sha2-512 or umac-128@openssh.com 
# because of an encrypt-and-MAC mode. See the link below:
# https://crypto.stackexchange.com/questions/202/should-we-mac-then-encrypt-or-encrypt-then-mac
#
MACs hmac-sha2-512,hmac-sha2-256

#
# OpenSSH 6.5: added support for ssh-ed25519. It offers better security 
# than ECDSA and DSA.
# OpenSSH 7.0: disabled support for ssh-dss. 
# OpenSSH 7.2: added support for rsa-sha2-512 and rsa-sha2-256.
#
HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,ssh-rsa,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ssh-rsa-cert-v01@openssh.com,ssh-dss-cert-v01@openssh.com,ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com

#
# OpenSSH 6.5: added support for key exchange using elliptic-curve
# Diffie Hellman in Daniel Bernstein's Curve25519.
# OpenSSH 7.3: added support for diffie-hellman-group14-sha256,
# diffie-hellman-group16-sha512 and diffie-hellman-group18-sha512.
#
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group18-sha512,diffie-hellman-group16-sha512,diffie-hellman-group14-sha256

# HostKeys for protocol version 2.
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# Disabled because uses a small 1024 bit key.
#HostKey /etc/ssh/ssh_host_dsa_key

# Disabled because uses weak elliptic curves.
# See: https://safecurves.cr.yp.to/
#HostKey /etc/ssh/ssh_host_ecdsa_key


# INFO is a basic logging level that will capture user login/logout activity.
# DEBUG logging level is not recommended for production servers.
LogLevel INFO

# Disconnect if no successful login is made in 60 seconds.
LoginGraceTime 60

# Do not permit root logins via SSH.
PermitRootLogin no

# Check file modes and ownership of the user's files before login.
StrictModes yes

# Close TCP socket after 2 invalid login attempts.
MaxAuthTries 2

# The maximum number of sessions per network connection.
MaxSessions 3

# User/group permissions.
AllowGroups
DenyUsers root
DenyGroups root

# Password and public key authentications.
PasswordAuthentication yes
PermitEmptyPasswords no
PubkeyAuthentication no
AuthorizedKeysFile  .ssh/authorized_keys

# Disable unused authentications mechanisms.
ChallengeResponseAuthentication no
KerberosAuthentication no
GSSAPIAuthentication no
HostbasedAuthentication no
IgnoreUserKnownHosts yes

# Disable insecure access via rhosts files.
IgnoreRhosts yes

AllowAgentForwarding no
AllowTcpForwarding no

# Disable X Forwarding.
X11Forwarding no

# Disable message of the day but print last log.
PrintMotd yes
PrintLastLog yes

# Show banner.
Banner /etc/issue

# Do not send TCP keepalive messages.
TCPKeepAlive no

# Prevent users from potentially bypassing some access restrictions.
PermitUserEnvironment no

# Disable compression.
Compression no

# Disconnect the client if no activity has been detected for 900 seconds.
ClientAliveInterval 300
ClientAliveCountMax 0

# Do not look up the remote hostname.
UseDNS no

UsePAM yes
EOF

systemctl restart sshd.service

if [[ $VERBOSE == "Y" ]]; then
    systemctl status sshd.service --no-pager
    echo
fi

# Configuring SSHD Server... (OK)
####################################################################################################
# Network Time Protocol through chronyd.service...(OK)

cat > /etc/sysconfig/chronyd <<EOF
OPTIONS="-u chrony"
EOF

echo "Enabling chronyd.service..."
systemctl enable chronyd.service

if [[ $VERBOSE == "Y" ]]; then
    systemctl status chronyd.service --no-pager
    echo
fi

# Network Time Protocol through chronyd.service end...(OK)
####################################################################################################
# Disable X Windows Startup...(OK)

echo "Disabling X Windows startup..."
if [[ $GUI == "N" ]]; then
    echo "GUI is set to NO. Disabling X Windows Startup..."
    systemctl set-default multi-user.target
else
    echo "GUI is set to YES.Skipping..."
fi

# Disable X Windows Startup end...(OK)
####################################################################################################
# Secure user and services host files...(OK)

echo "Securing .rhosts and hosts.equiv"

for dir in $(awk -F ":" '{print $6}' /etc/passwd); do
    find "$dir" \( -name "hosts.equiv" -o -name ".rhosts" \) -exec rm -f {} \; 2> /dev/null
done
    
if [[ -f /etc/hosts.equiv ]]; then
    rm /etc/hosts.equiv
fi

# Secure user and services host files end...(OK)
####################################################################################################
# Fail2Ban...(OK)

echo "Enable fail2ban..."

$APT install fail2ban
systemctl enable fail2ban
systemctl start fail2ban

if [[ $VERBOSE == "Y" ]]; then
    systemctl status fail2ban --no-pager
    echo
fi

# Fail2Ban end...(OK)
####################################################################################################


echo "---------- Installation and hardening of other services - Complete ----------"

####################################################################################################
# Installing Modules and Apache for CentOS...(OK)

echo "---------- At last let's install, configure and secure Apache Web Server ----------"

for pack in $PACKAGES; do
    echo "Installing $pack package..."
    $APT install "$pack"
done

chown apache:apache -R /var/www/html
chmod -R 511 /var/www/html
restorecon -r /var/www/html

echo "Installing mod_evasive..."
$APT install mod_evasive

echo "Configuring $APACHE2DFILE ..."
cat > "$APACHE2DFILE" <<EOF
ServerRoot "/etc/httpd"

Listen 80

Include conf.modules.d/*.conf

User apache
Group apache

ServerAdmin root@localhost

<Directory />
    AllowOverride none
    Require all denied
</Directory>


DocumentRoot "/var/www/html"

<Directory /var/www/>
    Order Allow,Deny
    Allow from all
    Options +FollowSymLinks -Indexes +IncludesNoExec
    AllowOverride None
    Require all granted
</Directory>

<IfModule dir_module>
    DirectoryIndex index.html
</IfModule>

<Files ".ht*">
    Require all denied
</Files>


<IfModule mime_module>
    #
    # TypesConfig points to the file containing the list of mappings from
    # filename extension to MIME-type.
    #
    TypesConfig /etc/mime.types

    #
    # AddType allows you to add to or override the MIME configuration
    # file specified in TypesConfig for specific file types.
    #
    #AddType application/x-gzip .tgz
    #
    # AddEncoding allows you to have certain browsers uncompress
    # information on the fly. Note: Not all browsers support this.
    #
    #AddEncoding x-compress .Z
    #AddEncoding x-gzip .gz .tgz
    #
    # If the AddEncoding directives above are commented-out, then you
    # probably should define those extensions to indicate media types:
    #
    AddType application/x-compress .Z
    AddType application/x-gzip .gz .tgz

    #
    # AddHandler allows you to map certain file extensions to "handlers":
    # actions unrelated to filetype. These can be either built into the server
    # or added with the Action directive (see below)
    #
    # To use CGI scripts outside of ScriptAliased directories:
    # (You will also need to add "ExecCGI" to the "Options" directive.)
    #
    #AddHandler cgi-script .cgi

    # For type maps (negotiated resources):
    #AddHandler type-map var

    #
    # Filters allow you to process content before it is sent to the client.
    #
    # To parse .shtml files for server-side includes (SSI):
    # (You will also need to add "Includes" to the "Options" directive.)
    #
    AddType text/html .shtml
    AddOutputFilter INCLUDES .shtml
</IfModule>

AddDefaultCharset UTF-8

<IfModule mime_magic_module>
    #
    # The mod_mime_magic module allows the server to use various hints from the
    # contents of the file itself to determine its type.  The MIMEMagicFile
    # directive tells the module where the hint definitions are located.
    #
    MIMEMagicFile conf/magic
</IfModule>

<IfModule mod_headers.c>
    Header set X-XSS-Protection "1; mode=block"
    Header edit Set-Cookie ^(.*)$ $1;HttpOnly;Secure
</IfModule>

IncludeOptional conf.d/*.conf

ServerSignature Off
ServerTokens Prod
FileETag None
TraceEnable Off
Header always append X-Frame-Options SAMEORIGIN
Timeout 30
EOF


echo "Configuring Mod Security..."

$APT install mod_security

mkdir /etc/httpd/crs
cd /etc/httpd/crs
wget https://github.com/SpiderLabs/owasp-modsecurity-crs/tarball/master
tar -xvf master
mv SpiderLabs-owasp-modsecurity-crs-* owasp-modsecurity-crs
cd /etc/httpd/crs/owasp-modsecurity-crs/
cp modsecurity_crs_10_setup.conf.example modsecurity_crs_10_setup.conf

touch /etc/httpd/modsecurity.d/mod_security.conf

cat > /etc/httpd/modsecurity.d/mod_security.conf <<EOF
<IfModule mod_security2.c>
    SecRuleEngine On
    SecStatusEngine On
    SecRequestBodyAccess On
    SecResponseBodyAccess On 
    SecResponseBodyMimeType text/plain text/html text/xml application/octet-stream 
    SecDataDir /tmp
    SecRule RESPONSE_STATUS "@streq 408" "phase:5,t:none,nolog,pass,setvar:ip.slow_dos_counter=+1, expirevar:ip.slow_dos_counter=60, id:'1234123456'"
    SecRule IP:SLOW_DOS_COUNTER "@gt 5" "phase:1,t:none,log,drop,msg:'Client Connection Dropped due to high number of slow DoS alerts', id:'1234123457'"
</IfModule>
EOF

echo "Configuring Mod Evasive..."

mkdir /var/log/mod_evasive
chown apache:apache /var/log/mod_evasive/

cat > /etc/httpd/conf.d/mod_evasive.conf <<EOF
LoadModule evasive20_module modules/mod_evasive24.so

<IfModule mod_evasive24.c>
   DOSHashTableSize 3097
   DOSPageCount  2
   DOSSiteCount  50
   DOSPageInterval 1
   DOSSiteInterval  1
   DOSBlockingPeriod  600
   DOSLogDir   /var/log/mod_evasive
   DOSEmailNotify  root@localhost
</IfModule>
EOF

echo "Configuring Welcome..."

cat > /etc/httpd/conf.d/welcome.conf <<EOF
# 
# This configuration file enables the default "Welcome" page if there
# is no default index page present for the root URL.  To disable the
# Welcome page, comment out all the lines below. 
#
# NOTE: if this file is removed, it will be restored on upgrades.
#
<LocationMatch "^/+$">
    Options -Indexes
    ErrorDocument 403 /noindex/index.html
</LocationMatch>

<Directory /usr/share/httpd/noindex>
    Options MultiViews
    DirectoryIndex index.html

    AddLanguage en-US .en-US
    AddLanguage es-ES .es-ES
    AddLanguage zh-CN .zh-CN
    AddLanguage zh-HK .zh-HK
    AddLanguage zh-TW .zh-TW

    LanguagePriority en
    ForceLanguagePriority Fallback

    AllowOverride None
    Require all granted
</Directory>

Alias /noindex /usr/share/httpd/noindex
EOF

semanage fcontext --add -t httpd_sys_rw_content_t "/var/log/mod_evasive(/.*)?"
restorecon -r /var/log/mod_evasive

echo "Configuring QoS Module..."
touch /etc/httpd/conf.d/qos.conf

cat > /etc/httpd/conf.d/qos.conf <<EOF
<IfModule mod_qos.c>
    # handles connections from up to 100000 different IPs
    QS_ClientEntries 100000
    # will allow only 20 connections per IP
    QS_SrvMaxConnPerIP 20
    # disables keep-alive when 70% of the TCP connections are occupied:
    QS_SrvMaxConnClose      70%
   # minimum request/response speed (deny slow clients blocking the server, ie. slowloris keeping connections open without requesting anything):
    QS_SrvMinDataRate       150 1200
    # and limit request header and body (carefull, that limits uploads and post requests too):
    # LimitRequestFields      30
    # QS_LimitRequestBody     102400
</IfModule>
EOF

echo "Restarting Apache HTTPD..."
systemctl restart httpd
systemctl enable httpd

if [[ $VERBOSE == "Y" ]]; then
    systemctl status httpd.service --no-pager
    httpd -M
    echo
fi

# Installing Modules and Apache for CentOS end...(OK)
####################################################################################################
# Ensure files ownership...(OK)

echo "Ensuring files ownership (user and group)..."
find / -ignore_readdir_race -nouser -print -exec chown root {} \;
find / -ignore_readdir_race -nogroup -print -exec chgrp root {} \;

# Ensure files ownership end...(OK)
####################################################################################################
# Ensure permissions on all logfiles are configured...(OK)

echo "Ensuring permissions on var/log directory..."
find /var/log -type f -exec chmod g-wx,o-rwx {} +

# Ensure permissions on all logfiles are configured end...(OK)
####################################################################################################
# Check systemd-delta...(OK)

if [[ $VERBOSE == "Y" ]]; then
    echo "Checking systemd-delta..."
    systemd-delta --no-pager
    echo
fi

# Check systemd-delta end...(OK)
####################################################################################################
# End of script file...(OK)

echo "The script finished executing..."
echo "Reboot is recommended!"

# End of script file end...(OK)
####################################################################################################