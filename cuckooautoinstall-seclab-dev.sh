#!/bin/bash

# Cuckoo Auto Installation Script - SRG SSR INIT Security

# Copyright (C) 2016 -2017 Patrick Vanreck - patrick.vanreck@srgssr.ch
# Copyright (C) 2016 Stefan Mettler - stefan.mettler@srgssr.ch

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# any later version.

# Addons and Updates:
# -------------------
# Within this version we added some extra tools to harden the Linux and
# add more shell based monitoring tools like iptraf, nethogs and jnettop.
# Also the installation of syslog-ng is included to send logdata to a Syslogger. 
# This Version includes the Volatility-2.5 and the last Lynis and Glances version.
# Remember that Lynis has to be configured later

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

source /etc/os-release

# Configuration variables. You can override these in config.
SUDO="sudo"
TMPDIR=$(mktemp -d)
RELEASE=$(lsb_release -cs)
UBUNTU-VERSION=$(lsb_release -ds)
CUCKOO_USER="cuckoo"
CUCKOO_PATH="/opt/cuckoo/"
OPT_PATH="/opt/"
CUSTOM_PKGS="htop atop iotop iftop jnettop iptraf syslog-ng multitail tcptrack nethogs grc python python-pip python-dev libffi-dev libssl-dev zip"
ORIG_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}"  )" && pwd  )
VOLATILITY_URL="http://downloads.volatilityfoundation.org/releases/2.4/volatility-2.4.tar.gz"
VOLATILITY_2_5_URL="http://downloads.volatilityfoundation.org/releases/2.5/volatility-2.5.zip"
SSDEEP_URL="http://sourceforge.net/projects/ssdeep/files/ssdeep-2.13/ssdeep-2.13.tar.gz/download -O ssdeep-2.13.tar.gz"
VIRTUALBOX_REP="deb http://download.virtualbox.org/virtualbox/debian $RELEASE contrib"
VIRTUALBOX_XTPACK_URL="http://download.virtualbox.org/virtualbox/5.0.24/Oracle_VM_VirtualBox_Extension_Pack-5.0.24-108355a.vbox-extpack"
VIRTUALBOX_XTPACK="Oracle_VM_VirtualBox_Extension_Pack-5.0.24-108355a.vbox-extpack"
VIRTUALBOX_PHP="http://sourceforge.net/projects/phpvirtualbox/files/phpvirtualbox-5.0-5.zip/download -O phpvirtualbox.zip"
CUCKOO_REPO="https://github.com/cuckoosandbox/cuckoo.git"
YARA_REPO="https://github.com/plusvic/yara.git"
JANSSON_REPO="https://github.com/akheron/jansson.git"
PYDEEP_REPO="https://github.com/kbandla/pydeep.git"
FOG_REPO="https://github.com/FOGProject/fogproject.git"
VMCLOAK_REPO="https://github.com/jbremer/vmcloak.git"

LOG=$(mktemp)
UPGRADE=false

declare -a packages
declare -a python_packages 

packages["debian"]="python-pip python-sqlalchemy mongodb python-bson python-dpkt python-jinja2 python-magic python-gridfs python-libvirt python-bottle python-pefile python-chardet git build-essential autoconf automake libtool dh-autoreconf libcurl4-gnutls-dev libmagic-dev python-dev tcpdump libcap2-bin virtualbox dkms python-pyrex"
packages["ubuntu"]="python-pip python-sqlalchemy mongodb python-bson python-dpkt python-jinja2 python-magic python-gridfs python-libvirt python-bottle python-pefile python-chardet git build-essential autoconf automake libtool dh-autoreconf libcurl4-gnutls-dev libmagic-dev python-dev tcpdump libcap2-bin virtualbox dkms python-pyrex"
python_packages=(pymongo django pydeep maec py3compat lxml cybox distorm3 pycrypto)

# Pretty icons
log_icon="\e[31m✓\e[0m"
log_icon_ok="\e[32m✓\e[0m"
log_icon_nok="\e[31m✗\e[0m"

# -

print_copy(){
cat <<EO

┌─────────────────────────────────────────────────────────┐
│          Cuckoo Sandbox AutoInstall Script 0.3          │
│          =====================================          │
│                                                         │
│        Based on Ubuntu Release: $UBUNTU-VERSION      │
│                                                         │
│     Patrick Vanreck - <patrick.vanreckl@srgssr.ch>      │
│     Stefan Mettler - <stefan.mettler@srgssr.ch>         │
│                                                         │
│              SRGSSR INIT Security - 2016                │
│                                                         │
└─────────────────────────────────────────────────────────┘
EO
}

check_viability(){
    [[ $UID != 0 ]] && {
        type -f $SUDO || {
            echo "You're not root and you don't have $SUDO, please become root or install $SUDO before executing $0"
            exit
        }
    } || {
        SUDO=""
    }

    [[ ! -e /etc/debian_version ]] && {
        echo  "This script currently works only on debian-based (debian, ubuntu...) distros"
        exit 1
    }
}

print_help(){
    cat <<EOH
Usage: $0 [--verbose|-v] [--help|-h] [--upgrade|-u]

    --verbose   Print output to stdout instead of temp logfile
    --help      This help menu
    --upgrade   Use newer volatility, yara and jansson versions (install from source)

EOH
    exit 1
}

setopts(){
    optspec=":hvu-:"
    while getopts "$optspec" optchar; do
        case "${optchar}" in
            -)
                case "${OPTARG}" in
                    help) print_help ;;
                    upgrade) UPGRADE=true ;;
                    verbose) LOG=/dev/stdout ;;
                esac;;
            h) print_help ;;
            v) LOG=/dev/stdout;;
            u) UPGRADE=true;;
        esac
    done
}


run_and_log(){
    $1 &> ${LOG} && {
        _log_icon=$log_icon_ok
    } || {
        _log_icon=$log_icon_nok
        exit_=1
    }
    echo -e "${_log_icon} ${2}"
    [[ $exit_ ]] && { echo -e "\t -> ${_log_icon} $3";  exit; }
}

clone_repos(){
    git clone ${JANSSON_REPO}
    git clone ${YARA_REPO}
	git clone ${PYDEEP_REPO}
	git clone ${FOG_REPO}
	git clone ${VMCLOAK_REPO}
    return 0
}

cdcuckoo(){
    eval cd ~${CUCKOO_USER}
    return 0
}

create_cuckoo_user(){
    $SUDO adduser  --disabled-password -gecos "" ${CUCKOO_USER}
    $SUDO usermod -G vboxusers ${CUCKOO_USER}
	$SUDO usermod -a -G libvirtd ${CUCKOO_USER}
    return 0
}

clone_cuckoo(){
    cdcuckoo
    $SUDO cd $OPT_PATH
    $SUDO git clone $CUCKOO_REPO
    cd $CUCKOO_PATH
    [[ $STABLE ]] && $SUDO git checkout 5231ff3a455e9c1c36239a025a1f6840029a9ed8
    cd ..
    $SUDO chown -R ${CUCKOO_USER}:${CUCKOO_USER} cuckoo
    cd $TMPDIR
    return 0
}

clone_fog(){
    $SUDO cd $OPT_PATH
    $SUDO git clone $FOG_REPO
    cd $TMPDIR
    return 0
}

create_hostonly_iface(){
    $SUDO vboxmanage hostonlyif create
    $SUDO iptables -A FORWARD -o eth0 -i vboxnet0 -s 192.168.56.0/24 -m conntrack --ctstate NEW -j ACCEPT
    $SUDO iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    $SUDO iptables -A POSTROUTING -t nat -j MASQUERADE
    $SUDO sysctl -w net.ipv4.ip_forward=1
    return 0
}

setcap(){
    $SUDO /bin/bash -c 'setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump' 2 &> /dev/null
    return 0
}

fix_django_version(){
    cdcuckoo
    python -c "import django; from distutils.version import LooseVersion; import sys; sys.exit(LooseVersion(django.get_version()) <= LooseVersion('1.5'))" && { 
        egrep -i "templates = \(.*\)" cuckoo/web/web/settings.py || $SUDO sed -i '/TEMPLATE_DIRS/{ N; s/.*/TEMPLATE_DIRS = \( \("templates"\),/; }' cuckoo/web/web/settings.py
    }
    cd $TMPDIR
    return 0
}

enable_mongodb(){
    cdcuckoo
    $SUDO sed -i '/\[mongodb\]/{ N; s/.*/\[mongodb\]\nenabled = yes/; }' cuckoo/conf/reporting.conf
    cd $TMPDIR
    return 0
}

build_jansson(){
    # Not cool =(
    cd ${TMPDIR}/jansson
    autoreconf -vi --force
    ./configure
    make
    make check
    $SUDO make install
    cd ${TMPDIR}
    return 0
}

build_yara(){
    cd ${TMPDIR}/yara
    ./bootstrap.sh
    $SUDO autoreconf -vi --force
    ./configure --enable-cuckoo --enable-magic
    make
    $SUDO make install
    cd yara-python/
    $SUDO python setup.py install
    cd ${TMPDIR}
    return 0
}

build_volatility(){
    wget $VOLATILITY_URL
    tar xvf volatility-2.4.tar.gz
    cd volatility-2.4/
    $SUDO python setup.py build
    $SUDO python setup.py install
    return 0
}

build_volatility_2_5(){
    wget $VOLATILITY_2_5_URL
    unzip volatility-2.5.zip
    cd volatility-master/
    $SUDO python setup.py build
    $SUDO python setup.py install
    return 0
}

build_ssdeep(){
    cd ${TMPDIR}
    wget $SSDEEP_URL
	tar xvf ssdeep-2.13.tar.gz
	cd ssdeep-2.13/
    ./configure
	make
	$SUDO make install
    cd ${TMPDIR}
    return 0
}

build_pydeep(){
    cd ${TMPDIR}/pydeep
    $SUDO python setup.py build
    $SUDO python setup.py test
    $SUDO python setup.py install
    cd ${TMPDIR}
    return 0
}

build_fog(){
    cd ${TMPDIR}/fogproject-dev-branch
    $SUDO ./installfog.sh -y
    return 0
}

build_vmcloak(){
    cd ${TMPDIR}/vmcloak
    $SUDO python setup.py install
    return 0
}

pip_install_upgrade(){
    # Upgrade the pip tool to have last python intallation tool
    $SUDO pip install --upgrade pip
    return 0
}

pip(){
    # TODO: Calling upgrade here should be optional.
    # Unless we make all of this into a virtualenv, wich seems like the
    # correct way to follow
    for package in ${@}; do $SUDO pip install ${package} --upgrade; done
    return 0
}

prepare_virtualbox(){
    cd ${TMPDIR}
    echo ${VIRTUALBOX_REP} |$SUDO tee /etc/apt/sources.list.d/virtualbox.list
    wget -O - https://www.virtualbox.org/download/oracle_vbox.asc | $SUDO apt-key add -
    pgrep virtualbox && return 1
    pgrep VBox && return 1 
    return 0
}

prepare_vmcloak(){
#	Set IP of Hostonly Gateway if needed -> uncoment "#" ...
	$SUDO vboxmanage hostonlyif ipconfig vboxnet0 --ip 192.168.56.1
    $SUDO mkdir -p /mnt/win7x64srg
    $SUDO mount -o loop,ro /tmp/win7x64srg.iso /mnt/win7x64srg
    $SUDO mkdir -p /mnt/winXPsrg
    $SUDO mount -o loop,ro /tmp/winXPsrg.iso /mnt/winXPsrg
    $SUDO mkdir -p /mnt/win10x64srg
    $SUDO mount -o loop,ro /tmp/win10x64srg.iso /mnt/win10x64srg
    return 0
}

build_virtualbox_remoteaccess(){
	## Script not enabled until TODO tasks shown below finished
	# Read first to understand the tasks: https://github.com/buguroo/cuckooautoinstall/blob/master/doc/Remote.rst
    cd ${TMPDIR}
	wget $VIRTUALBOX_XTPACK_URL
	$SUDO VBoxManage extpack install $VIRTUALBOX_XTPACK
	VBOXWEB_USER=cuckoo
	$SUDO apt-get install nginx php5-common php5-mysql php5-fpm php-pear
	$SUDO cd /usr/share/nginx/www
	wget -L -c $VIRTUALBOX_PHP -O phpvirtualbox.zip
	$SUDO unzip phpvirtualbox.zip
	cd phpvirtualbox-5.0-5
	$SUDO cp config.php-example config.php
    ##  TODO: Create Script to Edit config.php and add the cuckoo user to the following:
    #	var $username = 'cuckoo';
	#	var $password = '4fRe3s$Zb8';
	$SUDO /etc/init.d/nginx start
	## for older phpVirtualbox versions do:
	# su cuckoo
	# vboxwebsrv -H 127.0.0.1 --background
	## for newer phpVirtualbox versions do (actually enabled):
	$SUDO VBoxManage setproperty websrvauthlibrary default
    $SUDO /etc/init.d/vboxweb-service restart
    return 0
}

prepare_tcpdump(){
	$SUDO apt-get install libcap2-bin
	$SUDO chmod +s /usr/sbin/tcpdump
    return 0
}

install_packages(){
    $SUDO apt-get update
    $SUDO apt-get install -y ${packages["${RELEASE}"]}
    $SUDO apt-get install -y $CUSTOM_PKGS
    $SUDO apt-get -y install 
    return 0
}

install_lynis_auditor(){
    $SUDO apt-get update
    $SUDO apt-key adv --keyserver keyserver.ubuntu.com --recv-keys C80E383C3DE9F082E01391A0366C67DE91CA5D5F
	$SUDO echo "deb https://packages.cisofy.com/community/lynis/deb/ $RELEASE" > /etc/apt/sources.list.d/cisofy-lynis.list
	$SUDO apt install apt-transport-https
	$SUDO apt-get update
	$SUDO apt-get install lynis
    return 0
}

install_python_packages(){
    pip ${python_packages[@]}
    return 0
}

install_cuckoo_requirements(){
    $SUDO cd $CUCKOO_PATH
	$SUDO pip install -r requirements.txt
    cd ${TMPDIR}
    return 0
}

# Init.

print_copy
check_viability
setopts ${@}

# Load config

source config &>/dev/null

echo "Logging enabled on ${LOG}"

# If we're notupgrading to recent yara, jansson and volatility, install them as packages.
[[ $UPGRADE != true ]] && {
    CUSTOM_PKGS="volatility yara python-yara libyara3 libjansson4 ${CUSTOM_PKGS}"
}

# Install packages
run_and_log prepare_virtualbox "Getting virtualbox repo ready" "Virtualbox is running, please close it"
run_and_log install_packages "Installing packages ${CUSTOM_PKGS} and ${packages[$RELEASE]}" "Something failed installing packages, please look at the log file"

# Install python packages
run_and_log pip_install_upgrade "Upgrade pip installation tool" "Failed"
run_and_log install_python_packages "Installing python packages: ${python_packages[@]}" "Something failed install python packages, please look at the log file"

# Create user and clone repos
run_and_log create_cuckoo_user "Creating cuckoo user" "Could not create cuckoo user"
run_and_log clone_repos "Cloning repositories" "Could not clone repos"
run_and_log clone_cuckoo "Cloning cuckoo repository" "Failed"
run_and_log clone_fog "Cloning FOG repository" "Failed"

# Build packages
[[ $UPGRADE == true ]] && {
    run_and_log install_cuckoo_requirements "Installing Cuckoo Sandbox Requirements"
    run_and_log build_jansson "Building and installing jansson"
    run_and_log build_yara "Building and installing yara"
##  run_and_log build_volatility "Installing volatility 2.4"
	run_and_log build_volatility_2_5 "Installing volatility 2.5"
    run_and_log build_ssdeep "Installing ssdeep"
    run_and_log build_pydeep "Installing pydeep"	
    run_and_log build_fog "Installing fog"
	run_and_log build_vmcloak "Installing VMCloak"
}

# Configuration
run_and_log fix_django_version "Fixing django problems on old versions"
run_and_log enable_mongodb "Enabling mongodb in cuckoo"

# Networking (latest, because sometimes it crashes...)
run_and_log create_hostonly_iface "Creating hostonly interface for cuckoo"
run_and_log setcap "Setting capabilities for tcpdump"

#Prepare TCPDUMP
run_and_log prepare_tcpdump "Tcpdump requires root privileges, but since you don’t want Cuckoo to run as root you’ll have to set specific Linux capabilities to the binary" "Could not change the TPCDUMP settings"

# Install Addons and Security tools
run_and_log install_lynis_auditor "Installing last version of Cisofy Lynis Auditor " "Lynis allready installed, please close it"
