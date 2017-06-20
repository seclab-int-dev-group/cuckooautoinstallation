About CuckooAutoinstallation-free
=================================

`Modified Cuckoo Sandbox <http://www.cuckoosandbox.org/>`_. auto install script

What is Cuckoo Sandbox?
-----------------------

Cuckoo Sandbox is a malware analysis system.

What does that mean? 
--------------------

It means that you can throw any suspicious file at it and get a report with
details about the file's behavior inside an isolated environment.

The Autoinstallation of the Cuckoo-Sandbox was created at `Buguroo Offensive Security <http://www.buguroo.com>`_ initially to make the painful cuckoo installation quicker, easier and painless.


Modified Cuckoo Sandbox
-----------------------
Within this Autoinstallation Script we aim to continue the work of the heavily modified version of [Cuckoo Sandbox](http://www.cuckoosandbox.org) provided under the GPL by Optiv, Inc.

It offers a number of advantages over the upstream Cuckoo:
+ Fully-normalized file and registry names
+ 64-bit analysis
+ Handling of WoW64 filesystem redirection
+ Many additional API hooks
+ Service monitoring
+ Correlates API calls to malware call chains
+ Ability to follow APC injection and stealth explorer injection
+ Pretty-printed API flags
+ Per-analysis Tor support
+ Over 150 new signature modules (over 75 developed solely by Optiv)
+ Anti-anti-sandbox and anti-anti-VM techniques built-in
+ More stable hooking
+ Ability to restore removed hooks
+ Greatly improved behavioral analysis and signature module API
+ Ability to post comments about analyses
+ Deep hooks in IE's JavaScript and DOM engines usable for Exploit Kit identification
+ Automatic extraction and submission of interesting files from ZIPs, RARs, RFC 2822 emails (.eml), and Outlook .msg files
+ Direct submission of AV quarantine files (Forefront, McAfee, Trend Micro, Kaspersky, MalwareBytes, MSE/SCEP, and SEP12 formats currently supported)
+ Automatic malware classification by [Malheur](http://mlsec.org/malheur/)
+ Significant contributions from [Jeremy Hedges](https://github.com/killerinstinct/), [William Metcalf](https://github.com/wmetcalf), and Kevin Ross
+ Hundreds of other bugfixes

For more information on the initial set of changes, see:
http://www.accuvant.com/blog/improving-reliability-of-sandbox-results

If you want to contribute to development, feel free to submit a pull request.

Supported systems
-----------------

Most of this script is not distro dependant (tough of course you've got to run
it on GNU/Linux), but package installation, at this moment supports only
debian derivatives.

Also, given that we use the propietary virtualbox version (most of the time OSE
edition doesn't fulfill our needs), this script requires that they've got
a debian repo in `Virtualbox Downloads <http://downloads.virtualbox.org>`_ 
for your distro. Forcing the distro in config file should make it work in
unsupported ones.

Authors
-------

`Patrick Vanreck - <https://github.com/patrickvanreck>`_ - `patrick.vanreck@hotmail.com <mailto:patrick.vanreck@hotmail.com>`_ 

`Stefan Mettler - <https://github.com/cryptron>`_ - `https://ch.linkedin.com/in/stefan-mettler-a876a4139`_ 


Quickstart guide
================

* Clone this repo & execute the script: *bash cuckooautoinstall.bash*

.. image:: /../screenshots/cuckooautoinstall.png?raw=true


If you trust us, your network setup and a lot of more variables enough
(which is totally not-recommended) and you're as lazy as it gets, you can
execute as a normal user if you've got sudo configured:

::

    wget -O - https://raw.githubusercontent.com/buguroo/cuckooautoinstall/master/cuckooautoinstall.bash | bash


The script does accept a configuration file in the form of a simple
bash script with options such as:

::

    SUDO="sudo"
    TMPDIR=$(mktemp -d)
    RELEASE=$(lsb_release -cs)
    CUCKOO_USER="cuckoo"
    CUSTOM_PKGS=""
    ORIG_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}"   )" && pwd   )
    VOLATILITY_URL="http://downloads.volatilityfoundation.org/releases/2.4/volatility-2.4.tar.gz"
    VIRTUALBOX_REP="deb http://download.virtualbox.org/virtualbox/debian $RELEASE contrib"
    CUCKOO_REPO='https://github.com/cuckoobox/cuckoo'
    YARA_REPO="https://github.com/plusvic/yara"
    JANSSON_REPO="https://github.com/akheron/jansson"

    LOG=$(mktemp)
    UPGRADE=false

You can override any of these variables in the config file.

It accepts parameters

::

    ┌─────────────────────────────────────────────────────────┐
    │                CuckooAutoInstall 0.2                    │
    │ David Reguera García - Dreg <dreguera@buguroo.com>      │
    │ David Francos Cuartero - XayOn <dfrancos@buguroo.com>   │
    │            Buguroo Offensive Security - 2015            │
    └─────────────────────────────────────────────────────────┘
    Usage: cuckooautoinstall.bash [--verbose|-v] [--help|-h] [--upgrade|-u]

        --verbose   Print output to stdout instead of temp logfile
        --help      This help menu
        --upgrade   Use newer volatility, yara and jansson versions (install from source)

For most setups, --upgrade is recommended always.

* Add a password (as root) for the user *'cuckoo'* created by the script

::

    passwd cuckoo

* Create the virtual machines `http://docs.cuckoosandbox.org/en/latest/installation/guest/`
  or import virtual machines

::

  VBoxManage import virtual_machine.ova

* Add to the virtual machines with HostOnly option using vboxnet0

::

  vboxmanage modifyvm “virtual_machine" --hostonlyadapter1 vboxnet0

* Configure cuckoo (`http://docs.cuckoosandbox.org/en/latest/installation/host/configuration/` )

* Execute cuckoo 

::

  cd ~cuckoo/cuckoo
  python cuckoo.py

.. image:: /../screenshots/github%20cuckoo%20working.png?raw=true


* Execute also django using port 6969

::

  cd ~cuckoo/cuckoo/web
  python manage.py runserver 0.0.0.0:6969

.. image:: /../screenshots/github%20django.png?raw=true

Script features
=================

* Installs by default Cuckoo sandbox with the ALL optional stuff: yara, ssdeep, django ...
* Installs the last versions of ssdeep, yara, pydeep-master & jansson.
* Solves common problems during the installation: ldconfigs, autoreconfs...
* Installs by default virtualbox and *creates the hostonlyif*.
* Creates the *'cuckoo'* user in the system and it is also added this user to *vboxusers* group.
* Enables *mongodb* in *conf/reporting.conf* 
* Creates the *iptables rules* and the ip forward to enable internet in the cuckoo virtual machines

::

    sudo iptables -A FORWARD -o eth0 -i vboxnet0 -s 192.168.56.0/24 -m conntrack --ctstate NEW -j ACCEPT
    sudo iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    sudo iptables -A POSTROUTING -t nat -j MASQUERADE
    sudo sysctl -w net.ipv4.ip_forward=1

Enables run *tcpdump* from nonroot user

::

    sudo apt-get -y install libcap2-bin
    sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump

Fixes the *"TEMPLATE_DIRS setting must be a tuple"* error when running python manage.py from the *DJANGO version >= 1.6*. Replacing in *web/web/settings.py*

::

        TEMPLATE_DIRS = (
            "templates"
        )


becomes

::

        TEMPLATE_DIRS = (
            ("templates"),
        )


Install cuckoo as daemon
==========================

For this, we recommend supervisor usage.

Install supervisor

::

    sudo apt-get install supervisor

Edit */etc/supervisor/conf.d/cuckoo.conf* , like

::

        [program:cuckoo]
        command=python cuckoo.py
        directory=/home/cuckoo
        User=cuckoo

        [program:cuckoo-api]
        command=python api.py
        directory=/home/cuckoo/utils
        user=cuckoo

Reload supervisor

::

  sudo supervisorctl reload


iptables
========

As you probably have already noticed, iptables rules don't stay there after
a reboot. If you want to make them persistent, we recommend 
iptables-save & iptables-restore

::

    iptables-save > your_custom_iptables_rules
    iptables-restore < your_custom_iptables_rules



Extra help
==========

You may want to read:

* `Remote <./doc/Remote.rst>`_ - Enabling remote administration of VMS and VBox
* `OVA <./doc/OVA.rst>`_ - Working with OVA images
* `Antivm <./doc/Antivm.rst>`_ How to deal with malware that has VM detection techniques
* `VMcloak <./doc/Vmcloak.rst>`_ VMCloak - Cuckoo windows virtual machines management

TODO
====

* Improve documentation

Contributing
============

This project is licensed as GPL3+ as you can see in "LICENSE" file.
All pull requests are welcome, having in mind that:

- The scripting style must be compliant with the current one
- New features must be in sepparate branches (way better if it's git-flow =) )
- Please, check that it works correctly before submitting a PR.

We'd probably be answering to PRs in a 7-14 day period, please be patient.
