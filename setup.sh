#!/bin/bash
set -e
set -x

# Install dependencies
sudo apt-get install -y busybox-static fakeroot git dmsetup kpartx netcat-openbsd nmap python3-psycopg2 snmp uml-utilities util-linux vlan postgresql wget qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils vim unzip

# Create and Move to firmadyne directory, push the current directory into stack
FIRMADYNE_INSTALL_DIR=/firmadyne
mkdir $FIRMADYNE_INSTALL_DIR
pushd $FIRMADYNE_INSTALL_DIR

# Clone repos
git clone https://github.com/ReFirmLabs/binwalk
git clone --recursive https://github.com/firmadyne/firmadyne.git

# Set up binwalk
pushd binwalk
# Automatically give "yes" as response for all the commands
sudo ./deps.sh --yes
sudo python3 ./setup.py install
# Go into previous directory
popd

# Install additional deps for file identification-jefferson extraction
sudo pip3 install git+https://github.com/ahupp/python-magic
sudo pip install git+https://github.com/sviehb/jefferson

# Set up database
sudo service postgresql start
sudo -u postgres createuser firmadyne
sudo -u postgres createdb -O firmadyne firmware
sudo -u postgres psql -d firmware < ./firmadyne/database/schema
# Prints the command to alter the password of user firmadyne to "firmadyne" and then it pipelines the output to postgres line interface to change the password and executes it as postgres super user
echo "ALTER USER firmadyne PASSWORD 'firmadyne'" | sudo -u postgres psql

# Set up firmadyne
pushd firmadyne
./download.sh

# Set FIRMWARE_DIR in firmadyne.config
# Sets up Environment Variable FIRMADYNE as $"pwd", then appends it as first line in firmadyne.config
mv firmadyne.config firmadyne.config.orig
echo -e '#!/bin/sh' "\nFIRMWARE_DIR=$(pwd)/" > firmadyne.config
cat firmadyne.config.orig >> firmadyne.config

# Make sure firmadyne user owns this dir
sudo chown -R firmadyne:firmadyne $FIRMADYNE_INSTALL_DIR
