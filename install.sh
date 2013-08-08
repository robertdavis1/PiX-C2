#!/bin/sh

echo "Creating PingC2 Database"
echo "Enter mysql username (must be able to create databases): "
read username
echo "Enter password: "
read password
echo "Enter user for pingc2: "
read user
echo "Enter password for new user: "
read pass

mysql -u $username -p$password < pingc2-db-create.sql
mysql -u $username -p$password -e "GRANT ALL PRIVILEGES ON pingc2.* TO $user@'localhost' IDENTIFIED BY '$pass'"

echo "[Main]" > 'conf/pingc2.conf'
echo "dbuser=$user" >> 'conf/pingc2.conf'
echo "dbpass=$pass" >> 'conf/pingc2.conf'
