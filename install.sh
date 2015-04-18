#!/bin/sh

echo "Creating PiX-C2 Database"
echo "Enter mysql username (must be able to create databases): "
read username
echo "Enter password: "
read password
echo "Enter user for pixc2: "
read user
echo "Enter password for new user: "
read pass

mysql -u $username -p$password < pixc2-db-create.sql
mysql -u $username -p$password -e "GRANT ALL PRIVILEGES ON pixc2.* TO $user@'localhost' IDENTIFIED BY '$pass'"

echo "[Main]" > 'conf/pixc2.conf'
echo "dbuser=$user" >> 'conf/pixc2.conf'
echo "dbpass=$pass" >> 'conf/pixc2.conf'
