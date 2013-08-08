#!/bin/sh

echo "Creating PingC2 Database"
echo "Enter mysql username: "
read username
echo "Enter password: "
read password

mysql -u $username -p$password < pingc2-db-create.sql
