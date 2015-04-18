create database pixc2;
use pixc2;
create table bots (id int primary key not null  auto_increment, remoteip varchar(16), name varchar(100), os varchar(25), localip varchar(16), checkin date);

