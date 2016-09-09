cd /usr/share/exploitdb
wget http://www.exploit-db.com/archive.tar.bz2
#tar -xvjf archive.tar.bz2
unzip archive.tar.bz2
cd exploit-database-master
tar cf - . |(cd ..; tar xfBp - )
cd /usr/share/exploitdb
rm -rf exploit-database-master
rm archive.tar.bz2
