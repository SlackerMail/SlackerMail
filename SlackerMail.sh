#!/bin/sh
# SlackerMail Beta v.025 install script by: Wayne O. Jackson - wjack@the-slacker.com
 
# Check to make sure the internet is reachable.

wget -q --tries=10 --timeout=20 --spider http://google.com
if [[ $? -ne 0 ]]; then
    echo "Can't reach the internet. Check your internet connection. Exiting!"
    exit
fi

# Check to make sure script is ran as root.

if (( $EUID != 0 )); then
    echo "Must be root to run this script."
    exit
fi

# Make sure ncurses uses utf-8 properly.

export NCURSES_NO_UTF8_ACS=1

# Check that system is supported.

if ( grep -i -q "Slackware 15.0 x86_64" /etc/os-release ); then
NETDATA=0
FAIL2BAN=0
LOGWATCH=0
WEBMIN=0
SMMLM=0
else
  echo "Slackware-15.0.x86_64 not detected! Sorry, your system is not supported."
exit
fi

# Check to make sure Apache is installed.

if [ -f "/etc/rc.d/rc.httpd" ]; then
chmod 0755 /etc/rc.d/rc.httpd
/etc/rc.d/rc.httpd restart > /dev/null 2>&1
else 
echo "Apache not installed! Please install Apache and retry."
exit 
fi

# SlackerMail install message

dialog --title "SlackerMail install script" --backtitle "SlackerMail install script" --yesno \
"This script will install SlackerMail, a full featured mail server for Slackware OS. SlackerMail is very similar to iRedMail, of which it was inspired. \
SlackerMail is beta, so use at own risk. Do you want to continue?" 10 80
dialog_status=$?

if [ $dialog_status -ne 0 ]; then
echo "SlackerMail install aborted!"
exit
fi
clear
sleep 0.5s
# Make sure the script is ran from the SlackerMail root directory.

SMPWD=$(pwd)
if [[ $SMPWD != *"SlackerMail-"* ]]; then
echo "Script must be ran from the SlackerMail root directory."
exit
fi

# Check for FQDN

FQDN=$(hostname -f)
HOST=$(hostname -s)
DOMAIN=$(hostname -d)

dots="${FQDN//[^.]}"
if [ $dots == ".." ]; then
dialog --title "Your present FQDN" --backtitle "SlackerMail \
install script" --inputbox "Keep present FQDN or change?" 8 60 $FQDN 2>/etc/HOSTNAME
else
dialog --title "You do NOT have a fully qualified domain name set" --backtitle "SlackerMail \
install script" --inputbox "Please enter your FQDN, eg. mail.example.org" 8 60 2>/etc/HOSTNAME
fi
clear
sleep 0.5s

# Setup /etc/hosts file

echo -e "127.0.0.1 localhost.localdomain localhost\n127.0.0.1 $FQDN $HOST" > /etc/hosts

curl -I http://$DOMAIN > /dev/null 2>&1
if [ $? -ne 0 ]; then
   echo "http://$DOMAIN is not reachable! Can not proceed! Maybe a problem with the httpd config files or DNS Zone is not setup properly."
   exit
fi

# Choose optional items to be installed

choices="$(dialog --stdout --checklist "Select optional items to be installed:" 0 44 5 >choice.tmp \
1 Webmin off \
2 Logwatch off \
3 Fail2ban off \
4 smmlm-mailing-list-manager off \
5 Netdata off)"

if [[ $(tail -1 choice.tmp) == *1* ]]; then 
WEBMIN=1
fi

if [[ $(tail -1 choice.tmp) == *2* ]]; then 
LOGWATCH=1
fi

if [[ $(tail -1 choice.tmp) == *3* ]]; then 
FAIL2BAN=1
fi

if [[ $(tail -1 choice.tmp) == *4* ]]; then 
SMMLM=1
fi

if [[ $(tail -1 choice.tmp) == *5* ]]; then 
NETDATA=1
fi
rm choice.tmp
clear
sleep 0.5s

# Choose the number of characters for the 8 randomly generated passwords.

passgen="$(dialog --stdout --backtitle "Random password generation" \
--radiolist "Select number of randomly generated characters in passwords:" 10 66 3 \
 1 "12" off \
 2 "24" on \
 3 "36" off)"
 
 if [ $passgen = 1 ]; then
 passgen=12
 fi
 
 if [ $passgen = 2 ]; then
 passgen=24
 fi
 
 if [ $passgen = 3 ]; then
 passgen=36
 fi
clear
sleep 0.5s

# Random password generator function.

random_pass() { 
pass=$(cat /dev/urandom | tr -cd '[:alnum:]' | fold -w $passgen | grep -Pm1 '(?=.*[[:upper:]].*[[:upper:]].*[[:upper:]])(?=.*[[:digit:]].*[[:digit:]].*[[:digit:]])(?=.*[[:lower:]].*[[:lower:]].*[[:lower:]])') 
echo $pass
}

# Setup Webmin

if [ $WEBMIN = 1 ]; then 
mkdir -p /root/tmp
cd /root/tmp/
wget https://github.com/webmin/webmin/releases/download/2.102/webmin-2.102.tar.gz
tar -xf webmin-2.102.tar.gz
rm /root/tmp/webmin-2.102.tar.gz
cd webmin-2.102
./setup.sh /usr/local/webmin
cd /root/tmp
rm -R /root/tmp/webmin-2.102
echo -e '#!/bin/bash
/etc/webmin/stop > /dev/null 2>&1
rm /var/webmin/miniserv.pid' >> /etc/rc.d/rc.local_shutdown
fi

# Setup Apache

mkdir -p /root/tmp
cd /root/tmp
installpkg $SMPWD/pkgs/php-imagick-3.5.1-x86_64-2_SBo.tgz
sed -i '1iextension=imagick.so' /etc/php.d/imagick.ini
cp -f $SMPWD/conf/httpd.conf /etc/httpd/
cp -f $SMPWD/conf/httpd-ssl.conf /etc/httpd/extra/
sed -i "/ServerAdmin admin@example.org/c\ServerAdmin admin@$DOMAIN" /etc/httpd/httpd.conf
sed -i "/ServerName example.org:80/c\ServerName $DOMAIN:80" /etc/httpd/httpd.conf
cp -f $SMPWD/conf/www.conf /etc/php-fpm.d/
chmod 0755 /etc/rc.d/rc.php-fpm
echo -e '/etc/rc.d/rc.php-fpm start > /dev/null 2>&1' >> /etc/rc.d/rc.local
echo -e '/etc/rc.d/rc.php-fpm stop > /dev/null 2>&1' >> /etc/rc.d/rc.local_shutdown
chmod 0755 /etc/rc.d/rc.local_shutdown

# Create self signed ssl certs

cd /root/tmp
mkdir -p /etc/ssl/$DOMAIN
openssl req -newkey rsa:4096 -x509 -sha256 -days 3650 -nodes -out $DOMAIN.crt -keyout $DOMAIN.key -subj "/C=US/ST=Georgia/L=Atlanta/O=SlackerMail/OU=SlackerMail/CN=$DOMAIN"
mv -f $DOMAIN.crt /etc/ssl/$DOMAIN/
mv -f $DOMAIN.key /etc/ssl/$DOMAIN/
sed -i '526iInclude /etc/httpd/extra/httpd-ssl.conf' /etc/httpd/httpd.conf
sed -i "/ServerName example.org/c\ServerName $DOMAIN" /etc/httpd/extra/httpd-ssl.conf
sed -i "/ServerAdmin admin@example.org/c\ServerAdmin admin@$DOMAIN" /etc/httpd/extra/httpd-ssl.conf
sed -i "147iSSLCertificateFile \"/etc/ssl/$DOMAIN/$DOMAIN.crt\"" /etc/httpd/extra/httpd-ssl.conf
sed -i "159iSSLCertificateKeyFile \"/etc/ssl/$DOMAIN/$DOMAIN.key\"" /etc/httpd/extra/httpd-ssl.conf
sleep 1
/etc/rc.d/rc.httpd restart > /dev/null 2>&1
mkdir -p /root/SlackerMail
echo "SlackerMail Configuration File
------------------------------

Self signed SSL Certs:
/etc/ssl/$DOMAIN/$DOMAIN.crt
/etc/ssl/$DOMAIN/$DOMAIN.key" > /root/SlackerMail/SlackerMail.setup

# Setup the firewall with iptables

cp -f $SMPWD/conf/rc.firewall /etc/rc.d/
chmod 0755 /etc/rc.d/rc.firewall
# Figure out which network interface is being used.
NETIFACE=$(ip route get 1.1.1.1 | grep -oP 'dev\s+\K[^ ]+') # Thanks to P.... for this.
sed -i "/INET_IFACE=/c\INET_IFACE=\"$NETIFACE\"" /etc/rc.d/rc.firewall

# Setup MySQL (maridb)

mysql_install_db --user=mysql
chmod 755 /etc/rc.d/rc.mysqld
sed -i '/SKIP="--skip-networking"/c\#SKIP="--skip-networking"' /etc/rc.d/rc.mysqld
/etc/rc.d/rc.mysqld restart > /dev/null 2>&1
sleep 1

random_pass > /root/SlackerMail/mysql-root.pass
sleep 1
MYSQLPASS=$(cat /root/SlackerMail/mysql-root.pass)
mysqladmin -u root password $MYSQLPASS
mysqladmin -u root -h localhost password $MYSQLPASS
chmod 0600 /root/SlackerMail/mysql-root.pass
mysql -u root -Bse "drop database test;use mysql;SELECT user, host FROM user;DELETE FROM user WHERE user='';flush privileges"
cp -f $SMPWD/conf/server.cnf /etc/my.cnf.d/
echo -e "[client]\ndefault-character-set = utf8mb4\n\n[client-mariadb]" > /etc/my.cnf.d/client.cnf
mkdir -p /var/log/mysql
chown mysql:mysql /var/log/mysql
/etc/rc.d/rc.mysqld restart > /dev/null 2>&1
sleep 1

random_pass > /root/SlackerMail/vmail.pass
sleep 1
VMAILPASS=$(cat /root/SlackerMail/vmail.pass)
mysql -u root -Bse "CREATE DATABASE vmail;GRANT ALL PRIVILEGES ON vmail.* TO 'vmail'@'localhost' IDENTIFIED BY '${VMAILPASS}';flush privileges"
if [ $? -ne 0 ]; then
   echo "Not able to create vmail database."
   exit
fi
chmod 0600 /root/SlackerMail/vmail.pass

echo "
Mysql root password: $MYSQLPASS

Mysql vmail database password: $VMAILPASS" >> /root/SlackerMail/SlackerMail.setup

# Setup Dovecot

cd /root/tmp
openssl dhparam -out dh2048_param.pem 2048
mv -f dh2048_param.pem /etc/ssl/

echo -e "ssl_min_protocol = TLSv1.2
ssl = required
verbose_ssl = no
ssl_cert = </etc/ssl/$DOMAIN/$DOMAIN.crt
ssl_key = </etc/ssl/$DOMAIN/$DOMAIN.key
ssl_dh = </etc/ssl/dh2048_param.pem
# Fix 'The Logjam Attack'
ssl_cipher_list = EECDH+CHACHA20:EECDH+AESGCM:EDH+AESGCM:AES256+EECDH
ssl_prefer_server_ciphers = yes" > /etc/dovecot/conf.d/10-ssl.conf

groupadd -g 150 vmail
useradd -r -d /var/vmail -s /bin/false -u 150 -g 150 vmail
mkdir /var/vmail
chmod 770 /var/vmail
chown vmail:vmail /var/vmail

echo -e "driver = mysql 
connect = host=127.0.0.1 port=3306 dbname=vmail user=vmail password=$VMAILPASS 
default_pass_scheme = SHA512-CRYPT

password_query = \\
  SELECT username as user, password, '/var/vmail/%d/%n' as \\
  userdb_home, 'maildir:/var/vmail/%d/%n' as userdb_mail, \\
  150 as userdb_uid, 150 as userdb_gid \\
  FROM mailbox WHERE username = '%u' AND active = '1'

user_query = \\
  SELECT '/var/vmail/%d/%n' as home, 'maildir:/var/vmail/%d/%n' \\
  as vmail, 150 AS uid, 150 AS gid, \\
  concat('dirsize:storage=', quota) AS quota \\
  FROM mailbox WHERE username = '%u' AND active = '1'" > /etc/dovecot/dovecot-sql.conf.ext
  
chmod 0600 /etc/dovecot/dovecot-sql.conf.ext

echo -e 'disable_plaintext_auth = yes 
auth_mechanisms = plain login 
!include auth-sql.conf.ext' > /etc/dovecot/conf.d/10-auth.conf

echo -e 'mail_location   = maildir:/var/vmail/%d/%n
mail_uid        = vmail
mail_gid        = vmail
first_valid_uid = 150
last_valid_uid  = 150' >> /etc/dovecot/conf.d/10-mail.conf

cp -f $SMPWD/conf/10-master.conf /etc/dovecot/conf.d/10-master.conf

echo -e '## Log destination.
##
log_path       = /var/log/dovecot/dovecot.log
info_log_path  = /var/log/dovecot/dovecot-info.log' >> /etc/dovecot/conf.d/10-logging.conf

installpkg $SMPWD/pkgs/dovecot-pigeonhole-0.5.17-x86_64-1_SBo.tgz
cp /usr/doc/dovecot-2.3.17.1/example-config/conf.d/90-sieve.conf /etc/dovecot/conf.d/
cp /usr/doc/dovecot-2.3.17.1/example-config/conf.d/90-sieve-extprograms.conf /etc/dovecot/conf.d/
cp /usr/doc/dovecot-2.3.17.1/example-config/conf.d/20-managesieve.conf /etc/dovecot/conf.d/

echo -e "protocol lmtp {
  postmaster_address = postmaster@$DOMAIN
  mail_plugins       = \$mail_plugins sieve quota
  log_path           = /var/log/dovecot/dovecot-lmtp-errors.log
  info_log_path      = /var/log/dovecot/dovecot-lmtp.log
}" > /etc/dovecot/conf.d/20-lmtp.conf

echo -e "protocol lda {
  postmaster_address = postmaster@$DOMAIN
  mail_plugins       = \$mail_plugins sieve quota
  auth_socket_path   = /var/run/dovecot/auth-master
  log_path           = /var/log/dovecot/dovecot-lda-errors.log
  info_log_path      = /var/log/dovecot/dovecot-lda.log
}" > /etc/dovecot/conf.d/15-lda.conf

echo -e 'mail_home       = /var/vmail/%d/%n/sieve' >> /etc/dovecot/conf.d/10-mail.conf

echo -e 'protocols = $protocols sieve

service managesieve-login {
  inet_listener sieve {
    port = 4190
  }
}

service managesieve {
  process_limit = 1024
}

protocol sieve {
  log_path                          = /var/log/dovecot/dovecot-sieve-errors.log
  info_log_path                     = /var/log/dovecot/dovecot-sieve.log
  managesieve_max_line_length       = 65536
  managesieve_implementation_string = Dovecot Pigeonhole
}' > /etc/dovecot/conf.d/20-managesieve.conf

echo -e 'plugin {
    sieve = file:/var/vmail/%d/%n/sieve;active=/var/vmail/%d/%n/sieve/.dovecot.sieve
    sieve_default = /etc/dovecot/sieve/default.sieve
    sieve_global = /etc/dovecot/sieve/global/
}
lda_mailbox_autocreate = yes
lda_mailbox_autosubscribe = yes' > /etc/dovecot/conf.d/90-sieve.conf

mkdir -p /etc/dovecot/sieve/global
chown -R vmail:vmail /etc/dovecot/sieve/
mkdir /var/log/dovecot
chown vmail:vmail /var/log/dovecot
chmod 771 /var/log/dovecot

touch /etc/dovecot/sieve/default.sieve
chown vmail:vmail /etc/dovecot/sieve/default.sieve

echo -e 'require "fileinto";
if header :contains "X-Spam-Flag" "YES" {
    fileinto "Junk";
}' > /etc/dovecot/sieve/default.sieve

usermod -G dovecot -a postfix
chmod 0755 /etc/rc.d/rc.dovecot
echo -e "/etc/rc.d/rc.dovecot restart > /dev/null 2>&1" >> /etc/rc.d/rc.local

# Setup Postfix

mkdir -p /etc/postfix/mysql

echo -e "user     = vmail 
password = $VMAILPASS 
hosts    = 127.0.0.1:3306 
dbname   = vmail 
query    = SELECT goto FROM alias,alias_domain 
  WHERE alias_domain.alias_domain = '%d' 
  AND alias.address=concat('%u', '@', alias_domain.target_domain) 
  AND alias.active = 1" > /etc/postfix/mysql/mysql_virtual_alias_domainaliases_maps.cf

echo -e "user         = vmail
password     = $VMAILPASS
hosts        = 127.0.0.1:3306
dbname       = vmail
table        = alias
select_field = goto 
where_field  = address
additional_conditions = and active = '1'" > /etc/postfix/mysql/mysql_virtual_alias_maps.cf

echo -e "user         = vmail
password     = $VMAILPASS
hosts        = 127.0.0.1:3306
dbname       = vmail
table        = domain
select_field = domain
where_field  = domain
additional_conditions = and backupmx = '0' and active = '1'" > /etc/postfix/mysql/mysql_virtual_domains_maps.cf

echo -e "user     = vmail
password = $VMAILPASS
hosts    = 127.0.0.1:3306
dbname   = vmail
query    = SELECT maildir FROM mailbox, alias_domain 
  WHERE alias_domain.alias_domain = '%d'   
  AND mailbox.username=concat('%u', '@', alias_domain.target_domain )
  AND mailbox.active = 1" > /etc/postfix/mysql/mysql_virtual_mailbox_domainaliases_maps.cf

echo -e "user     = vmail
password = $VMAILPASS
hosts    = 127.0.0.1:3306
dbname   = vmail
table    = mailbox
select_field = CONCAT(domain, '/', local_part)
where_field  = username\nadditional_conditions = and active = '1'" > /etc/postfix/mysql/mysql_virtual_mailbox_maps.cf

chmod 0600 /etc/postfix/mysql/*

cp -f $SMPWD/conf/main.cf /etc/postfix/

sed -i "/myhostname = mail.example.org/c\myhostname = $FQDN" /etc/postfix/main.cf
sed -i "/mydomain = example.org/c\mydomain = $DOMAIN" /etc/postfix/main.cf
sed -i "/smtpd_tls_key_file=/c\smtpd_tls_key_file= /etc/ssl/$DOMAIN/$DOMAIN.key" /etc/postfix/main.cf
sed -i "/smtpd_tls_cert_file=/c\smtpd_tls_cert_file= /etc/ssl/$DOMAIN/$DOMAIN.crt" /etc/postfix/main.cf
sed -i "/smtpd_tls_CAfile =/c\smtpd_tls_CAfile = /etc/ssl/$DOMAIN/$DOMAIN.crt" /etc/postfix/main.cf

cp -f $SMPWD/conf/master.cf /etc/postfix/

chmod 0755 /etc/rc.d/rc.postfix
echo -e "/etc/rc.d/rc.postfix restart > /dev/null 2>&1" >> /etc/rc.d/rc.local

# Setup Amavis/ClamAV/SpamAssassin

# Install SpamAssassin

installpkg $SMPWD/pkgs/spamassassin-3.4.6-x86_64-1_SBo.tgz

# SpamAssassin Update

chmod 0644 /etc/rc.d/rc.spamd
sa-update

# Install Rust16

installpkg $SMPWD/pkgs/rust16-1.70.0-x86_64-1_SBo.tgz

# Install ClamAV

groupadd -g 210 clamav
useradd -u 210 -d /dev/null -s /bin/false -g clamav clamav
installpkg $SMPWD/pkgs/clamav-1.2.0-x86_64-1_SBo.tgz
sed -i "/LocalSocketGroup clamav/c\LocalSocketGroup amavis" /etc/clamd.conf

# Install Amavis

groupadd -g 225 amavis
useradd -m -d /var/lib/amavis -s /bin/bash -u 225 -g 225 amavis
usermod -G clamav -a amavis
usermod -G amavis -a clamav
installpkg $SMPWD/pkgs/amavisd-new-2.11.1-noarch-2_SBo.tgz

# Install Altermime

installpkg $SMPWD/pkgs/altermime-0.3.10-x86_64-1_SBo.tgz

# Setup Amavis

cp -f $SMPWD/conf/amavisd.conf /etc/
sed -i "/$myhostname = 'mail.example.org'; # Put your FQDN here/c\$myhostname = \'"$FQDN"\'; # Put your FQDN here" /etc/amavisd.conf
sed -i "/$mydomain = 'example.org';   # Put your domain name here/c\$mydomain = \'"$DOMAIN"\';   # Put your domain name here" /etc/amavisd.conf
sed -i "/'.' => {d => 'example.org',/c\    '.' => {d => \'"$DOMAIN"\'," /etc/amavisd.conf
sed -i "/@lookup_sql_dsn = /c\@lookup_sql_dsn = (['DBI:mysql:database=vmail;host=127.0.0.1;port=3306', 'vmail', \'"$VMAILPASS"\']);" /etc/amavisd.conf
mkdir /var/spool/amavisd /var/spool/amavisd/tmp /var/spool/amavisd/db /var/spool/amavisd/var /var/spool/amavisd/quarantine
chown -R amavis:amavis /var/spool/amavisd
chown root:amavis /etc/amavisd.conf
chmod 0640 /etc/amavisd.conf
chmod 775 /var/lib/spamassassin/
chown -R amavis:amavis /var/lib/spamassassin
chown -R amavis:amavis /var/lib/amavis
chown -R clamav:amavis /var/lib/clamav
freshclam
sed -i '11i/etc/rc.d/rc.clamav start > /dev/null 2>&1' /etc/rc.d/rc.local
sed -i '12i/etc/rc.d/rc.amavisd-new start > /dev/null 2>&1' /etc/rc.d/rc.local
echo -e "/etc/rc.d/rc.clamav stop > /dev/null 2>&1" >> /etc/rc.d/rc.local_shutdown
echo -e "/etc/rc.d/rc.amavisd-new stop > /dev/null 2>&1" >> /etc/rc.d/rc.local_shutdown

# Setup DKIM 

openssl genrsa -out $DOMAIN.priv 2048
openssl rsa -in $DOMAIN.priv -pubout > $DOMAIN.pub
mv $DOMAIN.priv /etc/ssl/$DOMAIN/$DOMAIN.pem
mv $DOMAIN.pub /etc/ssl/$DOMAIN/$DOMAIN.pub
chown amavis:amavis /etc/ssl/$DOMAIN/$DOMAIN.pem /etc/ssl/$DOMAIN/$DOMAIN.pub
chmod 600 /etc/ssl/$DOMAIN/$DOMAIN.pem 
chmod 644 /etc/ssl/$DOMAIN/$DOMAIN.pub
sed -i "/#dkim_key(/c\dkim_key(\'"$DOMAIN"\', 'dkim', \'"/etc/ssl/$DOMAIN/$DOMAIN.pem"\');" /etc/amavisd.conf
cat /etc/ssl/$DOMAIN/$DOMAIN.pub > /root/SlackerMail/dkim.pubkey
chmod 0600 /root/SlackerMail/dkim.pubkey
sed '1d;$d' "/etc/ssl/$DOMAIN/$DOMAIN.pub" | sed '1s/.*/v=DKIM1;p=&/' | tr -d '\n' > /root/SlackerMail/$DOMAIN.pub.txt
chmod 0600 /root/SlackerMail/$DOMAIN.pub.txt
echo "
DKIM Keys for $DOMAIN:
/etc/ssl/$DOMAIN/$DOMAIN.pem
/etc/ssl/$DOMAIN/$DOMAIN.pub

DKIM key formated to be entered in the DNS Zone at your VPS provider:
/root/SlackerMail/$DOMAIN.pub.txt" >> /root/SlackerMail/SlackerMail.setup

# Install and setup Postgrey

groupadd -g 301 postgrey
useradd -u 301 -d /var/lib/postgrey -s /bin/false -g postgrey postgrey
installpkg $SMPWD/pkgs/postgrey-1.37-x86_64-1_SBo.tgz
wget https://postgrey.schweikert.ch/pub/postgrey_whitelist_clients
mv -f postgrey_whitelist_clients /etc/postfix/

echo -e "PORT=10023
PIDFILE=/var/run/postgrey/postgrey.pid
USER=postgrey
GROUP=postgrey
HOST=$FQDN" > /etc/postgrey.conf

chmod 755 /etc/rc.d/rc.postgrey
sed -i '14i/etc/rc.d/rc.postgrey start > /dev/null 2>&1' /etc/rc.d/rc.local
echo -e "/etc/rc.d/rc.postgrey stop > /dev/null 2>&1" >> /etc/rc.d/rc.local_shutdown

# Install and setup Logwatch

if [ $LOGWATCH = 1 ]; then

installpkg $SMPWD/pkgs/python2-PyYAML-3.13-x86_64-1_SBo.tgz
installpkg $SMPWD/pkgs/logwatch-7.9-noarch-1_SBo.tgz
rm /etc/cron.daily/0logwatch
touch /etc/cron.daily/0logwatch
chmod 0755 /etc/cron.daily/0logwatch

echo '#!/bin/sh
#Set logwatch location
LOGWATCH_SCRIPT="/usr/sbin/logwatch"
#Add options to this line. Most options should be defined in /etc/logwatch/conf/logwatch.conf,
#but some are only for the nightly cronrun such as --output mail and should be set here.
#Other options to consider might be "--format html" or "--encode base64", man logwatch for more details.
OPTIONS="--output mail"
#Call logwatch
$LOGWATCH_SCRIPT $OPTIONS
exit 0' > /etc/cron.daily/0logwatch

echo '$postfix_Enable_Long_Queue_Ids = Yes' > /etc/logwatch/conf/services/postfix.conf

fi

# Setup Postfix Admin

cd /var/www
wget https://github.com/postfixadmin/postfixadmin/archive/refs/tags/postfixadmin-3.3.13.tar.gz
tar -xf postfixadmin-3.3.13.tar.gz
ln -s postfixadmin-postfixadmin-3.3.13 postfixadmin
rm postfixadmin-3.3.13.tar.gz
cd postfixadmin
mkdir templates_c
chown apache:root templates_c
cp /var/www/postfixadmin/config.inc.php /var/www/postfixadmin/config.local.php

random_pass > /root/SlackerMail/postfixadmin_setup.pass
sleep 1
PASETUPPASS=$(cat /root/SlackerMail/postfixadmin_setup.pass)
doveadm pw -p $PASETUPPASS > /root/SlackerMail/postfixadmin_setup_hashed.pass
CHANGEME=$(cat /root/SlackerMail/postfixadmin_setup_hashed.pass | cut -c 8-)
chmod 0600 /root/SlackerMail/postfixadmin_setup.pass /root/SlackerMail/postfixadmin_setup_hashed.pass

sed -i "/$CONF\['configured'\] = false;/c\$CONF\['configured'\] = true;" /var/www/postfixadmin/config.local.php
sed -i "/$CONF\['setup_password'\] = 'changeme';/c\$CONF\['setup_password'\] = '$CHANGEME';" /var/www/postfixadmin/config.local.php
sed -i "/$CONF\['database_user'\] = 'postfix';/c\$CONF\['database_user'\] = 'vmail';" /var/www/postfixadmin/config.local.php
sed -i "/$CONF\['database_password'\] = 'postfixadmin';/c\$CONF\['database_password'\] = '$VMAILPASS';" /var/www/postfixadmin/config.local.php
sed -i "/$CONF\['database_name'\] = 'postfix';/c\$CONF\['database_name'\] = 'vmail';" /var/www/postfixadmin/config.local.php
sed -i "/$CONF\['database_socket'\] = '';/c\$CONF\['database_port'\] = '3306';" /var/www/postfixadmin/config.local.php
sed -i "/$CONF\['admin_email'\] = '';/c\$CONF\['admin_email'\] = 'admin@$DOMAIN';" /var/www/postfixadmin/config.local.php
sed -i "/    'abuse' => 'abuse@change-this-to-your.domain.tld',/c\    'abuse' => 'admin@$DOMAIN'," /var/www/postfixadmin/config.local.php
sed -i "/    'hostmaster' => 'hostmaster@change-this-to-your.domain.tld',/c\    'hostmaster' => 'admin@$DOMAIN'," /var/www/postfixadmin/config.local.php
sed -i "/    'postmaster' => 'postmaster@change-this-to-your.domain.tld',/c\    'postmaster' => 'admin@$DOMAIN'," /var/www/postfixadmin/config.local.php
sed -i "/    'webmaster' => 'webmaster@change-this-to-your.domain.tld'/c\    'webmaster' => 'admin@$DOMAIN'," /var/www/postfixadmin/config.local.php
sed -i "266i\    \'virusalert\' => \'admin@$DOMAIN\'," /var/www/postfixadmin/config.local.php
sed -i "267i\    \'root\' => \'admin@$DOMAIN\'" /var/www/postfixadmin/config.local.php
sed -i "/$CONF\['domain_path'\] = 'YES';/c\$CONF\['domain_path'\] = 'NO';" /var/www/postfixadmin/config.local.php
sed -i "/$CONF\['domain_in_mailbox'\] = 'NO';/c\$CONF\['domain_in_mailbox'\] = 'YES';" /var/www/postfixadmin/config.local.php
sed -i "/$CONF\['footer_text'\] = 'Return to change-this-to-your.domain.tld';/c\$CONF\['footer_text'\] = 'Return to $DOMAIN';" /var/www/postfixadmin/config.local.php
sed -i "/$CONF\['footer_link'\] = 'http:\/\/change-this-to-your.domain.tld';/c\$CONF\['footer_link'\] = 'https:\/\/$DOMAIN';" /var/www/postfixadmin/config.local.php
sed -i "/$CONF\['emailcheck_resolve_domain'\]='YES';/c\$CONF\['emailcheck_resolve_domain'\]='NO';" /var/www/postfixadmin/config.local.php
sed -i "/$CONF\['password_expiration'\] = 'YES';/c\$CONF\['password_expiration'\] = 'NO';" /var/www/postfixadmin/config.local.php
sed -i "/$CONF\['version'\] = '3.3.11';/c\$CONF\['version'\] = '3.3.13';" /var/www/postfixadmin/config.local.php

echo "
Postfix Admin setup password: $PASETUPPASS
Postfix Admin Setup Web Address: https://$DOMAIN/postfixadmin/setup.php" >> /root/SlackerMail/SlackerMail.setup
sleep 1
random_pass > /root/SlackerMail/postfixadmin_admin.pass
sleep 1
PAADMINPASS=$(cat /root/SlackerMail/postfixadmin_admin.pass)
sleep 1
random_pass > /root/SlackerMail/roundcube_admin.pass
sleep 1
RCADMINPASS=$(cat /root/SlackerMail/roundcube_admin.pass)
sleep 1
php /var/www/postfixadmin/public/upgrade.php
sleep 1
/var/www/postfixadmin/scripts/postfixadmin-cli domain add $DOMAIN --aliases 100 --mailboxes 100 --active 1 --description $DOMAIN
sleep 1
/var/www/postfixadmin/scripts/postfixadmin-cli admin add admin@$DOMAIN --superadmin 1 --active 1 --password $PAADMINPASS --password2 $PAADMINPASS
sleep 1
/var/www/postfixadmin/scripts/postfixadmin-cli mailbox add admin@$DOMAIN --name admin --quota 100 --active 1 --password $RCADMINPASS --password2 $RCADMINPASS
sleep 1
echo "
Postfix Admin Password: $PAADMINPASS
Postfix Admin Web Address: https://$DOMAIN/postfixadmin" >> /root/SlackerMail/SlackerMail.setup

# Setup Roundcube

random_pass > /root/SlackerMail/roundcube.pass
sleep 1
RCPASS=$(cat /root/SlackerMail/roundcube.pass)
chmod 0600 /root/SlackerMail/roundcube.pass
mysql -u root -Bse "CREATE DATABASE roundcubemail CHARACTER SET utf8 COLLATE utf8_general_ci;CREATE USER 'roundcube'@'localhost' IDENTIFIED BY '${RCPASS}';GRANT ALL PRIVILEGES ON roundcubemail.* TO 'roundcube'@'localhost';FLUSH PRIVILEGES"
if [ $? -ne 0 ]; then
   echo "Not able to create roundcubemail database."
   exit
fi
cd /var/www
wget https://github.com/roundcube/roundcubemail/releases/download/1.6.2/roundcubemail-1.6.2-complete.tar.gz
tar -xf roundcubemail-1.6.2-complete.tar.gz
ln -s roundcubemail-1.6.2 roundcubemail
rm roundcubemail-1.6.2-complete.tar.gz
chown root:root /var/www/roundcubemail
chown -R apache:root /var/www/roundcubemail-1.6.2
cd roundcubemail
mysql -u roundcube roundcubemail -p$RCPASS < SQL/mysql.initial.sql
echo '#submission header checks file' > /etc/postfix/submission_header_checks
cp -f $SMPWD/conf/config.inc.php.txt /var/www/roundcubemail/config/config.inc.php
chown apache:apache /var/www/roundcubemail/config/config.inc.php
chmod 0600 /var/www/roundcubemail/config/config.inc.php
sed -i "/$config\['db_dsnw'\] = 'mysql:\\/\\/roundcube:password@localhost\\/roundcubemail';/c\$config\['db_dsnw'\] = 'mysql:\\/\\/roundcube:$RCPASS@localhost\\/roundcubemail';" /var/www/roundcubemail/config/config.inc.php
sed -i "/$config\['support_url'\] = 'https:\/\/example.org';/c\$config\['support_url'\] = 'https:\/\/$DOMAIN';" /var/www/roundcubemail/config/config.inc.php
DESKEY=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 24 | head -n 1)
echo $DESKEY > /root/SlackerMail/roundcube.deskey
chmod 0600 /root/SlackerMail/roundcube.deskey
DK24=$(cat /root/SlackerMail/roundcube.deskey)
sed -i "/$config\['des_key'\] = '24-character-Des-Key';/c\$config\['des_key'\] = '$DK24';" /var/www/roundcubemail/config/config.inc.php

echo "
Mysql Roundcubemail Database Password: $RCPASS
Roundcubemail mailbox password for admin@$DOMAIN: $RCADMINPASS
Roundcubemail Web Address: https://$DOMAIN/mail" >> /root/SlackerMail/SlackerMail.setup

# Setup Fail2ban

if [ $FAIL2BAN = 1 ]; then 

echo "SyslogFacility AUTHPRIV" >> /etc/ssh/sshd_config

installpkg $SMPWD/pkgs/fail2ban-0.11.2-x86_64-1_SBo.tgz
chmod 755 /etc/rc.d/rc.fail2ban

echo "[Definition]
# Option: loglevel. Default is ERROR
# Available options: CRITICAL, ERROR, WARNING, NOTICE, INFO, DEBUG
loglevel = INFO
# Set the log target
logtarget = /var/log/fail2ban.log" > /etc/fail2ban/fail2ban.local

SSH_IP=${SSH_CONNECTION%% *}
echo "[DEFAULT]
# time is in seconds. 3600 = 1 hour, 86400 = 24 hours (1 day)
findtime    = 3600
bantime     = 86400
maxretry    = 2
ignoreip    = 127.0.0.1 127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 $SSH_IP" > /etc/fail2ban/jail.local

echo "[sshd]
backend = polling
enabled = true
filter  = sshd
logpath = /var/log/secure
action  = iptables-multiport[name=sshd, port=\"22\", protocol=tcp]" > /etc/fail2ban/jail.d/sshd.local

echo "# Got this from iRedMail
[postfix-pregreet]
backend  = polling
enabled  = true
maxretry = 1
filter   = postfix-pregreet
logpath  = /var/log/maillog
action   = iptables-multiport[name=postfix-pregreet, port=\"80,443,25,587,465,110,995,143,993\", protocol=tcp]" > /etc/fail2ban/jail.d/postfix-pregreet.local

echo "# Got this from iRedMail
[Definition]
# Block clients which cannot pass Postfix postscreen pregreet test.
# FYI: http://www.postfix.org/POSTSCREEN_README.html#pregreet
#
# The SMTP protocol is a classic example of a protocol where the server speaks
# before the client. postscreen(8) detects zombies that are in a hurry and that
# speak before their turn.
failregex = postscreen\[\d+\]: PREGREET .* from \[<HOST>\]:\d+:

# while setting up new account, Thunderbird doesn't wait for server connection
# greeting/banner, this causes Thunderbird cannot pass the Postfix pregreet
# test and caught by \`failregex\` rules listed above (the rule contains
# 'PREGREET' line).
# FYI: https://bugzilla.mozilla.org/show_bug.cgi?id=538809#c41
ignoreregex = postscreen\[\d+\]: PREGREET .* from \[<HOST>\]:\d+: (EHLO|HELO) we-guess.mozilla.org" > /etc/fail2ban/filter.d/postfix-pregreet.conf

echo "# Got this from iRedMail
[postfix]
backend = polling
enabled = true
filter  = postfix-irm
logpath = /var/log/maillog
action  = iptables-multiport[name=postfix-irm, port=\"80,443,25,587,465,110,995,143,993\", protocol=tcp]" > /etc/fail2ban/jail.d/postfix-irm.local

echo "# Got this from iRedMail
[Definition]
# *) '554 5.7.1' is 'Helo command rejected: ACCESS DENIED'
#
#   'ACCESS DENIED' is string defined in postfix restriction rule \`check_helo_access\`.
#   no all rules contains 'ACCESS DENIED', so we use status code insead.

failregex = \[<HOST>\]: SASL (PLAIN|LOGIN) authentication failed
            lost connection after (AUTH|UNKNOWN) from (.*)\[<HOST>\]
            reject: RCPT from .*\[<HOST>\]: .*: Relay access denied
            reject: RCPT from .*\[<HOST>\]: .*: Sender address rejected: Domain not found
            reject: RCPT from .*\[<HOST>\]: .*: Helo command rejected: Host not found
            reject: RCPT from .*\[<HOST>\]: .*: Helo command rejected: need fully-qualified hostname
            reject: RCPT from .*\[<HOST>\]: 554 5.7.1
            reject: RCPT from .*\[<HOST>\]:\d+: 550 5.5.1 Protocol error
            warning: Illegal address syntax from (.*)\[<HOST>\] in RCPT command
            postfix\/submission\/smtpd.*: too many errors after AUTH from .*\[<HOST>\]

ignoreregex =" > /etc/fail2ban/filter.d/postfix-irm.conf

sed -i '15i/etc/rc.d/rc.fail2ban start > /dev/null 2>&1' /etc/rc.d/rc.local
echo "/etc/rc.d/rc.fail2ban stop > /dev/null 2>&1" >> /etc/rc.d/rc.local_shutdown

fi

# Setup smmlm

if [ $SMMLM = 1 ]; then

# Create random password for mailinglist mailbox.

random_pass > /root/SlackerMail/smmlm-mailinglist-mailbox.pass
sleep 1
MLPASS=$(cat /root/SlackerMail/smmlm-mailinglist-mailbox.pass)
sleep 1
/var/www/postfixadmin/scripts/postfixadmin-cli mailbox add mailinglist@$DOMAIN --name mailinglist --quota 100 --active 1 --password $MLPASS --password2 $MLPASS
sleep 1
echo "
mailinglist@$DOMAIN roundcube mailbox password: $MLPASS" >> /root/SlackerMail/SlackerMail.setup

# Add group, user, and make directory for smmlm.

groupadd -g 401 smmlm
useradd -u 401 -d /var/spool/smmlm -s /bin/false -g smmlm smmlm
mkdir /var/spool/smmlm
chown smmlm:smmlm /var/spool/smmlm
chmod 0750 /var/spool/smmlm

# Create the mailinglist database and insert the lists table for smmlm.

echo "CREATE TABLE lists(
    list_id INTEGER PRIMARY KEY,
    email TEXT UNIQUE
);" > /var/spool/smmlm/smmlm.sql
sleep 1
sqlite3 /var/spool/smmlm/mailinglist.db < /var/spool/smmlm/smmlm.sql
chown smmlm:smmlm /var/spool/smmlm/smmlm.sql
chown smmlm:smmlm /var/spool/smmlm/mailinglist.db

# Install the smmlm bash script that controls the database.

cp -f $SMPWD/pkgs/smmlm /var/spool/smmlm/
chown smmlm:smmlm /var/spool/smmlm/smmlm
chmod 0750 /var/spool/smmlm/smmlm
sed -i "s/mailinglist@example.org/mailinglist@$DOMAIN/g" /var/spool/smmlm/smmlm

# Install the sqlite3 .timeout option that prevents the database from being locked under heavy load.

echo ".timeout 1000" > /var/spool/smmlm/init.sql
chown smmlm:smmlm /var/spool/smmlm/init.sql

# Install the email2subs bash script that sends messages toyour subscribers.

cp -f $SMPWD/pkgs/email2subs /var/spool/smmlm/
chown smmlm:smmlm /var/spool/smmlm/email2subs
chmod 0750 /var/spool/smmlm/email2subs
sed -i "s/example.org/$DOMAIN/g" /var/spool/smmlm/email2subs

# Create the message file that holds the message you want to send to your subscribers.

echo "Hello subscribers! This is a test of the my mailing list.


To unsubscribe: send an email to mailinglist@$DOMAIN with unsubscribe in the body of the email.

Thanks,
admin@$DOMAIN" > /var/spool/smmlm/message
chown smmlm:smmlm /var/spool/smmlm/message

# Create the welcome message that is sent to new subscribers.

echo "Welcome to my mailing list.


To unsubscribe: Send an email to mailinglist@$DOMAIN with unsubscribe in the body of the email.

Thanks,
admin@$DOMAIN" > /var/spool/smmlm/welcome-message
chown smmlm:smmlm /var/spool/smmlm/welcome-message

# Create header checks in /etc/postfix/header_checks to divert email going to mailinglist to the smmlm filter.

sed -i "3i/^To: \"mailinglist@$DOMAIN\"/ FILTER smmlm:" /etc/postfix/header_checks
sed -i "4i/^To: mailinglist@$DOMAIN/ FILTER smmlm:" /etc/postfix/header_checks

# Setup smmlm mail filter in /etc/postfix/master.cf.

sed -i '30ismmlm  unix  -        n       n       -       10      pipe\n  flags=Rq user=smmlm null_sender=\n  argv=/var/spool/smmlm/smmlm -f ${sender} -- ${recipient}\n\
127.0.0.1:10022 inet n  -   -   -   -  smtpd\n  -o content_filter=smmlm:\n' /etc/postfix/master.cf 

fi

# Setup Netdata

if [ $NETDATA = 1 ]; then 

# Install Mysql Python Connector and python2-PyYAML

pip install mysql-connector-python
installpkg $SMPWD/pkgs/python2-PyYAML-3.13-x86_64-1_SBo.tgz

# Add the netdata group and user
groupadd -g 338 netdata
useradd -u 338 -g 338 -c "netdata user" -s /bin/bash netdata

# Grant Mysql usage to Netdata.

random_pass > /root/SlackerMail/netdata-mysql.pass
sleep 1
NETDATAMYSQLPASS=$(cat /root/SlackerMail/netdata-mysql.pass)
chmod 0600 /root/SlackerMail/netdata-mysql.pass
mysql -u root -Bse "GRANT USAGE ON *.* TO netdata@localhost IDENTIFIED BY '${NETDATAMYSQLPASS}';FLUSH PRIVILEGES"

echo "
Mysql Netdata Password: $NETDATAMYSQLPASS" >> /root/SlackerMail/SlackerMail.setup

# Install Netdata

cd /root/tmp
wget https://github.com/netdata/netdata/releases/download/v1.42.2/netdata-v1.42.2.gz.run
chmod 0755 netdata-v1.42.2.gz.run
./netdata-v1.42.2.gz.run --accept
rm netdata-v1.42.2.gz.run

# Create Netdata users file and password.

random_pass > /root/SlackerMail/netdata-users.pass
sleep 1
chmod 0600 /root/SlackerMail/netdata-users.pass
NETDATAUSERSPASS=$(cat /root/SlackerMail/netdata-users.pass)
echo "
Netdata Web Interface User and Password:
User: netdata
Password: $NETDATAUSERSPASS
Netdata Web Address: https://$DOMAIN/netdata" >> /root/SlackerMail/SlackerMail.setup
chmod 0600 /root/SlackerMail/SlackerMail.setup
touch /etc/httpd/netdata.users
chown apache:apache /etc/httpd/netdata.users
chmod 0400 /etc/httpd/netdata.users
printf "netdata:$(openssl passwd -apr1 $NETDATAUSERSPASS)" > /etc/httpd/netdata.users

# Setup Fail2ban to work with Netdata.

touch /var/log/fail2ban.log
chmod 0644 /var/log/fail2ban.log
sed -i '9icreate 644 root root' /etc/logrotate.d/fail2ban

# Setup Mysql to work with Netdata.

touch /opt/netdata/etc/netdata/go.d/mysql.conf
chown netdata:netdata /opt/netdata/etc/netdata/go.d/mysql.conf
chmod 0400 /opt/netdata/etc/netdata/go.d/mysql.conf

echo "jobs:
  - name: local
    dsn: netdata:$NETDATAMYSQLPASS@tcp(127.0.0.1:3306)/" >> /opt/netdata/etc/netdata/go.d/mysql.conf
    
# Setup PHP-FPM to work with Netdata.

touch /opt/netdata/etc/netdata/go.d/phpfpm.conf
chown netdata:netdata /opt/netdata/etc/netdata/go.d/phpfpm.conf

echo "jobs:
  - name: local_socket
    socket: '/var/run/php-fpm.sock'" >> /opt/netdata/etc/netdata/go.d/phpfpm.conf
    
# Opt out of Netdata anaonymous statistics.

touch /opt/netdata/etc/netdata/.opt-out-from-anonymous-statistics

# Don't recieve emails from Netdata.

echo 'SEND_EMAIL="NO"' > /opt/netdata/etc/netdata/health_alarm_notify.conf
chown netdata:netdata /opt/netdata/etc/netdata/health_alarm_notify.conf

# Set Netdata to start at boot and stop at reboot or shutdown.

cp -f $SMPWD/conf/rc.netdata /etc/rc.d/
chmod 0755 /etc/rc.d/rc.netdata
echo "/etc/rc.d/rc.netdata start > /dev/null 2>&1" >> /etc/rc.d/rc.local
echo "/etc/rc.d/rc.netdata stop > /dev/null 2>&1" >> /etc/rc.d/rc.local_shutdown

fi

# Getting things in order.

# Securing PHP by disabling some functions.

sed -i "/disable_functions =/c\disable_functions = system, posix_uname, eval, pcntl_wexitstatus, posix_getpwuid, \
xmlrpc_entity_decode, pcntl_wifstopped, pcntl_wifexited, pcntl_wifsignaled, phpAds_XmlRpc, pcntl_strerror, ftp_exec, pcntl_wtermsig, \
mysql_pconnect, proc_nice, pcntl_sigtimedwait, posix_kill, pcntl_sigprocmask, fput, phpinfo, phpAds_remoteInfo, ftp_login, inject_code, \
posix_mkfifo, highlight_file, escapeshellcmd, show_source, pcntl_wifcontinued, fp, pcntl_alarm, pcntl_wait, ini_alter, posix_setpgid, \
parse_ini_file, ftp_raw, pcntl_waitpid, pcntl_getpriority, ftp_connect, pcntl_signal_dispatch, pcntl_wstopsig, ini_restore, ftp_put, \
passthru, proc_terminate, posix_setsid, pcntl_signal, pcntl_setpriority, phpAds_xmlrpcEncode, pcntl_exec, ftp_nb_fput, ftp_get, \
phpAds_xmlrpcDecode, pcntl_sigwaitinfo, shell_exec, pcntl_get_last_error, ftp_rawlist, pcntl_fork, posix_setuid" /etc/php.ini

# Making more security and performance adjustments to php.ini.

sed -i "/expose_php = On/c\expose_php = Off" /etc/php.ini
sed -i "/memory_limit = 128M/c\memory_limit = 256M" /etc/php.ini
sed -i "/post_max_size = 8M/c\post_max_size = 12M" /etc/php.ini
sed -i "/upload_max_filesize = 2M/c\upload_max_filesize = 10M" /etc/php.ini
# Set timezone to machines reported configured timezone.
LTZ=`readlink /etc/localtime | sed "s/\/usr\/share\/zoneinfo\///"`
sed -i "/;date.timezone =/c\date.timezone = $LTZ" /etc/php.ini


# Setup backup for Mysql databases.

mkdir -p /var/vmail/backup
cp -f $SMPWD/pkgs/mysql_backup.sh /var/vmail/backup/
chmod 0500 /var/vmail/backup/mysql_backup.sh

echo '# Daily backup of the mysql databases.
#!/bin/sh
/var/vmail/backup/mysql_backup.sh > /dev/null 2>&1' > /etc/cron.daily/mysql-backup
chmod 0755 /etc/cron.daily/mysql-backup

# Configure logging

sed -i "/#dateext/c\dateext" /etc/logrotate.conf
sed -i "/#compress/c\compress\ncompresscmd /bin/bzip2\nuncompresscmd /bin/bunzip2\ncompressext .bz2" /etc/logrotate.conf

# Install some needed utilities.

installpkg $SMPWD/pkgs/p7zip-17.04-x86_64-1_SBo.tgz
installpkg $SMPWD/pkgs/unrar-6.1.7-x86_64-1_SBo.tgz
installpkg $SMPWD/pkgs/openzfs-2.1.12_5.15.94-x86_64-1_SBo.tgz

# Create daily cron job to update time and update time.

echo -e '# Daily time update
#!/bin/sh
/usr/sbin/ntpdate pool.ntp.org > /dev/null 2>&1' > /etc/cron.daily/time-update
chmod 0755 /etc/cron.daily/time-update
/etc/cron.daily/time-update

# Do some cleanup and misc.

rm /root/SlackerMail/*.pass /root/SlackerMail/dkim.pubkey /root/SlackerMail/roundcube.deskey

# Add post install instructions.

echo -e "
Things to do after SlackerMail is installed.
--------------------------------------------

1. Enter your DKIM key from /root/SlackerMail/$DOMAIN.pub.txt into your DNS Zone Management at your VPS provider.
   At contabo.com I enter mine as \"dkim._domainkey.wjack.org 14400 TXT v=DKIM1;p=your-dkim-pubkey-here\"

2. Postfix Admin is fully setup and ready to use in this latest version. Go to https://$DOMAIN/postfixadmin and 
   login to your super admin account: admin@$DOMAIN with the postfix admin password listed above.

3. You should be able to sign into the admin@$DOMAIN Roundcube Mail mailbox at https://$DOMAIN/mail with the
   Roundcubemail mailbox password for admin@$DOMAIN listed above.

4. For security reasons, if you installed Webmin you may want to only allow your ip address to access webmin.
   To do this edit the /etc/webmin/miniserv.conf and add the line: allow=your-ip-address-here.

5. For security reasons you may want to only allow your ip address to access sshd. To do that edit /etc/hosts.allow
   and add the line: sshd: your-ip-address-here then in /etc/hosts.deny add the line: sshd: ALL

6. You'll probably want to switch to Let's Encrypt SSL certs. Go to https://the-slacker.com/let's.encrypt.setup.html 
   to read my how-to on getting and using Let's Encrypt SSL certs.

Thanks,
wjack@the-slacker.com" >> /root/SlackerMail/SlackerMail.setup

# Create file with version of SlackerMail

echo -e ".025" > /etc/SlackerMail-release

clear

# Dialog box asking if you want to reboot or not.

dialog --title "SlackerMail Install" \
--backtitle "SlackerMail Install" \
--yesno "SlackerMail has successfully installed. Reboot needed to finish setup. Do you want to reboot now?" 7 60
response=$?

clear

case $response in
   0) echo "Rebooting!"
   reboot;;
   1) echo "Exiting to shell!"
   exit;;
esac

