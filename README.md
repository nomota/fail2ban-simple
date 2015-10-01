# fail2ban - the simplest code ever
A very simple-minded fail2ban code in Perl - ban an IP address if it is detected in /var/log/secure file.
Just block IP addresses of repeated password failure.

# Installation

Step 0. You need to be in 'root' mode of your Linux box.

Step 1. Just download 'fail2ban.pl' in your Linux box '/root/bin/' directory.
    filename '/root/bin/fail2ban.pl'

Step 2. Run command: 'chmod 755 /root/bin/fail2ban.pl' (change mode to be executable)

Step 3. Add 'crontab' entry as follows. Command 'crontab -l' of your 'root' should display as follows
* * * * * /root/bin/fail2ban.pl >/dev/null 2>/dev/null &

Step 4. Just wait for one minute. That's all.

Step 5. If your Linux box is under attack, perhaps one minute later you'll have some entries.
    Command '/sbin/iptables -L' shall show what's been detected.

# Prerequisite

0. '/usr/bin/perl', '/sbin/iptables', '/usr/bin/tail' must be available by 'root'
1. '/var/log/secure' log should be in compatible with following PAM line ==> 
   "PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=43.229.53.60  user=root"

# Tested

Only on CentOS-6.
