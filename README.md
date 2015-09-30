# fail2ban - the most simplest code
A very simple mined fail2ban code in Perl - ban an IP address if it is detected in /var/log/secure file

# Installation

Step 0. You need to be in 'root' mode of your Linux box.

Step 1. Just download fail2ban.pl in your Linux box /root/bin/ directory.
    filename /root/bin/fail2ban.pl

Step 2. chmod 755 /root/bin/fail2ban.pl (change mode to be executable)

Step 3. Add crontab entry as follows. 'crontab -l' should display as follows
* * * * * /root/bin/fail2ban.pl >/dev/null 2>/dev/null &

Step 4. Just wait for one minute.
