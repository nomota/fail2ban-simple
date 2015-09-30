#!/usr/bin/perl

# -------------------------------------------------------------------------------------------------------
# 1. Ban abusing ip addresses detected by PAM in file '/var/log/secure file"
#    Ex. "PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=43.229.53.60  user=root"
# 2. Check duplication by 'iptables -L' command
# -------------------------------------------------------------------------------------------------------

my @iptables = `/sbin/iptables -L -n`;

sub ban_ip($)
{
    my ($ip) = @_;

    my $found = 0;
    foreach my $line (@iptables) {
        if ($line =~ /$ip/ && $line =~ /DROP/) {
            $found = 1; last;
        }
    }

    if ($found) { # Don't register duplicated ip block
        print "$ip is already in DROP list\n";
        return;
    }

    my $cmd = "/sbin/iptables -A INPUT -s $ip -j DROP";
    `$cmd`;
    print "+OK FAIL2BAN $ip\n";
}

MAIN: {
    my @lines = `/usr/bin/tail -20000 /var/log/secure`;
    my $intrusion = {};
    my $intrusion2 = {};
    foreach my $line (@lines) {
        # PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=43.229.53.60  user=root
        if ($line =~ /PAM\s+\d+\s+more authentication failures.+rhost=([\d\.]+).+user=(\S+)/) {
            my ($ip, $uid) = ($1, $2);
            if (! defined $intrusion->{$ip}) {
                $intrusion->{$ip} = [];
            }
            push @{$intrusion->{$ip}}, $uid;
        }
        
        # Failed password for invalid user ubnt from 167.114.129.42 port 53685 ssh2
        if ($line =~ /Failed password for invalid user .+ from ([\d\.]+)/) {
            my $ip = $1;
            if (! defined $intrusion2->{$ip}) {
                $intrusion2->{$ip} = [];
            }
            push @{$intrusion2->{$ip}}, $ip;
        }
    }

    foreach my $ip (keys %{$intrusion}) {
        if (@{$intrusion->{$ip}} >= 2) {
            # print "$ip: @{$intrusion->{$ip}}\n";
            print "$ip is suspecious\n";
            ban_ip($ip);
        }
    }
    
    foreach my $ip (keys %{$intrusion2}) {
        if (@{$intrusion2->{$ip}} >= 10) {
            # print "$ip: @{$intrusion2->{$ip}}\n";
            print "$ip is suspecious\n";
            ban_ip($ip);
        }
    }

}
