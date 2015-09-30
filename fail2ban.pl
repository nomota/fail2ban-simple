#!/usr/bin/perl

# -------------------------------------------------------------------------------------------------------
# 1. Ban abusing ip addresses detected by PAM in file '/var/log/secure file"
#    Ex. "PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=43.229.53.60  user=root"
# 2. Check duplication by 'iptables -L' command
# -------------------------------------------------------------------------------------------------------

my @iptables = `/sbin/iptables -L`;

# --------------------------------------------------------
# Check reverse ordered IP addresses for following case
# Ex: 157.0.47.59.broad.bx.ln.dynamic.163data.com.cn
# --------------------------------------------------------
sub reverse_ip($)
{
    my ($ip) = @_;
    my @nums = split(/\./, $ip);
    return "$nums[3].$nums[2].$nums[1].$nums[0]";
}

sub ban_ip($)
{
    my ($ip) = @_;
    my $ip2 = reverse_ip($ip);

    my $found = 0;
    foreach my $line (@iptables) {
        if (($line =~ /$ip/ || $line =~ /$ip2/) && $line =~ /DROP/) {
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
    foreach my $line (@lines) {
        # PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=43.229.53.60  user=root
        if ($line =~ /PAM\s+\d+\s+more authentication failures.+rhost=([\d\.]+).+user=(\S+)/) {
            my ($ip, $uid) = ($1, $2);
            if (! defined $intrusion->{$ip}) {
                $intrusion->{$ip} = [];
            }
            push @{$intrusion->{$ip}}, $uid;
        }
    }

    foreach my $ip (keys %{$intrusion}) {
        if (@{$intrusion->{$ip}} >= 2) {
            # print "$ip: @{$intrusion->{$ip}}\n";
            print "$ip is suspecious\n";
            ban_ip($ip);
        }
    }
}
