#!/usr/bin/perl
#
# $Id: qproxy.pl 14480 2013-05-13 08:26:20Z jakob $
#
# Copyright (c) 2013 Kirei AB. All rights reserved.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
# GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
# IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
# IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
######################################################################

use strict;
use warnings;
use Net::DNS;
use Time::HiRes qw(gettimeofday tv_interval);
use MIME::Base64;
use JSON;
use Net::IP qw(:PROC);
use Data::Dumper;

my $version = sprintf("qproxy 0.0 Net::DNS %s", Net::DNS->version);

sub main {
    while (<STDIN>) {
        exit(0) if ($_ eq "");
        chomp;
        exit(0) if ($_ eq "");

        my $param = undef;
        eval { $param = from_json($_); };
        if ($@) {
            fatal("Failed to parse JSON input");
        }

        my $resolver = setup_resolver($param);

        my $query =
          new Net::DNS::Packet($param->{qname}, $param->{qtype},
            $param->{qclass});

        my $t1       = [gettimeofday];
        my $response = $resolver->send($query);
        my $t2       = [gettimeofday];

        my $blob = {
            'address'   => $param->{address},
            'port'      => $param->{port},
            'transport' => $param->{transport},
            'time '     => tv_interval($t1, $t2),
            'query'     => $query ? encode_base64($query->data, "") : "",
            'response'  => $response
            ? encode_base64($response->data, "")
            : "",
            'version' => $version,
        };

        print to_json($blob, { utf8 => 1 });
    }
}

sub fatal {
    my $message = shift;

    my $blob = {
        'error'   => $message,
        'version' => $version,
    };

    print to_json($blob, { utf8 => 1 });

    exit(0);
}

sub setup_resolver {
    my $param = shift;

    # Check for required parameters
    fatal("Missing address") unless defined($param->{address});
    fatal("Missing QNAME")   unless defined($param->{qname});
    fatal("Missing QCLASS")  unless defined($param->{qclass});
    fatal("Missing QTYPE")   unless defined($param->{qtype});

    # Set defaults
    $param->{port}        //= 53;
    $param->{transport}   //= "udp";
    $param->{tcp_timeout} //= 60;
    $param->{udp_timeout} //= 60;
    $param->{bufsize}     //= 512;
    $param->{flags}->{cd} //= 0;
    $param->{flags}->{rd} //= 0;
    $param->{flags}->{ad} //= 0;
    $param->{flags}->{do} //= 0;

    # Validate input
    fatal("Failed to parse address")
      unless is_ip($param->{address});

    fatal("Failed to parse port")
      unless ($param->{port} =~ /^\d+$/ and is_port($param->{port}));

    fatal("Failed to parse transport")
      unless ($param->{transport} eq "tcp"
        or $param->{transport} eq "udp");

    fatal("Invalid UDP timeout")
      unless ($param->{udp_timeout} =~ /^\d+$/
        and $param->{udp_timeout} > 0
        and $param->{udp_timeout} <= 60);

    fatal("Invalid TCP timeout")
      unless ($param->{tcp_timeout} =~ /^\d+$/
        and $param->{tcp_timeout} > 0
        and $param->{tcp_timeout} <= 60);

    fatal("Invalid UDP buffer size")
      unless ($param->{bufsize} =~ /^\d+$/
        and $param->{bufsize} > 0
        and $param->{bufsize} <= 65536);

    # Validate flags
    fatal("Failed to parse CD flag") unless is_boolean($param->{flags}->{cd});
    fatal("Failed to parse RD flag") unless is_boolean($param->{flags}->{rd});
    fatal("Failed to parse AD flag") unless is_boolean($param->{flags}->{ad});
    fatal("Failed to parse DO flag") unless is_boolean($param->{flags}->{do});

    # Set up resolver
    my $res = Net::DNS::Resolver->new;
    $res->nameserver($param->{address});
    $res->port($param->{port});
    $res->usevc($param->{transport} eq "tcp" ? 1 : 0);
    $res->dnssec($param->{flags}->{do});
    $res->recurse($param->{flags}->{rd});
    $res->adflag($param->{flags}->{ad});
    $res->cdflag($param->{flags}->{cd});
    $res->dnsrch(0);
    $res->defnames(0);
    $res->retrans(5);
    $res->retry(4);

    if ($res->dnssec and not $res->usevc) {
        $res->udppacketsize($param->{bufsize});
    }

    return $res;
}

sub is_ip {
    my $ip = shift;
    return (ip_is_ipv4($ip) or ip_is_ipv4($ip));
}

sub is_port {
    my $port = shift;
    return ($port > 0 or $port < 65536);
}

sub is_boolean {
    my $x = shift;
    return 1 if ($x == 0 or $x == 1);
}

main;
