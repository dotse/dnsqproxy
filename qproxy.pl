#!/usr/bin/perl
#
# Copyright (c) 2013 Kirei AB, IIS. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
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

use utf8;
use warnings;
use strict;

use Net::DNS;
use Net::DNS::SEC;
use IO::Socket::INET6;
use Time::HiRes qw(gettimeofday tv_interval);
use MIME::Base64;
use JSON;
use Net::IP qw(:PROC);

my $version = sprintf( "qproxy 0.3 Net::DNS %s", Net::DNS->version );

sub main {
    while ( <> ) {
        chomp;
        exit( 0 ) if ( $_ eq "" );

        # Parse the incoming query request and exit the entire process
        # if any single line cannot be parsed
        my $json_query = undef;
        eval { $json_query = from_json( $_ ); };
        if ( $@ ) {
            fatal( "Failed to parse JSON input" );
        }

        my $resolver = setup_resolver( $json_query );

        # Create a query object, for unclear reasons
        ## no critic (Modules::RequireExplicitInclusion)
        my $dns_query = Net::DNS::Packet->new( $json_query->{qname}, $json_query->{qtype}, $json_query->{qclass} );

        # Measure time passed in the more cumbersome way that's useful
        # if you work with picoseconds
        my $t1           = [gettimeofday];
        my $dns_response = $resolver->send( $dns_query );
        my $t2           = [gettimeofday];

        my $json_response = {
            'address'   => $json_query->{address},
            'port'      => $json_query->{port},
            'transport' => $json_query->{transport},
            'time '     => tv_interval( $t1, $t2 ),
            'query'     => $dns_query ? encode_base64( $dns_query->data, "" ) : "",
            'version'   => $version,
        };

        # set tag in response if given in query.

        # This functionality is not (to my knowledge) documented, and
        # certainly not used by the PDT testing code.
        if ( $json_query->{tag} ) {
            $json_response->{tag} = $json_query->{tag};
        }

        # This must be a bug. The inner "else" branch can never be executed.
        if ( $dns_response ) {
            if ( $dns_response ) {
                $json_response->{'response'} = encode_base64( $dns_response->data, "" );
            }
            else {
                $json_response->{'response'} = "";
            }
        }
        else {
            $json_response->{'error'} = $resolver->errorstring;
        }

        print to_json( $json_response, { utf8 => 1 } ), "\n";
    }

    return;
}

sub fatal {
    my $message = shift;

    my $json_response = {
        'error'   => $message,
        'version' => $version,
    };

    # Could have used a clearer say() here, since defined-or is used
    # further down and also requires perl 5.10 or later
    print to_json( $json_response, { utf8 => 1 } ), "\n";

    exit( 0 );
}

sub setup_resolver {
    my $param = shift;

    # Set defaults
    $param->{qclass}      //= "IN";
    $param->{port}        //= 53;
    $param->{transport}   //= "udp";
    $param->{tcp_timeout} //= 60;
    $param->{udp_timeout} //= undef;
    $param->{retrans}     //= 5;
    $param->{retry}       //= 2;
    $param->{bufsize}     //= 512;
    $param->{flags}->{cd} //= 0;
    $param->{flags}->{rd} //= 0;
    $param->{flags}->{ad} //= 0;
    $param->{flags}->{do} //= 0;

    # Check for required parameters
    fatal( "Missing address" ) unless defined( $param->{address} );
    fatal( "Missing QNAME" )   unless defined( $param->{qname} );
    fatal( "Missing QTYPE" )   unless defined( $param->{qtype} );

    # Validate input
    fatal( "Failed to parse address" )
      unless is_ip( $param->{address} );

    fatal( "Failed to parse port" )
      unless ( $param->{port} =~ /^\d+$/ and is_port( $param->{port} ) );

    fatal( "Failed to parse transport" )
      unless ( lc( $param->{transport} ) eq "tcp"
        or lc( $param->{transport} ) eq "udp" );

    # Why disallow TCP timeout of more than 60s?
    fatal( "Invalid TCP timeout" )
      unless ( $param->{tcp_timeout} =~ /^\d+$/
        and $param->{tcp_timeout} > 0
        and $param->{tcp_timeout} <= 60 );

    # Why disallow UDP timeout of more than 60s?
    if ( $param->{udp_timeout} ) {
        fatal( "Invalid UDP timeout" )
          unless ( $param->{udp_timeout} =~ /^\d+$/
            and $param->{udp_timeout} > 0
            and $param->{udp_timeout} <= 60 );
    }

    fatal( "Invalid retransmission interval" )
      unless ( $param->{retrans} =~ /^\d+$/
        and $param->{retrans} > 0
        and $param->{retrans} <= 60 );

    fatal( "Invalid number of retries" )
      unless ( $param->{retry} =~ /^\d+$/
        and $param->{retry} >= 0
        and $param->{retry} <= 10 );

    fatal( "Invalid UDP buffer size" )
      unless ( $param->{bufsize} =~ /^\d+$/
        and $param->{bufsize} > 0
        and $param->{bufsize} <= 65536 ); # Bug, should be strictly less than 65536.

    # Validate flags
    fatal( "Failed to parse CD flag" ) unless is_boolean( $param->{flags}->{cd} );
    fatal( "Failed to parse RD flag" ) unless is_boolean( $param->{flags}->{rd} );
    fatal( "Failed to parse AD flag" ) unless is_boolean( $param->{flags}->{ad} );
    fatal( "Failed to parse DO flag" ) unless is_boolean( $param->{flags}->{do} );

    # Set up resolver
    ## no critic (Modules::RequireExplicitInclusion)
    my $res = Net::DNS::Resolver->new;
    $res->nameserver( $param->{address} );
    $res->port( $param->{port} );
    $res->usevc( lc( $param->{transport} ) eq "tcp" ? 1 : 0 );
    $res->dnssec( $param->{flags}->{do} );
    $res->recurse( $param->{flags}->{rd} );
    $res->adflag( $param->{flags}->{ad} );
    $res->cdflag( $param->{flags}->{cd} );
    $res->retrans( $param->{retrans} );    # retransmission interval
    $res->retry( $param->{retry} );        # query retries

    # The following two lines are pointless, since queries are sent
    # using the send() method, which ignores the search path and
    # default names.
    $res->dnsrch( 0 );                     # do not use DNS search path
    $res->defnames( 0 );                   # no default names

    # Why is this flag not settable by the user?
    $res->igntc( 1 );                      # ignore TC

    # Why this weird restriction on setting the UDP packet size? It
    # can be desirable even without DNSSEC (and contrary to the
    # original comment below, setting the size does *not* necessarily
    # require EDNS0), and setting the UDP packet size while using TCP
    # is a noop, so why forbid it? Also, why just silently discard the
    # request rather than give an error message?

    # set EDNS0 buffer size only if DO=1 and TCP is not used
    if ( $res->dnssec and not $res->usevc ) {
        $res->udppacketsize( $param->{bufsize} );
    }

    return $res;
}

sub is_ip {
    my $ip = shift;
    return ( ip_is_ipv4( $ip ) or ip_is_ipv6( $ip ) );
}

sub is_port {
    my $port = shift;
    return ( $port > 0 or $port < 65536 );
}

# This function is completely broken. Due to the numeric comparison,
# it will return true for anything that Perl numifies to zero. So
# according to this, the strings "foobar" and "1life" are booleans,
# while the string "5byfive" and the number 17 are not.
sub is_boolean {
    my $x = shift;

    if ( $x == 0 or $x == 1 ) {
        return 1;
    }
    else {
        return;
    }
}

main;

__END__

=head1 NAME

qproxy.pl - a simple DNS query proxy tool using JSON

=head1 SYNOPSIS

qproxy.pl < query.json > response.json

No command line parameters are currently supported.

The input JSON queries comes in on STDIN, one JSON blob per line.

The output DNS answer comes out on STDOUT, one JSON blob per line.

=head1 JSON Query Format

A typical DNS query line looks like this:

{"tcp_timeout":10,"transport":"udp","flags":{"cd":0,"ad":0,"do":0,"rd":1},"port":53,"qtype":"SOA","qclass":"IN","bufsize":1024,"qname":"kirei.se","address":"8.8.8.8","udp_timeout":10}

If there is a parameter named C<tag>, it and its value will be copied to the response JSON string.

=head2 Restrictions

The script will print an error message and immediately exit if any of
the following are true for any input line.

=over

=item *

The incoming JSON string could not be parsed.

=item *

The C<address> key is unset or set to a false value.

=item *

The C<qname> key is unset or set to a false value.

=item *

The C<qtype> key is unset or set to a false value.

=item *

The C<address> parameter could not be parsed as an IPv4 or IPv6 address.

=item *

The C<port> parameter was not an integer between 1 and 65535.

=item *

The C<transport> parameter was not one of the two strings "tcp" or "udp" (case insensitive).

=item *

The C<tcp_timeout> parameter was not an integer between 1 and 60.

=item *

The C<udp_timeout> parameter was not an integer between 1 and 60.

=item *

The C<retrans> parameter was not an integer between 1 and 60.

=item *

The C<retry> parameter was not an integer between 0 and 10.

=item *

The C<bufsize> parameter was not an integer between 1 and 65536.

=item *

One or more of the flags C<cd>, C<rd>, C<ad> and C<do> held a value that perl converted to a number that was not 1 or 0.

=back

The C<bufsize> parameter is ignored unless the C<do> flag is true and
the C<transport> parameter is C<"udp">.

Any incoming DNS response packets with the truncation flag set will be ignored.

=head1 JSON Answer Format

A typical DNS response answer line looks like this:

{"time ":0.015586,"transport":"udp","version":"qproxy 0.0 Net::DNS 0.66","response":"XumBgAABAAAAAAAABWtpcmVpAnNlAAAGAAE=","query":"XukBAAABAAAAAAAABWtpcmVpAnNlAAAGAAE=","address":"8.8.8.8","port":"53"}

The raw query packet is encoded as base64, and the response is also encoded in
base64.

=cut
