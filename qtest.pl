#!/usr/bin/perl

use utf8;
use warnings;
use strict;
use JSON;

my $nameserver = "8.8.8.8";

my @queries = (
    {
        tag       => "1",
        address   => $nameserver,
        transport => "tcp",
        bufsize   => 1280,
        qname     => "kirei.se",
        qtype     => "SOA",
        flags     => { do => 1, cd => 0, rd => 1, ad => 0 },
    },
    {
        tag       => "2",
        address   => $nameserver,
        transport => "udp",
        bufsize   => 512,
        qname     => "kirei.se",
        qtype     => "NS",
        flags     => { do => 0, cd => 0, rd => 1, ad => 0 },
    },
    {
        tag       => "3",
        address   => $nameserver,
        transport => "udp",
        bufsize   => 1024,
        qname     => "kirei.se",
        qtype     => "MX",
        flags     => { do => 1, cd => 0, rd => 1, ad => 0 },
    },
);

foreach my $json ( map { to_json( $_ ) } @queries ) {
    print $json, "\n";
}
