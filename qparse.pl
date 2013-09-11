#!/usr/bin/perl

use utf8;
use warnings;
use strict;
use Net::DNS;
use MIME::Base64;
use JSON;

while ( <STDIN> ) {
    chomp;
    my $json = $_;

    print STDERR "########## INPUT\n";
    print STDERR "\n";
    print STDERR "$json\n";
    print STDERR "\n";

    my $blob = from_json( $json );

    ## no critic (Modules::RequireExplicitInclusion)
    my $raw_query = decode_base64( $blob->{query} );
    my $query     = Net::DNS::Packet->new( \$raw_query );

    my $raw_response = decode_base64( $blob->{response} );
    my $response     = Net::DNS::Packet->new( \$raw_response );

    print STDERR "########## QUERY DUMP\n";
    print STDERR "\n";
    print STDERR $query->string;
    print STDERR "\n";

    print STDERR "########## RESPONSE DUMP\n";
    print STDERR "\n";
    print STDERR $response->string;

}
