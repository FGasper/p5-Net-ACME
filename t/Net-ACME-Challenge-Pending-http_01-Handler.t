package t::Net::ACME::Challenge::Pending::http_01::Handler;

use strict;
use warnings;
use autodie;

our @ISA;

BEGIN {
    require "Net-ACME-Certificate-Pending-http_01.t";
    unshift @ISA, 't::Net::ACME::Certificate::Pending::http_01';
}

use Test::More;

if ( !caller ) {
    my $test_obj = __PACKAGE__->new();
    plan tests => $test_obj->expected_tests(+1);
    $test_obj->runtests();
}

1;
