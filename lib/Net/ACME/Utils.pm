package Net::ACME::Utils;

=encoding utf-8

=head1 NAME

Net::ACME::Utils - utilities for C<Net::ACME>

=head1 SYNOPSIS

    Net::ACME::Utils::verify_token('blah/blah');     #dies
    Net::ACME::Utils::verify_token('blah-blah');     #succeeds

    my $jwk_hr = Net::ACME::Utils::get_jwk_data($rsa_key_pem);

=head1 DESCRIPTION

This module is a home for “miscellaneous” functions that just aren’t
in other modules. Think carefully before expanding this module; it’s
probably better, if possible, to put new functionality into more
topic-specific modules rather than this “catch-all” one.

=cut

use strict;
use warnings;

use Crypt::Format  ();
use Crypt::PK::RSA ();

use MIME::Base64 ();
*_to_base64url = \&MIME::Base64::encode_base64url;

use Net::ACME::X ();

my %KEY_OBJ_CACHE;

#Clear out the cache prior to global destruction.
END {
    %KEY_OBJ_CACHE = ();
}

sub verify_token {
    my ($token) = @_;

    local $@;
    eval {

        #XXX
        die Net::ACME::X::create('Empty') if !length $token;
        die Net::ACME::X::create('Empty') if $token =~ m<\A\s*\z>;

        if ( $token =~ m<[^0-9a-zA-Z_-]> ) {
            die Net::ACME::X::create( 'InvalidCharacters', "“$token” contains invalid Base64-URL characters.", { value => $token } );
        }

    };

    if ($@) {
        my $message = $@->to_string();

        die Net::ACME::X::create( 'InvalidParameter', "“$token” is not a valid ACME token. ($message)" );
    }

    return;
}

sub get_jwk_data {
    my ($key_pem) = @_;

    #The “1” makes it give a hashref rather than JSON.
    return _get_key_obj($key_pem)->export_key_jwk( 'public', 1 );
}

sub get_jwk_thumbprint {
    my ($key_jwk) = @_;

    return Crypt::PK::RSA->new( {%$key_jwk} )->export_key_jwk_thumbprint('SHA256');
}

#----------------------------------------------------------------------

sub _get_key_obj {
    my ($key_pem) = @_;

    return $KEY_OBJ_CACHE{ Crypt::Format::pem2der($key_pem) } ||= Crypt::PK::RSA->new( \$key_pem );
}

1;
