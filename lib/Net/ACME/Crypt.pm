package Net::ACME::Crypt;

#----------------------------------------------------------------------
# This module exists because of a desire to do these computations
# in pure Perl, for environments where a compiler may not be available.
# (Otherwise, CryptX would be ideal.)
#----------------------------------------------------------------------

use strict;
use warnings;

use Crypt::RSA::Parse ();
use Math::BigInt      ();
use MIME::Base64      ();

sub get_rsa_public_jwk {
    my ($pem_or_der) = @_;

    my $rsa = Crypt::RSA::Parse::private($pem_or_der);

    my $n = _bigint_to_raw( $rsa->modulus() );
    my $e = _bigint_to_raw( Math::BigInt->new( $rsa->publicExponent() ) );

    my %jwk = (
        kty => 'RSA',
        n => MIME::Base64::encode_base64url($n),
        e => MIME::Base64::encode_base64url($e),
    );

    return \%jwk;
}

sub get_rsa_jwk_thumbprint {
    my ($pem_or_der_or_jwk) = @_;

    require Digest::SHA;

    if ('HASH' ne ref $pem_or_der_or_jwk) {
        $pem_or_der_or_jwk = get_rsa_public_jwk($pem_or_der_or_jwk);
    }

    my $jwk_hr = $pem_or_der_or_jwk;

    #Since these will always be base64url values, it’s safe to hard-code.
    my $json = qq[{"e":"$jwk_hr->{'e'}","kty":"$jwk_hr->{'kty'}","n":"$jwk_hr->{'n'}"}];

    return MIME::Base64::encode_base64url( Digest::SHA::sha256($json) );
}

sub _bigint_to_raw {
    my ($bigint) = @_;

    my $hex = $bigint->as_hex();
    $hex =~ s<\A0x><>;

    #Ensure that we have an even number of hex digits.
    if (length($hex) % 2) {
        substr($hex, 0, 0) = '0';
    }

    return pack "H*", $hex;
}

1;
