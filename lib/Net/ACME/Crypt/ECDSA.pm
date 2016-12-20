package Net::ACME::Crypt::ECDSA;

use strict;
use warnings;

use MIME::Base64 ();

use constant JWK_CURVE_prime256v1 => 'P-256';
use constant JWK_CURVE_secp384r1 => 'P-384';
use constant JWK_CURVE_secp521r1 => 'P-521';

*_encode_b64u = \&MIME::Base64::encode_base64url;

sub jwk_curve_name {
    my ($key_obj) = @_;

    my $name = $key_obj->get_curve_name();

    my $getter_cr = __PACKAGE__->can("JWK_CURVE_$name") or do {
        die "Curve “$name” is not named in the JWK specification!";
    };

    return $getter_cr->();
}

1;
