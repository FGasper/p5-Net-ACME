package t::Net::ACME::Authorization::Pending;

use strict;
use warnings;

BEGIN {
    if ( $^V ge v5.10.1 ) {
        require autodie;
    }
}

use parent qw(
  Test::Class
);

use Test::More;
use Test::NoWarnings;
use Test::Deep;
use Test::Exception;

use Crypt::PK::RSA      ();
use MIME::Base64        ();

use Net::ACME::Utils ();

use Crypt::OpenSSL::Bignum ();
use Crypt::OpenSSL::RSA ();

if ( !caller ) {
    my $test_obj = __PACKAGE__->new();
    plan tests => $test_obj->expected_tests(+1);
    $test_obj->runtests();
}

#----------------------------------------------------------------------

sub test_verify_token : Tests(3) {
    throws_ok(
        sub { Net::ACME::Utils::verify_token('invalid/token') },
        'Net::ACME::X::InvalidParameter',
        'invalid token exception',
    );
    my $err = $@;

    like( $err->to_string(), qr<invalid/token>, '… and the invalid token is in the message' );

    lives_ok(
        sub { Net::ACME::Utils::verify_token('valid_-token') },
        'valid token',
    );

    return;
}

sub test_get_jwk_data : Tests(1) {
    my $rsa = Crypt::OpenSSL::RSA->generate_key(2048);

    my ( $modulus, $pub_exp ) = map { $_->to_bin() } $rsa->get_key_parameters();

    is_deeply(
        Net::ACME::Utils::get_jwk_data($rsa->get_private_key_string()),
        {
            kty => 'RSA',
            n   => MIME::Base64::encode_base64url($modulus),
            e   => MIME::Base64::encode_base64url($pub_exp),
        },
        'structure as expected',
    );

    return;
}

sub test_get_jwk_thumbprint : Tests(1) {
    my $pem        = Crypt::OpenSSL::RSA->generate_key(2048)->get_private_key_string();
    my $thumbprint = Crypt::PK::RSA->new( \$pem )->export_key_jwk_thumbprint('SHA256');

    my $jwk_data = Net::ACME::Utils::get_jwk_data($pem);

    is(
        Net::ACME::Utils::get_jwk_thumbprint($jwk_data),
        $thumbprint,
        'get_jwk_thumbprint()',
    );

    return;
}

1;
