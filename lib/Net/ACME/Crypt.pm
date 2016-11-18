package Net::ACME::Crypt;

#----------------------------------------------------------------------
# This module exists because of a desire to do these computations
# in pure Perl, for environments where a compiler may not be available.
# (Otherwise, CryptX would be ideal.)
#----------------------------------------------------------------------

use strict;
use warnings;

use Crypt::RSA::Parse ();
use Digest::SHA ();
use Math::BigInt      ();
use MIME::Base64      ();

#Our one non-core, non-pure-Perl dependency …
use Crypt::OpenSSL::RSA ();

*_encode_b64u = \&MIME::Base64::encode_base64url;

sub get_rsa_public_jwk {
    my ($pem_or_der) = @_;

    my $rsa = Crypt::RSA::Parse::private($pem_or_der);

    my $n = _bigint_to_raw( $rsa->modulus() );
    my $e = _bigint_to_raw( Math::BigInt->new( $rsa->publicExponent() ) );

    my %jwk = (
        kty => 'RSA',
        n => _encode_b64u($n),
        e => _encode_b64u($e),
    );

    return \%jwk;
}

sub get_rsa_jwk_thumbprint {
    my ($pem_or_der_or_jwk) = @_;

    if ('HASH' ne ref $pem_or_der_or_jwk) {
        $pem_or_der_or_jwk = get_rsa_public_jwk($pem_or_der_or_jwk);
    }

    my $jwk_hr = $pem_or_der_or_jwk;

    #Since these will always be base64url values, it’s safe to hard-code.
    my $json = qq[{"e":"$jwk_hr->{'e'}","kty":"$jwk_hr->{'kty'}","n":"$jwk_hr->{'n'}"}];

    return _encode_b64u( Digest::SHA::sha256($json) );
}

#Based on Crypt::JWT::encode_jwt(), but focused on this particular
#protocol’s needs.
sub create_rs256_jwt {
    my ( %args ) = @_;

    # key
    die "JWS: missing 'key'" if !$args{key};

    my $rsa = Crypt::OpenSSL::RSA->new_private_key($args{'key'});
    $rsa->use_sha256_hash();

    my $payload = $args{payload};
    my $alg     = 'RS256';

    my $header  = $args{extra_headers} ? { %{$args{extra_headers}} } : {};

    # serialize payload
    $payload = _payload_enc($payload);

    # encode payload
    my $b64u_payload = _encode_b64u($payload);

    # prepare header
    $header->{alg} = $alg;

    # encode header
    my $json_header = _encode_json($header);
    my $b64u_header = _encode_b64u($json_header);

    my $b64u_signature = _encode_b64u( $rsa->sign("$b64u_header.$b64u_payload") );

    return join('.', $b64u_header, $b64u_payload, $b64u_signature);
}

#----------------------------------------------------------------------

sub _encode_json {
    my ($payload) = @_;

    return JSON->new()->canonical(1)->encode($payload);
}

#Taken from Crypt::JWT
sub _payload_enc {
    my ($payload) = @_;

    if (ref($payload) =~ /^(?:HASH|ARRAY)$/) {
        $payload = _encode_json($payload);
    }
    else {
        utf8::downgrade($payload, 1) or die "JWT: payload cannot contain wide character";
    }

    return $payload;
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
