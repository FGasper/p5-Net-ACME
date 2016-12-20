package Net::ACME::Crypt;

#----------------------------------------------------------------------
# This module exists because of a desire to do these computations
# in environments where a compiler may not be available.
# (Otherwise, CryptX would be ideal.)
#----------------------------------------------------------------------

use strict;
use warnings;

use Digest::SHA       ();
use JSON              ();
use Module::Load ();
use MIME::Base64      ();

use Crypt::Perl::RSA::Parse ();

use Net::ACME::Crypt::RSA ();
use Net::ACME::X ();

#As per the ACME spec
use constant JWK_THUMBPRINT_DIGEST => 'sha256';

sub parse_key {
    my ($pem) = @_;

    my $eval_err = $@;

    my $obj = eval { Crypt::Perl::RSA::Parse::private($pem) };
    if (!$obj) {
        my $rsa_err = $@;

        Module::Load::load('Crypt::Perl::ECDSA::Parse');

        $obj = eval { Crypt::Perl::ECDSA::Parse::private($pem) };

        #TODO: Check for a specific parse error.
        if (!$obj) {
            die Net::ACME::X::Create('UnrecognizedKey', $pem);
        }
    }

    $@ = $eval_err;

    return $obj;
}

sub get_public_jwk {
    my ($key_obj) = @_;

    if ( $key_obj->isa('Crypt::Perl::RSA::PrivateKey') ) {
        return Net::ACME::Crypt::RSA::get_public_jwk($key_obj);
    }

    Module::Load::load('Net::ACME::Crypt::ECDSA');

    return $key_obj->get_struct_for_public_jwk();
}

sub get_jwk_thumbprint {
    my ($pem_or_der_or_jwk) = @_;

    Module::Load::load('Crypt::Perl::PK');

    my $func;

    if ('HASH' eq ref $pem_or_der_or_jwk) {
        $func = 'parse_jwk';
    }
    else {
        $func = 'parse_key';
    }

    my $key_obj = Crypt::Perl::PK->can($func)->($pem_or_der_or_jwk);

    return $key_obj->get_jwk_thumbprint(JWK_THUMBPRINT_DIGEST());
}

*_encode_b64u = \&MIME::Base64::encode_base64url;

*get_rsa_public_jwk = \&Net::ACME::Crypt::RSA::get_public_jwk;

sub create_jwt {
    my (%args) = @_;

    if ($args{'key'}->isa('Crypt::Perl::RSA::PrivateKey')) {
        return create_rs256_jwt(%args);
    }
    elsif ($args{'key'}->isa('Crypt::Perl::ECDSA::PrivateKey')) {
        return create_ecc_jwt(%args);
    }

    die "Unrecognized “key”: “$args{'key'}”";
}

#Based on Crypt::JWT::encode_jwt(), but focused on this particular
#protocol’s needs. Note that UTF-8 will probably get mangled in here,
#but that’s not a problem since ACME shouldn’t require sending raw UTF-8.
sub create_rs256_jwt {
    my ( @args ) = @_;

    my $alg = 'RS256';

    return _create_jwt(
        @args,
        alg => $alg,
        signer_cr => Net::ACME::Crypt::RSA->can("sign_$alg"),
    );
}

sub create_ecc_jwt {
    my (%args) = @_;

    Module::Load::load('Net::ACME::Crypt::ECDSA');

    my $key = $args{'key'};

    my $signer_cr = sub {
        my ($message) = @_;
        return $key->sign_jwa($message);
    };

    return _create_jwt(
        %args,
        alg => $key->get_jwa_alg(),
        signer_cr => $signer_cr,
    );
}

#----------------------------------------------------------------------

sub _create_jwt {
    my ( %args ) = @_;

    # key
    die "JWS: missing 'key'" if !$args{key};

    my $payload = $args{payload};
    my $alg     = $args{'alg'};

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

    my $signer_cr = $args{'signer_cr'};

    my $b64u_signature = _encode_b64u( $signer_cr->("$b64u_header.$b64u_payload", $args{key}) );

    return join('.', $b64u_header, $b64u_payload, $b64u_signature);
}

sub _encode_json {
    my ($payload) = @_;

    #Always do a canonical encode so that we can test more easily.
    #Note that JWS itself does NOT require this.
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

    return pack 'H*', $hex;
}

1;
