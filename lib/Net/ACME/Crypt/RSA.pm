package Net::ACME::Crypt::RSA;

use strict;
use warnings;

use Try::Tiny;

use Digest::SHA ();
use MIME::Base64 ();
use Module::Load ();

use Crypt::Perl::RSA::Parse ();

*_encode_b64u = \&MIME::Base64::encode_base64url;

my $_C_O_R_failed;
my $_C_O_R_succeeded;

#$key is PEM or DER
sub sign_RS256 {
    my ($msg, $key) = @_;

    #OpenSSL will do this faster.
    if ( !$_C_O_R_failed ) {
        if (!$_C_O_R_succeeded) {
            $_C_O_R_succeeded = try { Module::Load::load('Crypt::OpenSSL::RSA'); 1 };
        }

        if ($_C_O_R_succeeded) {
            my $rsa = Crypt::OpenSSL::RSA->new_private_key($key->to_pem());
            $rsa->use_sha256_hash();
            return $rsa->sign($msg);
        }
    }

    #No use in continuing to try.
    $_C_O_R_failed = 1;

#    elsif ( !$_no_openssl_bin ) {
#
#
#        $OPENSSL_BIN_PATH ||= File::Which::which('openssl');
#        if ($OPENSSL_BIN_PATH) {
#            return _sign_with_key_via_openssl_binary($msg, $key);
#        }
#    }

    return Crypt::Perl::RSA::Parse::private($key)->sign_RS256($msg);
}

sub get_public_jwk {
    my ($pem_or_der_or_obj) = @_;

    my $rsa;

    if (ref $pem_or_der_or_obj) {
        $rsa = $pem_or_der_or_obj;
    }
    else {
        $rsa = Crypt::Perl::RSA::Parse::private($pem_or_der_or_obj);
    }

    my $n = $rsa->modulus()->as_bytes();
    my $e = $rsa->publicExponent()->as_bytes();

    my %jwk = (
        kty => 'RSA',
        n => _encode_b64u($n),
        e => _encode_b64u($e),
    );

    return \%jwk;
}

#sub _try_to_load_module {
#    my ($module) = @_;
#
#    my $eval_err = $@;
#
#    #It’ll only try once, so the slowness is no big deal.
#    my $ok = eval "require $module";
#
#    $@ = $eval_err;
#
#    return $ok;
#}

#sub _sign_with_key_via_openssl_binary {
#    my ($msg, $key) = @_;
#
#    require File::Temp;
#
#    my ($fh, $path) = File::Temp::tempfile( CLEANUP => 1 );
#    print {$fh} $key or die "write($path): $!";
#    close $fh;
#
#    my ($d_fh, $d_path) = File::Temp::tempfile( CLEANUP => 1 );
#    print {$d_fh} $msg or die "write($d_path): $!";
#    close $d_fh;
#
#    #Works across exec().
#    local $?;
#
#    my $sig = qx/$OPENSSL_BIN_PATH dgst -sha256 -sign $path $d_path/;
#    die if $?;
#
#    return $sig;
#}

1;
