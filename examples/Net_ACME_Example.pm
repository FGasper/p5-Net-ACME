package Net_ACME_Example;

use strict;
use warnings;

use Call::Context ();

use FindBin;
use lib "$FindBin::Bin/../lib";

use Net::ACME::Crypt ();
use Net::ACME::LetsEncrypt ();

use Crypt::OpenSSL::RSA    ();
use Crypt::OpenSSL::PKCS10 ();

my $KEY_SIZE = 2_048;

my $secp256k1_key = <<END;
-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIF98YDRuGG4JhyJdAO1DAVApQp8evaTDr0UwhuG6tABkoAcGBSuBBAAK
oUQDQgAEiyeCxB7i+juH4IKyjNrLyveI2oMiCOumXLZIe+IOuKjQNpnd5tK2Nwj3
YsM1xabEPRHCHf52sX5V0SXFcO93rw==
-----END EC PRIVATE KEY-----
END

my $secp256k1_csr = <<END;
-----BEGIN CERTIFICATE REQUEST-----
MIHSMHoCAQAwGzEZMBcGA1UEAwwQZmVsaXBlZ2FzcGVyLmNvbTBWMBAGByqGSM49
AgEGBSuBBAAKA0IABIsngsQe4vo7h+CCsozay8r3iNqDIgjrply2SHviDrio0DaZ
3ebStjcI92LDNcWmxD0Rwh3+drF+VdElxXDvd6+gADAKBggqhkjOPQQDAgNIADBF
AiBttPAlXwOmwqLp/a/heDqAapyinoyRKOPtr8HrvJV6dAIhAMNgfaO2R2fCrr6V
RMvYtOunFiS2V94oxsN1I7hlMf92
-----END CERTIFICATE REQUEST-----
END

sub do_example {
    my ($handle_combination_cr) = @_;

    my $tos_url = Net::ACME::LetsEncrypt->get_terms_of_service();
    print "Look at:$/$/\t$tos_url$/$/… and hit CTRL-C if you DON’T accept these terms.$/";
    <STDIN>;

    #Safe as of 2016
    my $key_size = 2_048;

    my $reg_key     = Crypt::OpenSSL::RSA->generate_key($KEY_SIZE);
    my $reg_key_pem = $reg_key->get_private_key_string();

$reg_key_pem = '-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIALvcEgN8dcvV88MnZ2KjUYTaZvWgR7BRKI9cJQDrFTOoAoGCCqGSM49
AwEHoUQDQgAEeiMOmRczTOoW5TxAicXNQnYqFZ7bHqQQNICB7S9wup0pmPV9mpsq
fxxJ9QgjdO1aMAarxXlDjb8q7rZXs//QxQ==
-----END EC PRIVATE KEY-----';

    #Want a real cert? Then comment this out.
    {
        no warnings 'redefine';
        #*Net::ACME::LetsEncrypt::_HOST = \&Net::ACME::LetsEncrypt::STAGING_SERVER;
    }

    my $acme = Net::ACME::LetsEncrypt->new( key => $reg_key_pem );

#    my $reg = $acme->register();
#
#    $acme->accept_tos( $reg->uri(), $tos_url );

    #----------------------------------------------------------------------

    my @domains;
    while (1) {
        print 'Enter a domain for the certificate (or ENTER if you’re done): ';
        my $d = <STDIN>;
        chomp $d;
        last if !defined $d || !length $d;
        push( @domains, $d );
    }

    print $/;

    my ( $cert_key_pem, $csr_pem ) = _make_csr_for_domains(@domains);

    my $jwk = Net::ACME::Crypt::get_public_jwk( Net::ACME::Crypt::parse_key($reg_key_pem) );

    for my $domain (@domains) {
        my $authz_p = $acme->start_domain_authz($domain);

        for my $cmb_ar ( $authz_p->combinations() ) {

            my @challenges = $handle_combination_cr->( $domain, $cmb_ar, $jwk );

            next if !@challenges;

            $acme->do_challenge($_) for @challenges;

            while (1) {
                if ( $authz_p->is_time_to_poll() ) {
                    my $poll = $authz_p->poll();

                    last if $poll->status() eq 'valid';

                    if ( $poll->status() eq 'invalid' ) {
                        my @failed = map { $_->error() } $poll->challenges();

                        print $_->to_string() . $/ for @failed;

                        die "Failed authorization for “$domain”!$/";
                    }

                }

                sleep 1;
            }
        }
    }

    #Create your own CSR (e.g., using Crypt::OpenSSL::PKCS10).
    my $cert = $acme->get_certificate($csr_pem);

    #This shouldn’t actually be necessary for Let’s Encrypt,
    #but the ACME protocol describes it.
    while ( !$cert->pem() ) {
        sleep 1;
        next if !$cert->is_time_to_poll();
        $cert = $cert->poll() || $cert;
    }

    print map { "$_$/" } $cert_key_pem, $cert->pem(), $cert->issuers_pem();

    return;
}

sub _make_csr_for_domains {
return (
'-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIIOXwxhkbCvyNoiZCW8XgtuGl9IypyZBsjVrvIwfmHG1oAoGCCqGSM49
AwEHoUQDQgAEp+3jCiapNG3YNop8nfGbBmfYGyjPfExTWm8QSA/Oyxj7LX2314Ce
DXdZ5btYzG8avb9NDHvPOC9c/l1ZVEJfrw==
-----END EC PRIVATE KEY-----',
'-----BEGIN CERTIFICATE REQUEST-----
MIHUMH0CAQAwGzEZMBcGA1UEAwwQZmVsaXBlZ2FzcGVyLmNvbTBZMBMGByqGSM49
AgEGCCqGSM49AwEHA0IABKft4womqTRt2DaKfJ3xmwZn2Bsoz3xMU1pvEEgPzssY
+y19t9eAng13WeW7WMxvGr2/TQx7zzgvXP5dWVRCX6+gADAKBggqhkjOPQQDAgNH
ADBEAiBOnCyHxhyRYhDzPdWhUyRZCAWibrEqW2LTgUTbNG9mVgIgBSFWN+yDxZDG
sfp+QDwWc5ZmwM/lGoaqiNq3HvIAo28=
-----END CERTIFICATE REQUEST-----',
);

    my (@domains) = @_;
    Call::Context::must_be_list();

    my $rsa = Crypt::OpenSSL::RSA->generate_key($KEY_SIZE);

    my $req = Crypt::OpenSSL::PKCS10->new_from_rsa($rsa);
    $req->set_subject('/');

    my @san_parts = map { "DNS.$_:$domains[$_]" } 0 .. $#domains;

    $req->add_ext(
        Crypt::OpenSSL::PKCS10::NID_subject_alt_name(),
        join( ',', @san_parts ),
    );
    $req->add_ext_final();

    $req->sign();

    return ( $rsa->get_private_key_string(), $req->get_pem_req() );
}

1;
