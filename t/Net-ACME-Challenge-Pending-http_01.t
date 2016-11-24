package t::Net::ACME::Challenge::Pending::HTTP_01;

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

use File::Temp ();

use Net::ACME::Challenge::Pending::http_01 ();

use Net::ACME::Constants ();
use Net::ACME::Utils     ();

use Crypt::OpenSSL::RSA             ();

if ( !caller ) {
    my $test_obj = __PACKAGE__->new();
    plan tests => $test_obj->expected_tests(+1);
    $test_obj->runtests();
}

#----------------------------------------------------------------------

sub do_tests : Tests(4) {
    my ($self) = @_;

    my $challenge = Net::ACME::Challenge::Pending::http_01->new(
        token => 'the_token',
        uri   => 'http://the/challenge/uri',
    );

    is( $challenge->token(), 'the_token', 'token()' );
    is( $challenge->uri(), 'http://the/challenge/uri', 'uri()' );

    my $key_pem = Crypt::OpenSSL::RSA->generate_key(2048)->get_private_key_string();
    my $jwk     = Net::ACME::Utils::get_jwk_data($key_pem);

    my $scratch_dir = File::Temp::tempdir( CLEANUP => 1 );

    my $handler = $challenge->create_handler(
        $scratch_dir,
        $jwk,
    );

    my $dir = File::Temp::tempdir( CLEANUP => 1 );

    my $relative_path = "$Net::ACME::Constants::HTTP_01_CHALLENGE_DCV_DIR_IN_DOCROOT/the_token";

    ok(
        ( -e "$scratch_dir/$relative_path" ),
        'DCV file exists',
    );

    undef $handler;

    ok(
        !( -e "$scratch_dir/$relative_path" ),
        'after handler DESTROYed, DCV file is gone',
    );

    return;
}

sub _RSA_PEM {
    return <<END;
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAoy7y6JWNyIu/nAAAY4WE40sWefdwXZinEJDXvEepThFsndU7
vN/Yamy081Bf9F4KUsjZtMir+vwZL4ImOvnUUcXVa+OtrCQC6TnS7znNF6qAvdKf
EA9XfEzHWgDMCG1MrnWX4EWa/+Ragh3DLYEG+xH+EJw1L1rW0yHLKUZTo+4QW6OT
LVWpnVH8mYSmj0OIsOGGpgVO6HyYJNTYUJz0l8Uuaef3urlIW0Ai8etqvvQOJfX9
DEgq0LjYynTw7ZVPa1kxgnkxwtuU6QGkvpgo3IMjwiJ2a9XR7jzEKY7an4I087lP
3wKs9OmppieKSZrFp4uGVNT+ieKIn7rHTOfjsQIDAQABAoIBAQCCl7AOMqGlPTG6
xsWI3/HZdN4n/b4PKXuJ5mDAbRkxQQCLz3pfTUUE5rppfolMJ3ZbiiGwbGg2FEqT
mrS9vfIM/yYtkagLe0ZZH82PZdKcffdJ8qUZVS3ObCOeA8VFeTNE6xcAhLPm1fkY
6HiqkffkNiH9aQWnQCtsDD9qaL3HEhcSlEw62+gtXS2tPKaJuHf9+MUM9jzmNk6E
VBZkSpdt5H0ykblu3HPQGqTg9j/csfZcI6xshnuLREp2Kz2Rtls8JeZvDX7ljUMU
6sZ5D6HxTB9nV08wCIMQvW+t4141wR10/5hUKkV16VkMw4zfw+M2qzwj97EVqjQS
EU+w+meBAoGBANAvvvDsIEyyDWRK7cz7pMaFeLlCCmK1QJSfQOpdj4IstDklLdSj
pHF77s1OAXPzrAz02jXz15EsMs9Q5/OFxCkzske+JCPNYlIiAo64b6yw8XRDvuvv
JXajnoRapNZ7rAoHRwmeEPTlfIwB9e8L06dtdECXKOtMhCidaUxYhDvvAoGBAMip
QqrtcwtXU8UVX04QvEVDEaHI51m1Z82BWRIRMWRlxo5hjMhW24Dnrnqt7x1H/ghO
0HN0CGFTndQVez5liHTZJlqXkFb20e+sEEoseULXx/WHfkvRYsqwnA99SdwIMZpW
XAeuHDwK0wlidAT3uLvaHjWULyyiSs2ssseiVrpfAoGAH4S7AbqeAT6LrH1zly8Z
+TxH1LRc4ijSyC18JH9ZtLmT53rrf1/vC4dZ1hdTPPzNNYD0cGqkXkQ0xRJYq5O6
6Qn8mcP9sLXthsXDYVwm/Bwl0hZXl1yzbUzEOQGIJzi+CR6k8J3Pr2P3ATNiyngd
6SE3EnhQJ5+D+qoqQPa9vl0CgYBZaerWJZa1AAXI9VwRei2ao2cw80f71nTZwwCA
p36d4SgX++nyv5lyGErMScMaBiFxbEVAnPy6+bqDbcsMI8wpXTXU+mKMDdHAfaiI
lMa3/VUR2H1zpWrjLM1trYOC83e+8SpzFadpLd2Z+e/+4q/DrU72ywA2YF76xTCo
+nKw+wKBgCe44PGXDRmPu0DLHv+2SJNlPOHrV4NVxAdQwJ2lV8qlp1okL56X2z4f
e9xXbDAqx4LKOow0g12+9Qs0rzrEdIMYag9tm6kxTyiR75eraT79Zl4MO85wbwvO
18kfmSCPOlYcLkAYpWOMteLoIYremiHvmPSHvL5i15ic7dtQxq8e
-----END RSA PRIVATE KEY-----
END
}

1;
