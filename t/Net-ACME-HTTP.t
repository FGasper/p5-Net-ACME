package t::Net::ACME::HTTP;

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

use JSON ();

use Crypt::JWT               ();
use HTTP::Tiny::UA::Response ();

use Net::ACME::EvalBug ();
use Net::ACME::HTTP ();

use JSON      ();
use Crypt::OpenSSL::RSA ();

use Net::ACME::X ();

if ( !caller ) {
    my $test_obj = __PACKAGE__->new();
    plan tests => $test_obj->expected_tests(+1);
    $test_obj->runtests();
}

#----------------------------------------------------------------------

sub test_get_and_post : Tests(8) {
    my ($self) = @_;

    my $key_pem = Crypt::OpenSSL::RSA->generate_key(2048)->get_private_key_string();

    my $ua = Net::ACME::HTTP->new(
        key => $key_pem,
    );

    throws_ok(
        sub { $ua->post( 'no importa', { haha => 1 } ) },
        qr<nonce>,
        'post() before nonce is set dies',
    );

    my $server_err = Net::ACME::X::create(
        'HTTP::Protocol',
        {
            method  => 'HAHA',
            url     => 'http://the/url',
            status  => '400',
            reason  => 'Generic',
            headers => {
                $Net::ACME::HTTP::_NONCE_HEADER => '123123',
                BlahBlah                           => 'ohh',
            },
            content => JSON::encode_json(
                {
                    type   => 'urn:ietf:params:acme:error:malformed',
                    detail => 'fofo',
                },
            ),
        }
    );

    #A nonsense request. Simplest case, doesn’t return anything useful.
    #----------------------------------------------------------------------
    throws_ok(
        sub { $ua->get('http://isbvuhsvmdhvhbdm.asyichrsuihvr') },
        'Net::ACME::X::HTTP::Network',
        'get() to server that doesn’t exist',
    );

    my @request_args;
    my $ua_request_cr;

    no warnings 'redefine';
    local *Net::ACME::HTTP::_ua_request = sub {
        my ( $self, @args ) = @_;

        @request_args = @args;

        return $ua_request_cr->(@args);
    };

    #A get() that the server will reject.
    #----------------------------------------------------------------------

    $ua_request_cr = sub { die $server_err };

    throws_ok(
        sub { $ua->get('doesn’t matter') },
        'Net::ACME::X::Protocol',
        'HTTP::Server error converts to Protocol',
    );
    my $err = $@;

    is_deeply(
        \@request_args,
        [ 'get', 'doesn’t matter' ],
        'get() passes args to UA request()',
    );

    cmp_deeply(
        $err,
        methods(
            [ get => 'url' ]     => 'http://the/url',
            [ get => 'status' ]  => '400',
            [ get => 'reason' ]  => 'Generic',
            [ get => 'headers' ] => superhashof( { BlahBlah => 'ohh' } ),
            [ get => 'type' ]    => 'urn:ietf:params:acme:error:malformed',
            [ get => 'detail' ]  => re(qr<\Afofo\s+\(.+\)\z>),
        ),
        'Protocol error method returns',
    ) or diag explain $err;

    #A post() that the server will accept.
    #----------------------------------------------------------------------

    $ua_request_cr = sub {
        return HTTP::Tiny::UA::Response->new(
            {
                headers => {
                    $Net::ACME::HTTP::_NONCE_HEADER => '234234',
                },
            }
        );
    };
    $ua->post( 'doesn’t matter', { foo => 123 } );

    my $jwt = $request_args[2]->{'content'};

    my ( $header, $payload ) = Crypt::JWT::decode_jwt(
        token         => $jwt,
        key           => \$key_pem,
        decode_header => 1,
    );

    is(
        $header->{'nonce'},
        123123,
        'after an error, JWS sent to post() includes the previous result’s nonce',
    ) or diag explain $header;

    cmp_deeply(
        $payload,
        { foo => 123 },
        'JWS sent to post() includes the payload',
    ) or diag explain $payload;

    #A post() that the server will reject.
    #----------------------------------------------------------------------

    $ua_request_cr = sub { die $server_err };

    local $@ if !Net::ACME::EvalBug::bug_exists();

    eval { $ua->post( 'doesn’t matter', { foo => 123 } ) };

    $jwt = $request_args[2]->{'content'};

    ( $header, $payload ) = Crypt::JWT::decode_jwt(
        token         => $jwt,
        key           => \$key_pem,
        decode_header => 1,
    );

    is(
        $header->{'nonce'},
        234234,
        'after success, JWS sent to post() includes the previous result’s nonce',
    ) or diag explain $header;

    return;
}

1;
