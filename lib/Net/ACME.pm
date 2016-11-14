package Net::ACME;

=encoding utf-8

=head1 NAME

Net::ACME - Client for the ACME protocol (e.g., Let’s Encrypt)

=head1 SYNOPSIS

    package MyACME::SomeService;

    sub _HOST { }   #return the name of the ACME host

    #See the examples/ directory in the distribution for usage.

=head1 DESCRIPTION

This module implements client logic for the ACME protocol,
the system for automated issuance of SSL certificates used by Let’s Encrypt.

The methods of this class return objects that correspond to the
respective ACME resource:

=over 4

=item * C<register()>: C<Net::ACME::Registration>

=item * C<start_domain_authz()>: C<Net::ACME::Authorization::Pending>

=item * C<get_certificate()>: C<Net::ACME::Certificate> or C<Net::ACME::Certificate::Pending>

=back

=head1 EXAMPLES

See the C<examples> directory in the distribution.

=head1 TODO

=over 4

=item * Improve documentation

=item * Port tests from original cPanel module. (The meaningful ones are highly
dependent on cPanel’s testing framework.)

=item * Support EC keys.

=item * Test and support ACME v2 features (pending server support).

=back

=head1 THANKS

=over 4

=item * cPanel, Inc. for permission to adapt their ACME framework for
public consumption.

=item * Stephen Ludin for developing and maintaining C<Protocol::ACME>, from which
this module took its inspiration.

=back

=head1 REPOSITORY

L<https://github.com/FGasper/p5-Net-ACME>

=head1 AUTHOR

Felipe Gasper (FELIPE)

=cut

use strict;
use warnings;

use Crypt::Format     ();
use JSON              ();
use MIME::Base64      ();
use Types::Serialiser ();

use Net::ACME::Authorization::Pending      ();
use Net::ACME::Certificate                 ();
use Net::ACME::Certificate::Pending        ();
use Net::ACME::Constants                   ();
use Net::ACME::Challenge::Pending::http_01 ();
use Net::ACME::HTTP                        ();
use Net::ACME::Registration                ();
use Net::ACME::Utils                       ();
use Net::ACME::X                           ();

our $VERSION;
*VERSION = \$Net::ACME::Constants::VERSION;

#https://rt.cpan.org/Ticket/Display.html?id=114027
our $_ACCOMMODATE_RT114027 = 0;

*_to_base64url = \&MIME::Base64::encode_base64url;

sub new {
    my ( $class, %opts ) = @_;

    my $self = {
        _host => $class->_HOST(),
        _key  => $opts{'key'},
    };

    bless $self, $class;

    $self->_set_ua();

    return $self;
}

sub _HOST { die 'Not Implemented!' }

sub accept_tos {
    my ( $self, $reg_uri, $tos_url ) = @_;

    my $resp = $self->_post_url(
        $reg_uri,
        {
            resource  => 'reg',
            agreement => $tos_url,
        },
    );

    if ( !$_ACCOMMODATE_RT114027 ) {
        $resp->die_because_unexpected() if $resp->status() != 202;
    }

    return;
}

#Returns a Net::ACME::Registration instance whose
#terms_of_service() will be current/useful.
sub register {
    my ( $self, @contacts ) = @_;

    my $payload = {
        resource => 'new-reg',
    };

    if (@contacts) {
        $payload->{'contact'} = \@contacts;
    }

    my ( $resp, $reg_uri );

    $resp = $self->_post( 'new-reg', $payload );

    if ( !$_ACCOMMODATE_RT114027 && $resp->status() != 201 ) {
        $resp->die_because_unexpected();
    }

    $reg_uri = $resp->header('location');

    #We don’t save the terms-of-service here because the terms
    #of service might be updated between now and the next time we
    #load this data. It’s better to make the caller call
    #get_terms_of_service() each time.
    my @metadata = (
        uri => $reg_uri,
        %{ $resp->content_struct() },
    );

    #Even though we didn’t save the “terms-of-service” URL from
    #this registration object, we might as well hold onto it
    #for the current process to save a call to get_terms_of_service().
    return Net::ACME::Registration->new(
        @metadata,
        terms_of_service => { $resp->links() }->{'terms-of-service'},
    );
}

#NOTE: This doesn’t actually seem to work with Let’s Encrypt.
#The POST keeps coming back with a 202 status rather than 200.
#(Looks like Boulder doesn’t handle this function yet?)
#sub rollover_key {
#    my ($self, $reg_uri) = @_;
#
#    my $new_key = $self->create_key_pem();
#
#    my $sub_payload = {
#        resource => 'reg',
#        oldKey => $self->jwk_thumbprint(),
#    };
#
#    my $resp = $self->_post_url(
#        $reg_uri,
#        {
#            resource => 'reg',
#            newKey => Net::ACME::Utils::get_jws_data(
#                $new_key,
#                undef,
#                JSON::encode_json($sub_payload),
#            ),
#        },
#    );
#
#    if ($resp->status() != 200) {
#        die "Incorrect status: " . $resp->status() . $/ . $resp->content();
#    }
#
#    $self->{'_account_key'} = $new_key;
#    $self->_set_ua();
#
#    return $new_key;
#}

sub start_domain_authz {
    my ( $self, $domain_name ) = @_;

    my $resp = $self->_post(
        'new-authz',
        {
            resource   => 'new-authz',
            identifier => {
                type  => 'dns',
                value => $domain_name,
            },
        },
    );

    if ( !$_ACCOMMODATE_RT114027 ) {
        $resp->die_because_unexpected() if $resp->status() != 201;
    }

    my $content = $resp->content_struct();

    #my $http_challenge_index = _get_http_challenge_index($content);
    #
    #_validate_combinations_for_http_only( $content, $http_challenge_index );
    #
    #my $http_challenge_hr = $content->{'challenges'}[$http_challenge_index];

    return Net::ACME::Authorization::Pending->new(
        uri          => $resp->header('location'),
        combinations => $content->{'combinations'},
        challenges   => [
            map {
                my $class = 'Net::ACME::Challenge::Pending';
                if ( $_->{'type'} eq 'http-01' ) {
                    $class .= '::http_01';
                }
                $class->new(%$_);
              } @{ $content->{'challenges'} },
        ],
    );
}

#NOTE: This doesn’t actually work with Boulder (Let’s Encrypt) because
#that server implements acme-01. Deletion of an authz was added in acme-02.
#
#It is critical, though, that when this doesn’t work we still request the
#challenge against the authz so that the LE account doesn’t exceed a rate
#limit. (cf. COBRA-3273)
sub delete_authz {
    my ( $self, $authz ) = @_;

    #sanity
    if ( !UNIVERSAL::isa( $authz, 'Net::ACME::Authorization::Pending' ) ) {
        die "Must be a pending authz object, not “$authz”!";
    }

    my $resp = $self->_post_url(
        $authz->uri(),
        {
            resource => 'authz',
            delete   => Types::Serialiser::true(),
        },
    );

    $resp->die_because_unexpected() if $resp->status() != 200;

    return;
}

sub do_challenge {
    my ( $self, $challenge_obj ) = @_;

    my ( $token, $uri ) = map { $challenge_obj->$_() } qw( token uri );

    $self->{'_key_jwk'} ||= Net::ACME::Utils::get_jwk_data( $self->{'_key'} );

    my $resp = $self->_post_url(
        $uri,
        {
            resource         => 'challenge',
            keyAuthorization => $challenge_obj->make_key_authz( $self->{'_key_jwk'} ),
        },
    );

    $resp->die_because_unexpected() if $resp->status() != 202;

    return;
}

sub get_certificate {
    my ( $self, $csr_pem ) = @_;

    my $csr_der = Crypt::Format::pem2der($csr_pem);

    my $resp = $self->_post(
        'new-cert',
        {
            resource => 'new-cert',
            csr      => _to_base64url($csr_der),
        },
    );

    my $status = $resp->status();

    #NB: Let’s Encrypt doesn’t seem to need this,
    #but per the ACME spec it *could* work this way.
    if ( $status == 202 ) {
        my $pcert = Net::ACME::Certificate::Pending->new(
            uri         => $resp->header('location'),
            retry_after => $resp->header('retry-after'),
        );

        while (1) {
            if ( $pcert->is_time_to_poll() ) {
                my $c = $pcert->poll();
                return $c if $c;
            }
            sleep 1;
        }
    }

    if ( $status == 201 ) {
        return Net::ACME::Certificate->new(
            content         => $resp->content(),
            type            => $resp->header('content-type'),
            issuer_cert_uri => { $resp->links() }->{'up'},
        );
    }

    $resp->die_because_unexpected();

    return;
}

#This isn’t needed yet, nor is it useful because
#Let’s Encrypt (i.e., Boulder) doesn’t support it.
#Once Boulder supports this, we should switch to it
#in favor of the LE-specific logic in LetsEncrypt.pm.
#
#cf. https://ietf-wg-acme.github.io/acme/#rfc.section.6.1.1
#sub get_terms_of_service {
#    my ($self) = @_;
#
#    my $dir = $self->_get_directory();
#    my $url = $self->_get_directory()->{'meta'} or die 'No “meta” in directory!';
#    $url = $url->{'terms-of-service'} or die 'No “terms-of-service” in directory metadata!';
#
#    return $url;
#}

#----------------------------------------------------------------------

sub _set_ua {
    my ($self) = @_;
    $self->{'_ua'} = Net::ACME::HTTP->new(
        key => $self->{'_key'},
    );

    return;
}

#Find the challenge index for HTTP
sub _get_http_challenge_index {
    my ($content) = @_;

    my $http_challenge_index;

    #For now, we do this simply by just hard-coding logic
    #that only does one http-01 challenge.
    my @challenges = @{ $content->{'challenges'} };
    for ( 0 .. $#challenges ) {
        if ( $challenges[$_]->{'type'} eq 'http-01' ) {
            $http_challenge_index = $_;
            last;
        }
    }

    #This probably indicates an error in server configuration more than anything.
    if ( !defined $http_challenge_index ) {
        die Net::ACME::X->new( sprintf "This authorization does not accept [asis,HTTP] validation! (%s)", JSON::encode_json($content) );
    }

    return $http_challenge_index;
}

sub _validate_combinations_for_http_only {
    my ( $content, $http_challenge_index ) = @_;

    my $http_is_enough = ( @{ $content->{'challenges'} } == 1 );

    if ( !$http_is_enough ) {

        #Find a combination that consists exclusively of the number that
        #corresponds to the HTTP challenge.
        #NB: Per the ACME spec, no combinations means all challenges are required.
        if ( $content->{'combinations'} ) {
            for ( @{ $content->{'combinations'} } ) {
                if ( "@$_" == $http_challenge_index ) {
                    $http_is_enough = 1;
                    last;
                }
            }
        }
    }

    #This probably indicates an error in server configuration more than anything.
    if ( !$http_is_enough ) {
        die Net::ACME::X->new( sprintf "This authorization requires more than [asis,HTTP] validation! (%s)", JSON::encode_json($content) );
    }

    return;
}

#TODO: cache
sub _get_directory {
    my ($self) = @_;

    return $self->{'_directory'} ||= $self->{'_ua'}->get("https://$self->{'_host'}/directory")->content_struct();
}

sub _post {
    my ( $self, $link_name, $data ) = @_;

    my $url = $self->_get_directory()->{$link_name} or die "Unknown link name: “$link_name”";

    return $self->_post_url( $url, $data );
}

#mocked in tests
sub _post_url {
    my ( $self, $url, $data ) = @_;

    #Do this in case we haven’t initialized the directory yet.
    #Initializing the directory is necessary to get a nonce.
    $self->_get_directory();

    return $self->{'_ua'}->post( $url, $data );
}

1;
