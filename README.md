# NAME

Net::ACME - Client for the (old) ACME protocol (e.g., [Let’s Encrypt](http://letsencrypt.org))

  

# SYNOPSIS

    package MyACME::SomeService;

    use constant _HOST => ...;   #the name of the ACME host

    #See below for full examples.

# END-OF-LIFE WARNING

**WARNING:** Let’s Encrypt has announced [end-of-life for their API
that uses this protocol](https://community.letsencrypt.org/t/end-of-life-plan-for-acmev1/88430). All applications that use this module should migrate to
[Net::ACME2](https://metacpan.org/pod/Net::ACME2). Further use of this module is discouraged.

# DESCRIPTION

This module implements client logic (including SSL certificate issuance)
for the “draft” version of the ACME protocol,
the system for automated issuance of SSL certificates used by
[Let’s Encrypt](http://letsencrypt.org).

For support of the [IETF](http://ietf.org)-standard version of this
protocol, look at [Net::ACME2](https://metacpan.org/pod/Net::ACME2).

The methods of this class return objects that correspond to the
respective ACME resource:

- `register()`: `Net::ACME::Registration`
- `start_domain_authz()`: `Net::ACME::Authorization::Pending`
- `get_certificate()`: `Net::ACME::Certificate` or `Net::ACME::Certificate::Pending`

# WHY USE THIS MODULE?

- Closely based on cPanel’s widely-used Let’s Encrypt plugin.
- Support for both RSA and ECDSA encryption (via [Crypt::Perl](https://metacpan.org/pod/Crypt::Perl)).
- Thorough error-checking: any deviation from what the ACME protocol
expects is reported immediately via an exception.
- Well-defined object system, including typed, queryable exceptions.
- Extensive test coverage.
- Light memory footprint - no Moose/Moo/etc.
- No careless overwriting of globals like `$@`, `$!`, and `$?`.
(Hopefully your code isn’t susceptible to this anyway, but it’s just a good
precaution.)
- This is a pure-Perl solution. Most of its dependencies are
either core modules or pure Perl themselves. XS is necessary to
communicate with the ACME server via TLS; however, most Perl installations
already include the necessary logic (i.e., [Net::SSLeay](https://metacpan.org/pod/Net::SSLeay)) for TLS.

    In short, Net::ACME will run anywhere that Perl can speak TLS, which is
    _almost_ everywhere that Perl runs.

# STATUS

This module is now well-tested and should be safe for use in your application.

# CUSTOMIZATION

**HTTPS options**: This module uses `HTTP::Tiny` for its network operations.
In some instances it is desirable to specify custom `SSL_options` in that
module’s constructor; to do this, populate
`@Net::ACME::HTTP_Tiny::SSL_OPTIONS`.

# URI vs. URL

This module uses “uri” for ACME-related objects and “url” for
HTTP-related ones. This apparent conflict is a result of maintaining
consistency with both the ACME specification (“uri”) and [HTTP::Tiny](https://metacpan.org/pod/HTTP::Tiny) (“url”).

# EXAMPLES

See the `examples` directory in the distribution for complete, interactive
example scripts that also illustrate a bit of how ACME works.

See below for cut-paste-y examples.

# EXAMPLE: REGISTRATION

    my $tos_url = Net::ACME::LetsEncrypt->get_terms_of_service();

    my $acme = Net::ACME::LetsEncrypt->new( key => $reg_rsa_pem );

    #Use this method any time you want to update contact information,
    #not just when you set up a new account.
    my $reg = $acme->register('mailto:me@example.com', 'mailto:who@example.com');

    $acme->accept_tos( $reg->uri(), $tos_url );

# EXAMPLE: DOMAIN AUTHORIZATION & CERTIFICATE PROCUREMENT

    for my $domain (@domains) {
        my $authz_p = $acme->start_domain_authz($domain);

        for my $cmb_ar ( $authz_p->combinations() ) {

            #$cmb_ar is a set of challenges that the ACME server will
            #accept as proof of domain control. As of November 2016, these
            #sets all contain exactly one challenge each: “http-01”, etc.

            #Each member of @$cmb_ar is an instance of
            #Net::ACME::Challenge::Pending--maybe a subclass thereof such as
            #Net::ACME::Challenge::Pending::http_01.

            #At this point, you examine $cmb_ar and determine if this
            #combination is one that you’re interested in. You might try
            #something like:
            #
            #   next if @$cmb_ar > 1;
            #   next if $cmb_ar->[0]->type() ne 'http-01';

            #Once you’ve examined $cmb_ar and set up the appropriate response(s),
            #it’s time to tell the ACME server to send its challenge query.
            $acme->do_challenge($_) for @$cmb_ar;

            while (1) {
                if ( $authz_p->is_time_to_poll() ) {
                    my $poll = $authz_p->poll();

                    last if $poll->status() eq 'valid';

                    if ( $poll->status() eq 'invalid' ) {
                        my @failed = map { $_->error() } $poll->challenges();

                        warn $_->to_string() . $/ for @failed;

                        die "Failed authorization for “$domain”!";
                    }

                }

                sleep 1;
            }
        }
    }

    #Make a key and CSR.
    #Creation of CSRs is well-documented so won’t be discussed here.

    my $cert = $acme->get_certificate($csr_pem);

    #This shouldn’t actually be necessary for Let’s Encrypt,
    #but the ACME protocol describes it.
    while ( !$cert->pem() ) {
        sleep 1;
        next if !$cert->is_time_to_poll();
        $cert = $cert->poll() || $cert;
    }

# TODO

- Once the [ACME specification](https://tools.ietf.org/html/draft-ietf-acme-acme)
is finalized, update this module to take advantage of the full specification.
As Let’s Encrypt’s [Boulder](https://github.com/letsencrypt/boulder) is currently
the only widely-used ACME server, and that software is compatible with
[the first draft of the ACME spec](https://tools.ietf.org/html/draft-ietf-acme-acme-01),
there’s little reason to update for the time being.

# THANKS

- cPanel, Inc. for permission to adapt their ACME framework for
public consumption.
- Stephen Ludin for developing and maintaining [Protocol::ACME](https://metacpan.org/pod/Protocol::ACME), from which
this module took its inspiration.

# SEE ALSO

For support of the version of this protocol codified in
[RFC 8555](https://www.rfc-editor.org/rfc/rfc8555.txt), look at
[Net::ACME2](https://metacpan.org/pod/Net::ACME2).

I am aware of the following additional CPAN modules that implement
the draft ACME protocol:

- [Protocol::ACME](https://metacpan.org/pod/Protocol::ACME)
- [Crypt::LE](https://metacpan.org/pod/Crypt::LE)
- [WWW::LetsEncrypt](https://metacpan.org/pod/WWW::LetsEncrypt)
- [Mojo::ACME](https://metacpan.org/pod/Mojo::ACME)

# REPOSITORY (FEEDBACK/BUGS)

[https://github.com/FGasper/p5-Net-ACME](https://github.com/FGasper/p5-Net-ACME)

# AUTHOR

Felipe Gasper (FELIPE)

# LICENSE

This module is licensed under the same terms as Perl.
