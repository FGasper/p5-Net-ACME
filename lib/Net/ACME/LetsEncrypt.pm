package Net::ACME::LetsEncrypt;

use strict;
use warnings;

use parent qw( Net::ACME );

use constant {
    STAGING_SERVER    => 'acme-staging.api.letsencrypt.org',
    PRODUCTION_SERVER => 'acme-v01.api.letsencrypt.org',
};

*_HOST = *PRODUCTION_SERVER;

1;
