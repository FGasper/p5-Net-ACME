package Net::ACME::X::UnexpectedResponse;

use strict;
use warnings;

use parent qw( Net::ACME::X::HashBase );

#named args required:
#
#   url
#   status
#   reason
#
#optional:
#   headers
#
sub new {
    my ( $self, $args_hr ) = @_;

    return $self->SUPER::new(
        "The [asis,ACME] function “$args_hr->{'url'}” returned an unexpected status: “$args_hr->{'status'}” ($args_hr->{'reason'}).",
        $args_hr,
    );
}

1;
