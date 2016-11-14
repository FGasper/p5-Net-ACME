package Net::ACME::Registration;

use strict;
use warnings;

use parent qw( Class::Accessor::Fast );

my @params;

BEGIN {

    #Expand this as needed.
    @params = qw(
      key
      uri
      agreement
      terms_of_service
    );

    __PACKAGE__->mk_ro_accessors(@params);
}

sub new {
    my ( $class, %opts ) = @_;

    %opts = map { ( $_ => $opts{$_} ) } @params;

    return $class->SUPER::new( \%opts );
}

1;
