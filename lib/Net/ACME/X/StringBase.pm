package Net::ACME::X::StringBase;

use strict;
use warnings;

use parent qw( Net::ACME::X::OverloadBase );

sub new {
    my ( $class, $str ) = @_;

    $class->_check_overload();

    #Use a string literal so that the value can’t change.
    return bless \"$str", $class;
}

sub to_string { return ${ $_[0] } }

1;
