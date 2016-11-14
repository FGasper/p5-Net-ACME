package Net::ACME::X::Empty;

use strict;
use warnings;

use parent qw( Net::ACME::X::StringBase );

sub new {
    my ( $class, $args_hr ) = @_;

    my $str;

    if ( length $args_hr->{'name'} ) {
        $str = "“$args_hr->{'name'}” cannot be empty!";
    }
    else {
        $str = 'This value cannot be empty!';
    }

    return $class->SUPER::new($str);
}

1;
