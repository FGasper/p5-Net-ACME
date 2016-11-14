package Net::ACME::X::OverloadBase;

use strict;
use warnings;

use Carp ();

my $_OVERLOADED;

sub _check_overload {
    my ( $class, $str ) = @_;

    $_OVERLOADED ||= eval qq{
        package $class;
        use overload (q<""> => __PACKAGE__->can('__spew'));
    };

    return;
}

sub __spew {
    my ($self) = @_;

    my $spew = $self->to_string();

    if ( substr( $spew, -1 ) ne "\n" ) {
        $spew .= Carp::longmess();
    }

    return $spew;
}

1;
