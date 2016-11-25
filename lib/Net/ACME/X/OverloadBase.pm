package Net::ACME::X::OverloadBase;

use strict;
use warnings;

use Carp ();

use Net::ACME::EvalBug ();

my %_OVERLOADED;

sub _check_overload {
    my ( $class, $str ) = @_;

    local $@ if !Net::ACME::EvalBug::bug_exists();

    $_OVERLOADED{$class} ||= eval qq{
        package $class;
        use overload (q<""> => __PACKAGE__->can('__spew'));
        1;
    };

    #Should never happen as long as overload.pm is available.
    die if !$_OVERLOADED{$class};

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
