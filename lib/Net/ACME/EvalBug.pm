package Net::ACME::EvalBug;

use strict;
use warnings;

my $_exists;

#This bug was fixed in 5.12. Since 5.12 was out of support before this
#module came into existence, there’s no point in filing an RT case for it.
sub bug_exists {
    if (!defined $_exists) {
        local $@;
        eval {
            local $@;
            die 123;
        };
        $_exists = $@ ? 0 : 1;
    }

    return $_exists;
}

1;
