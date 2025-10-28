#!/usr/bin/env perl

use v5.14;
use strict;
use warnings FATAL => 'all';
use Test::More tests => 2;

BEGIN {
    use_ok('YaraFFI')                  || print "Bail out!\n";
    use_ok('YaraFFI::Record::YR_RULE') || print "Bail out!\n";
}

diag("Testing YaraFFI $YaraFFI::VERSION, Perl $], $^X");
