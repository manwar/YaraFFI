package YaraFFI::Record::YR_RULE;

$YaraFFI::Record::YR_RULE::VERSION   = '0.02';
$YaraFFI::Record::YR_RULE::AUTHORITY = 'cpan:MANWAR';

=head1 NAME

YaraFFI::Record::YR_RULE - YR_RULE for YaraFFI

=head1 VERSION

Version 0.02

=cut

use v5.14;
use strict;
use warnings;
use FFI::Platypus::Record;

record_layout
(
  string => 'identifier',
);

1;
