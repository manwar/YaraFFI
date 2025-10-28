package YaraFFI;

$YaraFFI::VERSION   = '0.01';
$YaraFFI::AUTHORITY = 'cpan:MANWAR';

=head1 NAME

YaraFFI - Minimal Perl FFI bindings for the YARA malware scanning engine

=head1 VERSION

Version 0.01

=head1 SYNOPSIS

    use YaraFFI;
    my $yara = YaraFFI->new;
    $yara->compile($rules);
    $yara->scan_mem($data, sub {
        my ($event) = @_;
        say "Matched: $event";
    });

=head1 DESCRIPTION

YaraFFI provides lightweight FFI bindings to libyara, allowing you to compile
YARA rules from strings and scan memory buffers or files. It supports basic
rule_match and string_match events via a Perl callback.

Currently it focuses on correctness and minimal functionality, not full YARA
feature coverage.

=head1 FEATURES

=over 4

=item * Compile YARA rules from string

=item * Scan in-memory buffers (C<scan_mem>)

=item * Scan files (C<scan_file>)

=item * Events passed to callback are simple objects (rule_match, string_match)

=back

=head1 NOT YET IMPLEMENTED

=over 4

=item * No match offset or metadata reporting

=item * No support for YARA modules or external variables

=item * No NOT_MATCH, IMPORT, or FINISHED events

=item * Scan flags currently hardcoded to 0

=back

=cut

use v5.14;
use strict;
use warnings;
use FFI::Platypus 2.00;
use File::Slurp qw(read_file);

# Event class that stringifies to rule name but also works as a hash
package YaraFFI::Event {
    use overload '""' => sub { $_[0]->{rule} }, fallback => 1;

    sub new {
        my ($class, %args) = @_;
        return bless \%args, $class;
    }
}

package YaraFFI;

my $ffi = FFI::Platypus->new(api => 2);
$ffi->lib("libyara.so");

# Attach YARA functions
$ffi->attach('yr_initialize'          => [] => 'int');
$ffi->attach('yr_finalize'            => [] => 'int');
$ffi->attach('yr_compiler_create'     => ['opaque*'] => 'int');
$ffi->attach('yr_compiler_destroy'    => ['opaque' ] => 'void');
$ffi->attach('yr_compiler_add_string' => ['opaque', 'string', 'string'] => 'int');
$ffi->attach('yr_compiler_get_rules'  => ['opaque', 'opaque*'] => 'int');
$ffi->attach('yr_rules_destroy'       => ['opaque'] => 'void');

# Callback signature: int callback(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data)
$ffi->attach('yr_rules_scan_mem' => ['opaque', 'opaque', 'size_t', 'int', '(opaque, int, opaque, opaque)->int', 'opaque', 'int'] => 'int');

# Define constants for YARA callback messages
use constant {
    CALLBACK_MSG_RULE_MATCHING     => 1,
    CALLBACK_MSG_RULE_NOT_MATCHING => 2,
    CALLBACK_MSG_SCAN_FINISHED     => 3,
    CALLBACK_MSG_IMPORT_MODULE     => 4,
    CALLBACK_CONTINUE              => 0,
    ERROR_SUCCESS                  => 0,
};

sub new {
    my ($class) = @_;
    yr_initialize();
    return bless { rules => undef }, $class;
}

sub compile {
    my ($self, $rule_str) = @_;
    my $compiler;
    my $res = yr_compiler_create(\$compiler);
    return 0 if $res != 0;

    $res = yr_compiler_add_string($compiler, $rule_str, undef);
    return 0 if $res != 0;

    my $rules;
    $res = yr_compiler_get_rules($compiler, \$rules);
    return 0 if $res != 0;

    yr_compiler_destroy($compiler);
    $self->{rules} = $rules;
    return 1;
}

sub scan_file {
    my ($self, $filename, $callback) = @_;
    die "Compile rules first" unless $self->{rules};

    my $content = read_file($filename, binmode => ':raw');
    return $self->scan_buffer($content, $callback);
}

sub scan_buffer {
    my ($self, $buffer, $callback, %opts) = @_;
    die "Compile rules first" unless $self->{rules};

    my $len = length($buffer);
    my $ptr = $ffi->cast('string' => 'opaque', $buffer);
    my @events;

    my $emit_strings = $opts{emit_string_events} // 1;

    my $callback_sub = $ffi->closure(sub {
        my ($context, $message, $message_data, $user_data) = @_;

        if ($message == CALLBACK_MSG_RULE_MATCHING) {
            eval {
                if ($message_data) {
                    my $found = 0;

                    OFFSET_LOOP: for (my $offset = 8; $offset < 256 && !$found; $offset += 8) {
                        my $rule_name;
                        eval {
                            my $identifier_field_addr = $message_data + $offset;
                            my $ptr_bytes = $ffi->cast('opaque' => 'string(8)', $identifier_field_addr);
                            my $name_ptr_value = unpack('Q', $ptr_bytes);

                            return if $name_ptr_value < 4096;
                            return if $name_ptr_value > 140737488355327 && $] >= 5.008;

                            $rule_name = $ffi->cast('opaque' => 'string', $name_ptr_value);
                        };

                        if (!$@ && defined $rule_name && $rule_name =~ /^[a-zA-Z_][a-zA-Z0-9_]*$/) {

                            # Always push the rule_match event
                            my $rule_event = YaraFFI::Event->new(
                                event => 'rule_match',
                                rule  => $rule_name,
                            );
                            push @events, $rule_event;
                            $callback->($rule_event) if defined $callback && ref $callback eq 'CODE';

                            # Only emit string_match if enabled
                            if ($emit_strings) {
                                my $string_event = YaraFFI::Event->new(
                                    event     => 'string_match',
                                    rule      => $rule_name,
                                    string_id => '$',
                                );
                                push @events, $string_event;
                                $callback->($string_event) if defined $callback && ref $callback eq 'CODE';
                            }

                            $found = 1;
                            last OFFSET_LOOP;
                        }
                    }
                }
            };
            warn "Callback error: $@" if $@;
        }

        return CALLBACK_CONTINUE;
    });

    my $res = yr_rules_scan_mem($self->{rules}, $ptr, $len, 0, $callback_sub, undef, 0);
    return $res;
}

sub DESTROY {
    my ($self) = @_;
    yr_rules_destroy($self->{rules}) if $self->{rules};
    yr_finalize();
}

=head1 AUTHOR

Mohammad Sajid Anwar, C<< <mohammad.anwar at yahoo.com> >>

=head1 REPOSITORY

L<https://github.com/manwar/YaraFFI>

=head1 BUGS

Please report any bugs or feature requests through the web interface at L<https://github.com/manwar/YaraFFI/issues>.
I will  be notified and then you'll automatically be notified of progress on your
bug as I make changes.

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc YaraFFI

You can also look for information at:

=over 4

=item * BUG Report

L<https://github.com/manwar/YaraFFI/issues>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/YaraFFI>

=item * Search MetaCPAN

L<https://metacpan.org/dist/YaraFFI>

=back

=head1 LICENSE AND COPYRIGHT

Copyright (C) 2025 Mohammad Sajid Anwar.

This program  is  free software; you can redistribute it and / or modify it under
the  terms  of the the Artistic License (2.0). You may obtain a  copy of the full
license at:

L<http://www.perlfoundation.org/artistic_license_2_0>

Any  use,  modification, and distribution of the Standard or Modified Versions is
governed by this Artistic License.By using, modifying or distributing the Package,
you accept this license. Do not use, modify, or distribute the Package, if you do
not accept this license.

If your Modified Version has been derived from a Modified Version made by someone
other than you,you are nevertheless required to ensure that your Modified Version
 complies with the requirements of this license.

This  license  does  not grant you the right to use any trademark,  service mark,
tradename, or logo of the Copyright Holder.

This license includes the non-exclusive, worldwide, free-of-charge patent license
to make,  have made, use,  offer to sell, sell, import and otherwise transfer the
Package with respect to any patent claims licensable by the Copyright Holder that
are  necessarily  infringed  by  the  Package. If you institute patent litigation
(including  a  cross-claim  or  counterclaim) against any party alleging that the
Package constitutes direct or contributory patent infringement,then this Artistic
License to you shall terminate on the date that such litigation is filed.

Disclaimer  of  Warranty:  THE  PACKAGE  IS  PROVIDED BY THE COPYRIGHT HOLDER AND
CONTRIBUTORS  "AS IS'  AND WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES. THE IMPLIED
WARRANTIES    OF   MERCHANTABILITY,   FITNESS   FOR   A   PARTICULAR  PURPOSE, OR
NON-INFRINGEMENT ARE DISCLAIMED TO THE EXTENT PERMITTED BY YOUR LOCAL LAW. UNLESS
REQUIRED BY LAW, NO COPYRIGHT HOLDER OR CONTRIBUTOR WILL BE LIABLE FOR ANY DIRECT,
INDIRECT, INCIDENTAL,  OR CONSEQUENTIAL DAMAGES ARISING IN ANY WAY OUT OF THE USE
OF THE PACKAGE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

=cut

1; # End of YaraFFI
