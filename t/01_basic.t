use strict;
use warnings;
use Test::More;
use FindBin;
use lib "$FindBin::Bin/../lib";
use YaraFFI;
use File::Temp qw(tempfile);

plan tests => 4;

# Create new YARA instance
my $yara = YaraFFI->new();
ok(defined $yara, "YaraFFI object created");

# Test rule compilation
my $rules = <<'RULES';
rule EICAR_Test_File
{
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}
RULES

ok($yara->compile($rules), "Rules compiled");

# Create test file
my ($fh, $filename) = tempfile(SUFFIX => '.com', UNLINK => 1);
print $fh 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';
close $fh;

# Test scanning
my $matched_rule;
my $res = $yara->scan_file($filename, sub {
    my ($event) = @_;        # YaraFFI::Event object
    $matched_rule = "$event";  # stringify explicitly
});

is($res, 0, "scan_file returned success");

ok(defined $matched_rule && $matched_rule eq 'EICAR_Test_File',
   "Rule matched during scan")
   or diag "Expected 'EICAR_Test_File' but got " . ($matched_rule || 'undef');

done_testing;
