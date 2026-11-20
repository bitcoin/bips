#!/usr/bin/perl
use strict;
use warnings;
use Cwd qw(getcwd);
use Encode qw(encode);
use File::Temp qw(tempdir);
use FindBin;
use IPC::Open3;
use Symbol qw(gensym);
use Test::More;

my $buildtable = "$FindBin::Bin/buildtable.pl";
my $cwd = getcwd();
my $tmpdir = tempdir(CLEANUP => 1);
chdir $tmpdir or die "chdir $tmpdir: $!";

my $formosa = "Formosa\x{2014}Seed encoding by themed mnemonic stories";
my @cases = (
	['49 ASCII characters', 'A' x 49, undef],
	['50 ASCII characters', 'A' x 50, undef],
	['51 ASCII characters', 'A' x 51, qr/too-long Title \(51 > 50 char max\)/],
	['BIP 450 title', $formosa, undef],
	['BIP 450 title plus one character', "$formosa!", undef],
	['BIP 450 title plus two characters', "$formosa!!", undef],
	['BIP 450 title plus three characters', "$formosa!!!", qr/too-long Title \(51 > 50 char max\)/],
	['50 characters with an em dash', ('A' x 49) . "\x{2014}", undef],
	['51 characters with an em dash', ('A' x 50) . "\x{2014}", qr/too-long Title \(51 > 50 char max\)/],
	['50 characters with a four-byte character', ('A' x 49) . "\x{1f600}", undef],
	['51 characters with a four-byte character', ('A' x 50) . "\x{1f600}", qr/too-long Title \(51 > 50 char max\)/],
);
$_->[1] = encode('UTF-8', $_->[1]) for @cases;
push @cases, ['invalid UTF-8', ('A' x 49) . "\xff", qr/UTF-8/];

for my $extension (qw(mediawiki md)) {
	my $fn = "bip-0450.$extension";
	my ($start, $end) = $extension eq 'md' ? ('```', '```') : ('<pre>', '</pre>');
	for my $case (@cases) {
		my ($name, $bytes, $error) = @$case;
		subtest "$extension: $name" => sub {
			open my $fixture, '>:raw', $fn or die "open $fn: $!";
			print {$fixture} "$start\n  BIP: 450\n  Title: $bytes\n",
				"  Authors: Test Author <test\@example.com>\n  Status: Draft\n",
				"  Type: Specification\n  Assigned: 2026-05-15\n  License: BSD-2-Clause\n$end\n";
			close $fixture or die "close $fn: $!";

			my $stderr = gensym;
			my $pid = open3(my $stdin, my $stdout, $stderr, $^X, $buildtable);
			close $stdin;
			my ($output, $diagnostic);
			{
				local $/;
				$output = <$stdout>;
				$diagnostic = <$stderr>;
			}
			waitpid $pid, 0;
			my $status = $?;
			if (defined $error) {
				isnt($status, 0, 'rejects the title');
				like($diagnostic, $error, 'reports the expected validation error');
			} else {
				is($status, 0, 'accepts the title');
				is($diagnostic, '', 'no warnings');
				is($output, "|-\n| [[$fn|450]]\n|\n| $bytes\n| Test Author\n| Specification\n| Draft\n",
					'preserves the title bytes in the generated table');
			}
		};
	}
	unlink $fn or die "unlink $fn: $!";
}

chdir $cwd or die "chdir $cwd: $!";
done_testing();
