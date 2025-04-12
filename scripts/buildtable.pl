#!/usr/bin/perl
use strict;
use warnings;

my $topbip = 9999;
my $include_layer = 1;

my %RequiredFields = (
	BIP => undef,
	Title => undef,
	Author => undef,
	Status => undef,
	Type => undef,
	Created => undef,
	# License => undef,   (has exceptions)
);
my %MayHaveMulti = (
	Author => undef,
	'Comments-URI' => undef,
	License => undef,
	'License-Code' => undef,
	'Discussion' => undef,
);
my %DateField = (
	Created => undef,
);
my %EmailField = (
	Author => undef,
	Editor => undef,
);
my %MiscField = (
	'Comments-URI' => undef,
	'Comments-Summary' => undef,
	'Discussions-To' => undef,
	'Discussion' => undef,
	'Replaces' => undef,
	'Requires' => undef,
	'Proposed-Replacement' => undef,
);
my @FieldOrder = qw(
	BIP
	Layer
	Title
	Author
	Authors
	Editor
	Deputies
	Discussions-To
	Comments-Summary
	Comments-URI
	Status
	Type
	Created
	License
	License-Code
	Discussion
	Post-History
	Version
	Requires
	Replaces
	Proposed-Replacement
	Superseded-By
);

my %ValidLayer = (
	'Consensus (soft fork)' => undef,
	'Consensus (hard fork)' => undef,
	'Peer Services' => undef,
	'API/RPC' => undef,
	'Applications' => undef,
);
my %ValidStatus = (
	Draft => undef,
	Complete => "background-color: #ffffcf",
	Deployed => "background-color: #cfffcf",
	Closed => "background-color: #ffcfcf",
);
my %ValidType = (
	'Specification' => undef,
	'Informational' => undef,
	'Process' => undef,
);
my %RecommendedLicenses = (
	'BSD-2-Clause' => undef,
	'BSD-3-Clause' => undef,
	'CC0-1.0' => undef,
	'GNU-All-Permissive' => undef,
);
my %AcceptableLicenses = (
	%RecommendedLicenses,
	'Apache-2.0' => undef,
	'BSL-1.0' => undef,
	'CC-BY-4.0' => undef,
	'CC-BY-SA-4.0' => undef,
	'MIT' => undef,
	'AGPL-3.0' => undef,
	'AGPL-3.0+' => undef,
	'FDL-1.3' => undef,
	'GPL-2.0' => undef,
	'GPL-2.0+' => undef,
	'LGPL-2.1' => undef,
	'LGPL-2.1+' => undef,
);
my %DefinedLicenses = (
	%AcceptableLicenses,
	'OPL' => undef,
	'PD' => undef,
);
my %GrandfatheredPD = map { $_ => undef } qw(9 36 37 38 42 49 50 60 65 67 69 74 80 81 83 90 99 105 107 109 111 112 113 114 122 124 125 126 130 131 132 133 140 141 142 143 144 146 147 150 151 152);
my %TolerateMissingLicense = map { $_ => undef } qw(1 10 11 12 13 14 15 16 21 31 33 34 35 39 43 44 45 47 61 64 68 70 71 72 73 101 102 106 120 121);
my %TolerateTitleTooLong = map { $_ => undef } qw(39 44 45 47 49 60 67 68 69 73 74 75 80 81 99 105 106 109 113 122 126 131 143 145 147 173 327);

my %emails;

my $bipnum = 0;
while (++$bipnum <= $topbip) {
	my $fn = sprintf "bip-%04d.mediawiki", $bipnum;
	my $is_markdown = 0;
	if (!-e $fn) {
		$fn = sprintf "bip-%04d.md", $bipnum;
		$is_markdown = 1;
	}
	-e $fn || next;
	open my $F, "<$fn";
	if ($is_markdown) {
		while (<$F> !~ m[^(?:\xef\xbb\xbf)?```$]) {
			die "No ``` in $fn" if eof $F;
		}
	} else {
		while (<$F> !~ m[^(?:\xef\xbb\xbf)?<pre>$]) {
			die "No <pre> in $fn" if eof $F;
		}
	}
	my %found;
	my ($title, $author, $status, $type, $layer);
	my ($field, $val, @field_order);
	while (<$F>) {
		last if ($is_markdown && m[^```$]);
		last if (!$is_markdown && m[^</pre>$]);
		if (m[^  ([\w-]+)\: (.*\S)$]) {
			$field = $1;
			$val = $2;
			die "Duplicate $field field in $fn" if exists $found{$field};
			die "Too many spaces in $fn" if $val =~ /^\s/;
		} elsif (m[^  ( +)(.*\S)$]) {
			die "Continuation of non-field in $fn" unless defined $field;
			die "Too many spaces in $fn" if length $1 != 2 + length $field;
			die "Not allowed for multi-value in $fn" unless exists $MayHaveMulti{$field};
			$val = $2;
		} else {
			die "Bad line in $fn preamble";
		}
		die "Extra spaces in $fn" if $val =~ /^\s/;
		if ($field eq 'BIP') {
			die "$fn claims to be BIP $val" if $val ne $bipnum;
		} elsif ($field eq 'Title') {
			$title = $val;
			my $title_len = length($title);
			die "$fn has too-long Title ($title_len > 44 char max)" if $title_len > 44 and not exists $TolerateTitleTooLong{$bipnum};
		} elsif ($field eq 'Author') {
			$val =~ m/^(\S[^<@>]*\S) \<([^@>]*\@[\w.-]+\.\w+)\>$/ or die "Malformed Author line in $fn";
			my ($authorname, $authoremail) = ($1, $2);
			$authoremail =~ s/(?<=\D)$bipnum(?=\D)/<BIPNUM>/g;
			$emails{$authorname}->{$authoremail} = undef;
			if (defined $author) {
				$author .= ", $authorname";
			} else {
				$author = $authorname;
			}
		} elsif ($field eq 'Status') {
			if ($bipnum == 38) {  # HACK
				$val =~ s/\s+\(.*\)$//;
			}
			die "Invalid status in $fn" unless exists $ValidStatus{$val};
			$status = $val;
		} elsif ($field eq 'Type') {
			die "Invalid type in $fn" unless exists $ValidType{$val};
			if (defined $ValidType{$val}) {
				$type = $ValidType{$val};
			} else {
				$type = $val;
			}
		} elsif ($field eq 'Layer') {  # BIP 123
			die "Invalid layer $val in $fn" unless exists $ValidLayer{$val};
			$layer = $val;
		} elsif ($field =~ /^License(?:\-Code)?$/) {
			die "Undefined license $val in $fn" unless exists $DefinedLicenses{$val};
			if (not $found{$field}) {
				die "Unacceptable license $val in $fn" unless exists $AcceptableLicenses{$val} or ($val eq 'PD' and exists $GrandfatheredPD{$bipnum});
			}
		} elsif ($field eq 'Comments-URI') {
			if ($found{'Comments-URI'}) {
				my $first_comments_uri = sprintf('https://github.com/bitcoin/bips/wiki/Comments:BIP-%04d', $bipnum);
				die "First Comments-URI must be exactly \"$first_comments_uri\" in $fn" unless $val eq $first_comments_uri;
			}
		} elsif (exists $DateField{$field}) {
			# Enforce date format 20XX-MM-DD, where XX is 00-99, MM is 01-12 and DD is 01-31
			die "Invalid date format in $fn" unless $val =~ /^20\d{2}\-(?:0[1-9]|1[0-2])\-(?:0[1-9]|[12]\d|30|31)$/;
		} elsif (exists $EmailField{$field}) {
			$val =~ m/^(\S[^<@>]*\S) \<[^@>]*\@[\w.]+\.\w+\>$/ or die "Malformed $field line in $fn";
		} elsif (not exists $MiscField{$field}) {
			die "Unknown field $field in $fn";
		}
		++$found{$field};
		push @field_order, $field unless @field_order and $field_order[-1] eq $field;
	}
	if (not $found{License}) {
		die "Missing License in $fn" unless exists $TolerateMissingLicense{$bipnum};
	}
	for my $field (keys %RequiredFields) {
		die "Missing $field in $fn" unless $found{$field};
	}
	my @expected_field_order = grep { exists $found{$_} } @FieldOrder;
	if ("@expected_field_order" ne "@field_order") {
		die "Field order is incorrect in $fn, should be:\n\t" . join(", ", @expected_field_order) . "\nbut contains:\n\t" . join(", ", @field_order);
	}
	print "|-";
	if (defined $ValidStatus{$status}) {
		print " style=\"" . $ValidStatus{$status} . "\"";
	}
	print "\n";
	print "| [[${fn}|${bipnum}]]\n";
	if ($include_layer) {
		if (defined $layer) {
			print "| ${layer}\n";
		} else {
			print "|\n";
		}
	}
	print "| ${title}\n";
	print "| ${author}\n";
	print "| ${type}\n";
	print "| ${status}\n";
	close $F;
}

for my $author (sort keys %emails) {
	my @emails = sort keys %{$emails{$author}};
	my $email_count = @emails;
	next unless $email_count > 1;
	warn "NOTE: $author has $email_count email addresses: @emails\n";
}
