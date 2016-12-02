#!/usr/bin/perl
use strict;
use warnings;

my $topbip = 9999;

my %RequiredFields = (
	BIP => undef,
	Title => undef,
	Author => undef,
	Status => undef,
	Type => undef,
	Created => undef,
);
my %MayHaveMulti = (
	Author => undef,
	'Post-History' => undef,
);
my %DateField = (
	Created => undef,
);
my %EmailField = (
	Author => undef,
	Editor => undef,
);
my %MiscField = (
	'Discussions-To' => undef,
	'Post-History' => undef,
	'Replaces' => undef,
	'Superseded-By' => undef,
	'Resolution' => undef,
);

my %ValidStatus = (
	Draft => undef,
	Deferred => undef,
	Accepted => "background-color: #ffffcf",
	Rejected => "background-color: #ffcfcf",
	Withdrawn => "background-color: #ffcfcf",
	Final => "background-color: #cfffcf",
	Active => "background-color: #cfffcf",
	Replaced => "background-color: #ffcfcf",
);
my %ValidType = (
	'Standards Track' => 'Standard',
	'Informational' => undef,
	'Process' => undef,
);

my %emails;

my $bipnum = 0;
while (++$bipnum <= $topbip) {
	my $fn = sprintf "bip-%04d.mediawiki", $bipnum;
	-e $fn || next;
	open my $F, "<$fn";
	while (<$F> !~ m[^(?:\xef\xbb\xbf)?<pre>$]) {
			die "No <pre> in $fn" if eof $F;
	}
	my %found;
	my ($title, $author, $status, $type);
	my ($field, $val);
	while (<$F>) {
		m[^</pre>$] && last;
		if (m[^  ([\w-]+)\: (.*\S)$]) {
			$field = $1;
			$val = $2;
			die "Duplicate $field field in $fn" if exists $found{$field};
		} elsif (m[^  ( +)(.*\S)$]) {
			die "Continuation of non-field in $fn" unless defined $field;
			die "Too many spaces in $fn" if length $1 != 2 + length $field;
			die "Not allowed for multi-value in $fn" unless exists $MayHaveMulti{$field};
			$val = $2;
		} else {
			die "Bad line in $fn preamble";
		}
		++$found{$field};
		die "Extra spaces in $fn" if $val =~ /^\s/;
		if ($field eq 'BIP') {
			die "$fn claims to be BIP $val" if $val ne $bipnum;
		} elsif ($field eq 'Title') {
			$title = $val;
		} elsif ($field eq 'Author') {
			$val =~ m/^(\S[^<@>]*\S) \<([^@>]*\@[\w.]+\.\w+)\>$/ or die "Malformed Author line in $fn";
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
		} elsif (exists $DateField{$field}) {
			die "Invalid date format in $fn" unless $val =~ /^20\d{2}\-(?:0\d|1[012])\-(?:[012]\d|30|31)$/;
		} elsif (exists $EmailField{$field}) {
			$val =~ m/^(\S[^<@>]*\S) \<[^@>]*\@[\w.]+\.\w+\>$/ or die "Malformed $field line in $fn";
		} elsif (not exists $MiscField{$field}) {
			die "Unknown field $field in $fn";
		}
	}
	for my $field (keys %RequiredFields) {
		die "Missing $field in $fn" unless $found{$field};
	}
	print "|-";
	if (defined $ValidStatus{$status}) {
		print " style=\"" . $ValidStatus{$status} . "\"";
	}
	print "\n";
	print "| [[${fn}|${bipnum}]]\n";
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
