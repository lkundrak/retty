#!/usr/bin/perl

$state = 0;
while ($l = <>) {
	chomp($l);
	if (!$state && $l =~ /^[0-9a-f]* <.*>:/) {
		$state++;
	} elsif ($state) {
		if ($l =~ /^\s*([0-9a-f]*):\t(.*)\t(.*)$/) {
			$c = $1;
			$a = $2;
			$b = $3;
			$a =~ s/[^0-9a-f]//g;
			$a =~ s/([0-9a-f]{2})/0x\1,/g;
			printf("/* %04s */\t%-30s\t/* \%s */\n", $c, $a, $b);
		}
	}
}
