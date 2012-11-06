#!/usr/bin/perl

# 'There are evil things written on this hilt,' he said; 'though maybe your
# eyes cannot see them. Keep it, Aragorn, till we reach the house of Elrond!
# But be wary, and handle it as little as you may! Alas! the wounds of this
# weapon are beyond my skill to heal. I will do what I can - but all the more
# do I urge you now to go on without rest.'

$state = 0;
while ($l = <STDIN>) {
	chomp($l);
	if (!$state && $l =~ /^[0-9a-f]* <.*>:/) {
		$state++;
	} elsif ($state) {
		if ($l =~ /^\s*([0-9a-f]*):\t(.*?)(?:\t(.*))?$/) {
			$c = $1;
			$a = $2;
			$b = $3;
			$a =~ s/[^0-9a-f]//g;
			$a =~ s/([0-9a-f]{2})/0x\1,/g;
			printf("/* %04s */\t%-30s\t/* \%s */\n", $c, $a, $b);
		} elsif ($l =~ /^([0-9a-f]+) <(\S+)>:\s*$/) {
			push (@id, [$2, $1]);
		}
	}
}

print "};\n";
foreach my $i (@id) {
	my ($id, $ofs) = @$i;
	print "poke_32($ARGV[0], 0x$ofs + 0x01, fd_$id);\n";
}
print "{\n";
