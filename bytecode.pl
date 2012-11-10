#!/usr/bin/perl

# 'There are evil things written on this hilt,' he said; 'though maybe your
# eyes cannot see them. Keep it, Aragorn, till we reach the house of Elrond!
# But be wary, and handle it as little as you may! Alas! the wounds of this
# weapon are beyond my skill to heal. I will do what I can - but all the more
# do I urge you now to go on without rest.'

use Config;

$state = 0;
$bytes = 0;
while ($l = <STDIN>) {
	chomp($l);
	if (!$state && $l =~ /^[0-9a-f]* <.*>:/) {
		$state++;
	} elsif ($state) {
		if ($l =~ /^\s*([0-9a-f]*):\t(.*?)(?:\t(.*))?$/) {
			$c = $1;
			$a = $2;
			$b = $3;

			# Unconditionally messess byte order, only works on little endian
			@bytes = map { reverse /([0-9a-f]{2})/g } split /\s+/, $a;
			$bytes += scalar @bytes;
			$a = join '', map { "0x$_, " } @bytes;

			printf("/* %04s */\t%-30s\t/* \%s */\n", $c, $a, $b);
		} elsif ($l =~ /^([0-9a-f]+) <(\S+)>:\s*$/) {
			push (@id, [$2, $1]);
		}
	}
}

print '0x00,' x ($Config{longsize} - ($bytes % $Config{longsize}));
print "};\n";
foreach my $i (@id) {
	my ($id, $ofs) = @$i;
	print "poke($ARGV[0], 0x$ofs + MOVSIZE, fd_$id);\n";
}
print "{\n";
