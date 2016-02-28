#!perl

use warnings;
use strict;

use SnortUnified(qw(:ALL));
use Data::Dumper;
use Socket;
##########################
my $record;
my $UF_DATA = openSnortUnified(shift);
while($record = readSnortUnified2Record()){
	print "record type " . $record->{'TYPE'} . " is " . $UNIFIED2_TYPES->{$record->{'TYPE'}} . "\n";
	foreach my $field ( @{$record->{'FIELDS'}} ){
		if ($field ne 'pkt' && $field ne 'data_blob'){
			print("Campo " . $field . " : " . $record->{$field} . "\n");
		}
		else{
			print "data_blob\n";
			print("====================== ASCII\n");
			my $valmake =  make_ascii($record->{'data_blob'}) . "\n";
			print $record->{'data_blob'};
			print $valmake;
			#print("====================== HEX\n");
			#print make_hex($record->{'data_blob'}) . "\n";
			#my ($a,$b,$c);
			#($a, $b, $c) = unpack('NN', $record->{'data_blob'});
			#print inet_ntoa($a) . "\n";
			#print inet_ntoa($b) . "\n";
			#print inet_ntoa($c) . "\n";
			#my $a = substr($record->{'data_blob'},1,4);
			#my $b = substr($record->{'data_blob'},4,4);
			#my $c = substr($record->{'data_blob'},8,4);
			#print sprintf("%d",unpack('N',$a)). "\n";
			#print sprintf("%d",unpack('N',$b)). "\n";
			#print inet_ntoa($c) . "\n";
		}
	}
}
closeSnortUnified();


sub make_hex() {
		my $data = shift;
		return unpack("h* ",$data);
}

sub make_ascii() {
		my $data = shift;
		print $data;
		my $asc = unpack('a*', $data);
		$asc =~ tr/A-Za-z0-9;:\"\'.,<>[]\\|?\/\`~!\@#$%^&*()_\-+={}/./c;
		return $asc;
}

