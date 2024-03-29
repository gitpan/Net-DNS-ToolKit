# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

######################### We start with some black magic to print on failure.
# Change 1..1 below to 1..last_test_to_print .
# (It may become useful if the test is moved to ./t subdirectory.)

BEGIN { $| = 1; print "1..10\n"; }
END {print "not ok 1\n" unless $loaded;}

#use diagnostics;
use Net::DNS::ToolKit qw(
	put16
	get1char
	parse_char
	newhead
	dn_comp
	put_qdcount
);
use Net::DNS::ToolKit::Debug qw(
	print_head
	print_buf
);
use Net::DNS::Codes qw(:all);

my $module = ($0 =~ /([A-Z]+)\.t$/)
	? 'Net::DNS::ToolKit::RR::'.$1
	: 'Net::DNS::ToolKit::RR::RP';

eval "require $module";

$loaded = 1;
print "ok 1\n";
######################### End of black magic.

# Insert your test code below (better if it prints "ok 13"
# (correspondingly "not ok 13") depending on the success of chunk 13
# of the test code):

$test = 2;

sub ok {
  print "ok $test\n";
  ++$test;
}

## test 2	setup, generate a header for a question

my $buffer = '';
my $off = newhead(\$buffer,
	12345,			# id
	QR | BITS_QUERY | RD | RA,	# query response, query, recursion desired, recursion available
);

print "bad question size $off\nnot "
	unless $off == NS_HFIXEDSZ;
&ok;

sub expect {
  my $x = shift;
  my @exp;
  foreach(split(/\n/,$x)) {
    if ($_ =~ /0x\w+\s+(\d+) /) {
      push @exp,$1;
    }
  }
  return @exp;
}

sub print_ptrs {
  foreach(@_) {
    print "$_ ";
  }
  print "\n";
}

sub chk_exp {
  my($bp,$exp) = @_;
  my @expect = expect($$exp);
  foreach(0..length($$bp) -1) {
    $char = get1char($bp,$_);
    next if $char == $expect[$_];
    print "buffer mismatch $_, got: $char, exp: $expect[$_]\nnot ";
    last;
  }
  &ok;
}

## test 3	setup, append question
# expect this from print_buf
my $exptext = q(
  0     :  0011_0000  0x30   48  0  
  1     :  0011_1001  0x39   57  9  
  2     :  1000_0001  0x81  129    
  3     :  1000_0000  0x80  128    
  4     :  0000_0000  0x00    0    
  5     :  0000_0001  0x01    1    
  6     :  0000_0000  0x00    0    
  7     :  0000_0000  0x00    0    
  8     :  0000_0000  0x00    0    
  9     :  0000_0000  0x00    0    
  10    :  0000_0000  0x00    0    
  11    :  0000_0000  0x00    0    
  12    :  0000_0011  0x03    3    
  13    :  0110_0110  0x66  102  f  
  14    :  0110_1111  0x6F  111  o  
  15    :  0110_1111  0x6F  111  o  
  16    :  0000_0011  0x03    3    
  17    :  0110_0010  0x62   98  b  
  18    :  0110_0001  0x61   97  a  
  19    :  0111_0010  0x72  114  r  
  20    :  0000_0011  0x03    3    
  21    :  0110_0011  0x63   99  c  
  22    :  0110_1111  0x6F  111  o  
  23    :  0110_1101  0x6D  109  m  
  24    :  0000_0000  0x00    0    
  25    :  0000_0000  0x00    0    
  26    :  0000_0001  0x01    1    
  27    :  0000_0000  0x00    0    
  28    :  0000_0001  0x01    1    
  29    :  0000_0000  0x00    0    
  30    :  0000_0000  0x00    0    
  31    :  0000_1011  0x0B   11    
  32    :  0111_0010  0x72  114  r  
  33    :  0110_0101  0x65  101  e  
  34    :  0111_0011  0x73  115  s  
  35    :  0111_0000  0x70  112  p  
  36    :  0110_1111  0x6F  111  o  
  37    :  0110_1110  0x6E  110  n  
  38    :  0111_0011  0x73  115  s  
  39    :  0110_1001  0x69  105  i  
  40    :  0110_0010  0x62   98  b  
  41    :  0110_1100  0x6C  108  l  
  42    :  0110_0101  0x65  101  e  
  43    :  1100_0000  0xC0  192    
  44    :  0001_0000  0x10   16    
);

my $name = 'foo.bar.com';
my @dnptrs;
($off,@dnptrs)=dn_comp(\$buffer,$off,\$name);
# push on some stuff that looks like a question
$off = put16(\$buffer,$off,T_A);
$off = put16(\$buffer,$off,C_IN);
put_qdcount(\$buffer,1);
#print_head(\$buffer);
#print_buf(\$buffer);
#print_ptrs(@dnptrs);
chk_exp(\$buffer,\$exptext);

#######################################

## test 4	put NS record
#	This is what we must test

#  ($newoff,$name,$type,$class,$ttl,$rdlength,
#        $rdata,...) = $get->XYZ(\$buffer,$offset);
#
#  ($newoff,@dnptrs)=$put->XYZ(\$buffer,$offset,\@dnptrs,   
#        $name,$type,$class,$ttl,$rdlength,$rdata,...);
#
#  $name,$TYPE,$CLASS,$TTL,$rdlength,$IPaddr) 
#    = $parse->XYZ($name,$type,$class,$ttl,$rdlength,
#        $rdata,...);

$exptext = q(
  0     :  0011_0000  0x30   48  0  
  1     :  0011_1001  0x39   57  9  
  2     :  1000_0001  0x81  129    
  3     :  1000_0000  0x80  128    
  4     :  0000_0000  0x00    0    
  5     :  0000_0001  0x01    1    
  6     :  0000_0000  0x00    0    
  7     :  0000_0000  0x00    0    
  8     :  0000_0000  0x00    0    
  9     :  0000_0000  0x00    0    
  10    :  0000_0000  0x00    0    
  11    :  0000_0000  0x00    0    
  12    :  0000_0011  0x03    3    
  13    :  0110_0110  0x66  102  f  
  14    :  0110_1111  0x6F  111  o  
  15    :  0110_1111  0x6F  111  o  
  16    :  0000_0011  0x03    3    
  17    :  0110_0010  0x62   98  b  
  18    :  0110_0001  0x61   97  a  
  19    :  0111_0010  0x72  114  r  
  20    :  0000_0011  0x03    3    
  21    :  0110_0011  0x63   99  c  
  22    :  0110_1111  0x6F  111  o  
  23    :  0110_1101  0x6D  109  m  
  24    :  0000_0000  0x00    0    
  25    :  0000_0000  0x00    0    
  26    :  0000_0001  0x01    1    
  27    :  0000_0000  0x00    0    
  28    :  0000_0001  0x01    1    
  29    :  0000_0000  0x00    0    
  30    :  0001_0110  0x16   22    
  31    :  0000_1011  0x0B   11    
  32    :  0111_0010  0x72  114  r  
  33    :  0110_0101  0x65  101  e  
  34    :  0111_0011  0x73  115  s  
  35    :  0111_0000  0x70  112  p  
  36    :  0110_1111  0x6F  111  o  
  37    :  0110_1110  0x6E  110  n  
  38    :  0111_0011  0x73  115  s  
  39    :  0110_1001  0x69  105  i  
  40    :  0110_0010  0x62   98  b  
  41    :  0110_1100  0x6C  108  l  
  42    :  0110_0101  0x65  101  e  
  43    :  1100_0000  0xC0  192    
  44    :  0001_0000  0x10   16    
  45    :  0000_0101  0x05    5    
  46    :  0110_0101  0x65  101  e  
  47    :  0111_0010  0x72  114  r  
  48    :  0111_0010  0x72  114  r  
  49    :  0110_1111  0x6F  111  o  
  50    :  0111_0010  0x72  114  r  
  51    :  1100_0000  0xC0  192    
  52    :  0001_0000  0x10   16    
);
$name = 'responsible.bar.com';
my $ername = 'error.bar.com';
### offset from above = 29
($off, @dnptrs) = $module->put(\$buffer,$off,\@dnptrs,$name,$ername);
#print_buf(\$buffer);
#print_ptrs(@dnptrs);
chk_exp(\$buffer,\$exptext);      

## test 5	test get

my $start = 29;	# from above
($newoff,$newname,(my $newEname)) = $module->get(\$buffer,$start);
# check offset against PUT operation above
print "bad offset, $newoff, exp: $off\nnot "
  unless $newoff == $off;
&ok;

## test 6	verify name
print "bad name\ngot: $newname\nexp: $name\nnot "
	unless $newname eq $name;
&ok;

## test 7	verify ername
print "bad name\ngot: $ername\nexp: $newEname\nnot "
	unless $newEname eq $ername;
&ok;

## test 8	check parse
($name,$ername) = $module->parse($newname,$newEname);
print "bad parse, got: $name, exp: $newname.\nnot "
	unless $name eq $newname .'.';
&ok;

## test 9
print "bad parse, got: $ername, exp: $newEname.\nnot "
	unless $ername eq $newEname .'.';
&ok;

## test 10	check inheritance
$module .= '::parse';
($_) = &$module($module,$newname,$newEname);
print "inheritance failed\n got: $_\nexp: $newname.\nnot "
	unless $_ eq $newname.'.';
&ok;
