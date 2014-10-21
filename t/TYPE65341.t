# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

######################### We start with some black magic to print on failure.
# Change 1..1 below to 1..last_test_to_print .
# (It may become useful if the test is moved to ./t subdirectory.)

# THIS IS A MODIFIED VERSION OF RRtype.t
# look at tests 11, 13, 20. 
#
# test 11 puts an 'A' record
# test 13 and 20 retrieve and parse (respectively) TYPE1 records 
# which are supposed to be the same since they are known types

BEGIN { $| = 1; print "1..25\n"; }
END {print "not ok 1\n" unless $loaded;}

use Net::DNS::Codes qw(:all );
use Net::DNS::ToolKit qw(
	newhead
	put_qdcount
	put_ancount
	inet_aton
	inet_ntoa
	get1char
	put1char
	putstring
	parse_char
);
use Net::DNS::ToolKit::Debug qw(
	print_head
	print_buf
);
use Net::DNS::ToolKit::RR;

$loaded = 1;
print "ok 1\n";
######################### End of black magic.



$test = 2;

sub ok {
  print "ok $test\n";
  ++$test;
}

##################################################
#	first 10 test are from Question.t
#	and are just setup + a little checking
# see test 11 for begin testing as TYPE65341 - unknown
##################################################

## test 2	generate a header for a question

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

my ($get,$put,$parse) = new Net::DNS::ToolKit::RR;

## test 3	append question
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
  26    :  0000_1111  0x0F   15    
  27    :  0000_0000  0x00    0    
  28    :  0000_0001  0x01    1    
);
my $name = 'foo.bar.com';
my @dnptrs;
my $type = T_MX;
my $class = C_IN;
(my $newoff,@dnptrs) = $put->Question(\$buffer,$off,$name,$type,$class);
put_qdcount(\$buffer,1);
#print_head(\$buffer);
#print_buf(\$buffer);
#print_ptrs(@dnptrs);
#print $newoff,"\n";
chk_exp(\$buffer,\$exptext);

## test 4	check offset
print "bad offset, $newoff, exp: 29\nnot "
	unless $newoff == 29;
&ok;

## test	5	get Question, check name
($newoff,$newname,$newtype,$newclass) = $get->Question(\$buffer,$off);
print "bad name, $newname, exp: $name\nnot "
	unless $newname eq $name;
&ok;

## test 6	check type
print "bad type: ",TypeTxt->{$newtype},", exp: ",TypeTxt->{$type},"\nnot "
	unless $newtype == $type;
&ok;

## test 7	check class
print "bad type: ",ClassTxt->{$newclass},", exp: ",ClassTxt->{$class},"\nnot "
	unless $newclass == $class;
&ok;

## test 8	parse record, check name .. should be pass thru
($name,$type,$class) = $parse->Question($newname,$newtype,$newclass);
print "bad name, $name, exp: $newname.\nnot "
	unless $newname.'.' eq $name;
&ok;

$name = $newname;

## test 9	check type
print "bad type: $type, exp: ",TypeTxt->{$newtype},"\nnot "
	unless $type eq TypeTxt->{$newtype};
&ok;

## test 10	check class
print "bad class: $class, exp: ",ClassTxt->{$newclass},"\nnot "
	unless $class eq ClassTxt->{$newclass};
&ok;

############ real tests follow
## test 11	autoload A.pm
$exptext = q(
  0	:  0011_0000  0x30   48  0  
  1	:  0011_1001  0x39   57  9  
  2	:  1000_0001  0x81  129    
  3	:  1000_0000  0x80  128    
  4	:  0000_0000  0x00    0    
  5	:  0000_0001  0x01    1    
  6	:  0000_0000  0x00    0    
  7	:  0000_0000  0x00    0    
  8	:  0000_0000  0x00    0    
  9	:  0000_0000  0x00    0    
  10	:  0000_0000  0x00    0    
  11	:  0000_0000  0x00    0    
  12	:  0000_0011  0x03    3    
  13	:  0110_0110  0x66  102  f  
  14	:  0110_1111  0x6F  111  o  
  15	:  0110_1111  0x6F  111  o  
  16	:  0000_0011  0x03    3    
  17	:  0110_0010  0x62   98  b  
  18	:  0110_0001  0x61   97  a  
  19	:  0111_0010  0x72  114  r  
  20	:  0000_0011  0x03    3    
  21	:  0110_0011  0x63   99  c  
  22	:  0110_1111  0x6F  111  o  
  23	:  0110_1101  0x6D  109  m  
  24	:  0000_0000  0x00    0    
  25	:  0000_0000  0x00    0    
  26	:  0000_1111  0x0F   15    
  27	:  0000_0000  0x00    0    
  28	:  0000_0001  0x01    1    
  29	:  0000_0101  0x05    5    
  30	:  0110_0111  0x67  103  g  
  31	:  0110_1111  0x6F  111  o  
  32	:  0110_1111  0x6F  111  o  
  33	:  0111_0011  0x73  115  s  
  34	:  0110_0101  0x65  101  e  
  35	:  0000_0110  0x06    6    
  36	:  0110_1110  0x6E  110  n  
  37	:  0110_1111  0x6F  111  o  
  38	:  0111_0100  0x74  116  t  
  39	:  0110_0110  0x66  102  f  
  40	:  0110_1111  0x6F  111  o  
  41	:  0110_1111  0x6F  111  o  
  42	:  1100_0000  0xC0  192    
  43	:  0001_0000  0x10   16    
  44	:  1111_1111  0xFF  255    
  45	:  0011_1101  0x3D   61  =  
  46	:  0000_0000  0x00    0    
  47	:  0000_0001  0x01    1    
  48	:  0000_0000  0x00    0    
  49	:  0000_0001  0x01    1    
  50	:  0101_0001  0x51   81  Q  
  51	:  1000_0000  0x80  128    
  52	:  0000_0000  0x00    0    
  53	:  0010_1100  0x2C   44  ,  
  54	:  0111_0100  0x74  116  t  
  55	:  0110_1000  0x68  104  h  
  56	:  0110_0101  0x65  101  e  
  57	:  0010_0000  0x20   32     
  58	:  0111_0001  0x71  113  q  
  59	:  0111_0101  0x75  117  u  
  60	:  0110_1001  0x69  105  i  
  61	:  0110_0011  0x63   99  c  
  62	:  0110_1011  0x6B  107  k  
  63	:  0010_0000  0x20   32     
  64	:  0100_0010  0x42   66  B  
  65	:  0111_0010  0x72  114  r  
  66	:  0110_1111  0x6F  111  o  
  67	:  0111_0111  0x77  119  w  
  68	:  0110_1110  0x6E  110  n  
  69	:  0010_0000  0x20   32     
  70	:  0100_0110  0x46   70  F  
  71	:  0110_1111  0x6F  111  o  
  72	:  0111_1000  0x78  120  x  
  73	:  0010_0000  0x20   32     
  74	:  0110_1010  0x6A  106  j  
  75	:  0111_0101  0x75  117  u  
  76	:  0110_1101  0x6D  109  m  
  77	:  0111_0000  0x70  112  p  
  78	:  0110_0101  0x65  101  e  
  79	:  0110_0100  0x64  100  d  
  80	:  0010_0000  0x20   32     
  81	:  0110_1111  0x6F  111  o  
  82	:  0111_0110  0x76  118  v  
  83	:  0110_0101  0x65  101  e  
  84	:  0111_0010  0x72  114  r  
  85	:  0010_0000  0x20   32     
  86	:  0111_0100  0x74  116  t  
  87	:  0110_1000  0x68  104  h  
  88	:  0110_0101  0x65  101  e  
  89	:  0010_0000  0x20   32     
  90	:  0100_1100  0x4C   76  L  
  91	:  0110_0001  0x61   97  a  
  92	:  0111_1010  0x7A  122  z  
  93	:  0111_1001  0x79  121  y  
  94	:  0010_0000  0x20   32     
  95	:  0100_0100  0x44   68  D  
  96	:  0110_1111  0x6F  111  o  
  97	:  0110_0111  0x67  103  g  
);
$name = 'goose.notfoo.bar.com';
my $txt = 'the quick Brown Fox jumped over the Lazy Dog';

# hex for $txt above
my $hex = '74686520717569636b2042726f776e20466f78206a756d706564206f76657220746865204c617a7920446f67';
my $str = pack('H88',$hex);
$off = $newoff;
my $ttl = 86400;
$type = 65341;
$class = C_IN;
($newoff,@dnptrs) = $put->TYPE65341(\$buffer,$off,\@dnptrs,$name,$type,$class,$ttl,$str);

#print_buf(\$buffer);
#print_ptrs(@dnptrs);
chk_exp(\$buffer,\$exptext);

## test 12	check offset
print "bad offset, $newoff, exp: 98\nnot "
	unless $newoff == 98;
&ok;

# change type of return record
my $exp = 0xff3d;
put1char(\$buffer,44,0xFF);		# type 65341
put1char(\$buffer,45,0x3d);
#print_buf(\$buffer);
## test 13	get, check offset
$newoff = 0; 
($newoff,$newname,$newtype,$newclass, my $newttl, my $rdlength, my $newtext) = $get->TYPE65341(\$buffer,$off);
#print "$newoff, $newname, $newtype, $newclass, $newttl, $rdlength, $newtext\n";
print "bad offset, $newoff, exp: 98\nnot "
	unless $newoff == 98;
&ok;

## test 14	check name
print "bad name, $newname, exp: $name\nnot "
	unless $newname eq $name;
&ok;

## test 15	check type
print "bad type: $newtype, exp: $exp\nnot "
	unless $newtype == $exp;
&ok;

## test 16	check class
print "bad type: ",ClassTxt->{$newclass},", exp: ",ClassTxt->{$class},"\nnot "
	unless $newclass == $class;
&ok;

## test 17	check ttl
print "bad ttl, $newttl, exp: $ttl\nnot "
	unless $newttl == $ttl;
&ok;

## test 18	check rdlength
print "bad rdlength, $rdlength, exp: 44\nnot "
	unless $rdlength == 44;
&ok;

## test 19	check txt
print "got: $newtext\nexp: $txt\nnot "
	unless $newtext eq $txt;
&ok;

## test 20	check parse, name first
($name,$type,$class,$ttl,$rdlength, my $parsetxt) =
  $parse->TYPE65341($newname,$newtype,$newclass,$newttl,$rdlength,$newtext);
print "name does not match\ngot: $name\nexp: $newname.\nnot "
	unless $name eq $newname.'.';
&ok;

$newname = $name;

## test 21	check type
$exp = 'TYPE65341';
print "bad type: $type, exp: $exp\nnot "
	unless $type eq $exp;
&ok;

## test 22	check class
print "bad class: $class, exp: ",ClassTxt->{$newclass},"\nnot "
	unless $class eq ClassTxt->{$newclass};
&ok;

## test 23	check ttl, pass thru
print "ttl does not match, got: $ttl, exp: $newttl\nnot "
	unless $ttl == $newttl;
&ok;

## test 24	rdlength, pass thru
print "bad rdlength, $rdlength, exp: 44\nnot "
	unless $rdlength == 44;
&ok;

$exp = '\# 44 74686520717569636b2042726f776e20466f78206a756d706564206f76657220746865204c617a7920446f67';
## test 25	check text conversion
print "got: $parsetxt\nexp: $exp\nnot "
	unless $parsetxt eq $exp;
&ok;
