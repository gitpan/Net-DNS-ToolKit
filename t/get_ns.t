# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

######################### We start with some black magic to print on failure.
# Change 1..1 below to 1..last_test_to_print .
# (It may become useful if the test is moved to ./t subdirectory.)

BEGIN { $| = 1; print "1..2\n"; }
END {print "not ok 1\n" unless $loaded;}

use Net::DNS::ToolKit qw(
	get_ns
	inet_ntoa
);

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

my @netaddrs = get_ns();

my $output = "\n\tlocal nameserver(s)\n";
if (@netaddrs) {
  foreach(@netaddrs) {
    $output .= "\t".inet_ntoa($_)."\n";
  }
  print STDERR $output;
} else {
  select STDERR; $| = 1;
  select STDOUT;
  print STDERR q|
The resolver library did not return any nameservers. This could
mean that your system is not properly configured, or more likely
that the ToolKit.pm interface to the "C" resolver library is not
working properly. 

This latter condition has been reported with versions of perl 5.8x
on some systems, however the author has not been able to duplicate
it on in house hosts. If you have a system that exhibits this problem
and can provide a shell account for debug purposes, please contact 
the author, Michael Robinton <michael@bizsystems.com> .
|;
  sleep 1;
  print "\nnot ";
}
print "ok 2\n";
