package Net::DNS::ToolKit::Debug;

#use 5.006;
use strict;
#use diagnostics;
#use warnings;

use AutoLoader qw(AUTOLOAD);
use vars qw($VERSION @EXPORT_OK @ISA);
use Net::DNS::Codes qw(:header :all);
use Net::DNS::ToolKit qw(
	gethead
	get1char
	parse_char
);
require Exporter;
@ISA = qw(Exporter);

$VERSION = do { my @r = (q$Revision: 0.03 $ =~ /\d+/g); sprintf "%d."."%02d" x $#r, @r };

@EXPORT_OK = qw(
	print_head
	print_buf
);

sub DESTROY {}

1;
__END__

=head1 NAME

Net::DNS::ToolKit::Debug - ToolKit print tools

=head1 SYNOPSIS

  use Net::DNS::ToolKit::Debug qw(
	print_head
	print_buf
  );

  STDOUT <= print_head(\$buffer);
  STDOUT <= print_buf(\$buffer,$from,$to);

=head1 DESCRIPTION

Functions to print/examine DNS buffers.

=over 4

=item * STDOUT <= print_head(\$buffer);

Print a formated text description of the header.

  input:	pointer to buffer

  output:	to STDOUT

  ID      => 1234    
  QR      => 1  
  OPCODE  => QUERY
  AA      => 0 
  TC      => 0
  RD      => 1   
  RA      => 0
  Z       => 0
  AD      => 0
  CD      => 0
  RCODE   => NOERROR
  QDCOUNT => 1
  ANCOUNT => 5
  NSCOUNT => 2
  ARCOUNT => 3

=cut

sub print_head {
  my ($bp) = @_;
  my($offset,$ID,$QR,$OPCODE,$AA,$TC,$RD,$RA,$Z,$AD,$CD,$RCODE,
        $QDCOUNT,$ANCOUNT,$NSCOUNT,$ARCOUNT) = gethead($bp);
  print "
  ID      => $ID
  QR      => $QR
  OPCODE  => ",OpcodeTxt->{$OPCODE},"
  AA      => $AA
  TC      => $TC
  RD      => $RD
  RA      => $RA    
  Z       => $Z   
  AD      => $AD  
  CD      => $CD
  RCODE   => ",RcodeTxt->{$RCODE},"
  QDCOUNT => $QDCOUNT
  ANCOUNT => $ANCOUNT
  NSCOUNT => $NSCOUNT
  ARCOUNT => $ARCOUNT\n";
}

=item * STDOUT <= print_buf(\$buffer,$from,$to);

Print a formated description of the $buffer contents.

  input:	$from [start],
		$to   [end],

  output:	to STDOUT

  If $from is missing, begin at $buffer start.
  If $to is missing, end at $buffer end.

  Prints nothing if $from > $to.

=back

=cut

sub print_buf {
  my($bp,$from,$to) = @_;
  $from = 0 unless $from;
  $to = length($$bp) -1 unless $to;
  return if $from > $to;

  foreach ($from..$to) {
    my $off = $_;
    my $char = get1char($bp,$off);
    @_ = parse_char($char);
    print "  $_\t:  ";
    foreach(@_) {     
      print "$_  ";   
    }  
    print "\n";
  }
}

=head1 DEPENDENCIES

	Net::DNS::ToolKit

=head1 EXPORT_OK

        print_head
        print_buf

=head1 AUTHOR

Michael Robinton <michael@bizsystems.com>

=head1 COPYRIGHT

    Copyright 2003, Michael Robinton <michael@bizsystems.com>
   
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
   
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
   
    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

=head1 See also:

Net::DNS::Codes(3), Net::DNS::ToolKit(3)

=cut

1;

