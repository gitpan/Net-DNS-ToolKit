package Net::DNS::ToolKit::RR::RP;

use strict;
#use warnings;

use vars qw($VERSION);

$VERSION = do { my @r = (q$Revision: 0.01 $ =~ /\d+/g); sprintf "%d."."%02d" x $#r, @r };

require Net::DNS::ToolKit::RR::MINFO;       

*get = \&Net::DNS::ToolKit::RR::MINFO::get;  
*put = \&Net::DNS::ToolKit::RR::MINFO::put;  
*parse = \&Net::DNS::ToolKit::RR::MINFO::parse;  

=head1 NAME

Net::DNS::ToolKit::RR::RP - Resource Record Handler

=head1 SYNOPSIS

  DO NOT use Net::DNS::ToolKit::RR::RP
  DO NOT require Net::DNS::ToolKit::RR::RP

  Net::DNS::ToolKit::RR::RP is autoloaded by 
  class Net::DNS::ToolKit::RR and its methods
  are instantiated in a 'special' manner.

  use Net::DNS::ToolKit::RR;
  ($get,$put,$parse) = new Net::DNS::ToolKit::RR;

  ($newoff,$name,$type,$class,$ttl,$rdlength,
        $rname,$tname) = $get->RP(\$buffer,$offset);

  Note: the $get->RP method is normally called
  via:  @stuff = $get->next(\$buffer,$offset);

  ($newoff,@dnptrs)=$put->RP(\$buffer,$offset,\@dnptrs,
	$name,$type,$class,$ttl,$rname,$tname);

  $NAME,$TYPE,$CLASS,$TTL,$rdlength,$RP) 
    = $parse->XYZ($name,$type,$class,$ttl,$rdlength,
        $rname,$tname);

=head1 DESCRIPTION

B<Net::DNS::ToolKit::RR:RP> appends an RP resource record to a DNS packet under
construction, recovers an RP resource record from a packet being decoded, and 
converts the numeric/binary portions of the resource record to human
readable form.

  Description from RFC1035.txt and RFC1183.txt

  3.2.1. Format

  All RRs have the same top level format shown below:

                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      NAME                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     CLASS                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TTL                      |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                   RDLENGTH                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
    |                     RDATA                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

  NAME	an owner name, i.e., the name of the node to which this
	resource record pertains.

  TYPE	two octets containing one of the RR TYPE codes.

  CLASS	two octets containing one of the RR CLASS codes.

  TTL	a 32 bit signed integer that specifies the time interval
	that the resource record may be cached before the source
	of the information should again be consulted.  Zero
	values are interpreted to mean that the RR can only be
	used for the transaction in progress, and should not be
	cached.  For example, SOA records are always distributed
	with a zero TTL to prohibit caching.  Zero values can
	also be used for extremely volatile data.

  RDLENGTH an unsigned 16 bit integer that specifies the length
	in octets of the RDATA field.

  RDATA	a variable length string of octets that describes the
	resource.  The format of this information varies
	according to the TYPE and CLASS of the resource record.

  RFC1183 2.2. The Responsible Person RR
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     RNAME                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     TNAME                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

   Both RDATA fields are required in all RP RRs.

   The first field, RNAME, is a domain name that specifies the
   mailbox for the responsible person.  Its format in master files uses
   the DNS convention for mailbox encoding, identical to that used for
   the RNAME mailbox field in the SOA RR.  The root domain name (just
   ".") may be specified for <mbox-dname> to indicate that no mailbox is
   available.

   The second field, TNAME, is a domain name for which TXT RR's
   exist.  A subsequent query can be performed to retrieve the
   associated TXT resource records at <txt-dname>.  This provides a
   level of indirection so that the entity can be referred to from
   multiple places in the DNS.  The root domain name (just ".") may be
   specified for <txt-dname> to indicate that the TXT_DNAME is absent,
   and no associated TXT RR exists.

   The format of the RP RR is class insensitive.  RP records cause no
   additional section processing. 

=over 4

=item * @stuff = $get->RP(\$buffer,$offset);

  Get the contents of the resource record.

  USE: @stuff = $get->next(\$buffer,$offset);

  where: @stuff = (
  $newoff $name,$type,$class,$ttl,$rdlength,
  $rname,$tname );

All except the last item, B<$cname>, is provided by
the class loader, B<Net::DNS::ToolKit::RR>. The code in this method knows
how to retrieve B<$cname>.

  input:        pointer to buffer,
                offset into buffer
  returns:      offset to next resource,
                @common RR elements,
		responsible.person.mail.box
		domain.where.txt.records.exist

=item * ($newoff,@dnptrs)=$put->RP(\$buffer,$offset,\@dnptrs,
	$name,$type,$class,$ttl,$rname,$tname);

Append an RP record to $buffer.

  where @common = (
	$name,$type,$class,$ttl);

The method will insert the $rdlength, $rname and $tname, then
pass through the updated pointer to the array of compressed names            

The class loader, B<Net::DNS::ToolKit::RR>, inserts the @common elements and
returns updated @dnptrs. This module knows how to insert its RDATA and
calculate the $rdlength.

  input:        pointer to buffer,
                offset (normally end of buffer), 
                pointer to compressed name array,
                @common RR elements,
		responsible.person.mail.box
		domain.where.txt.records.exist
  output:       offset to next RR,
                new compressed name pointer array,
           or   empty list () on error.

=item * (@COMMON,$RP) = $parse->RP(@common,$rname,$tname);

Converts binary/numeric field data into human readable form. The common RR
elements are supplied by the class loader, B<Net::DNS::ToolKit::RR>.
For RP RR's, this returns the $cname terminated with '.'

  input:	responsible.person.mail.box,
		domain.where.txt.records.exist
  returns:	responsible.person.mail.box.,
		domain.where.txt.records.exist.

=back

=head1 DEPENDENCIES

	Net::DNS::ToolKit
	Net::DNS::Codes
	Net::DNS::ToolKit::RR::NS

=head1 EXPORT

	none

=head1 AUTHOR

Michael Robinton <michael@bizsystems.com>

=head1 COPYRIGHT

    Copyright 2003 - 2011, Michael Robinton <michael@bizsystems.com>
   
Michael Robinton <michael@bizsystems.com>

All rights reserved.

This program is free software; you can redistribute it and/or modify
it under the terms of either:

  a) the GNU General Public License as published by the Free
  Software Foundation; either version 2, or (at your option) any
  later version, or

  b) the "Artistic License" which comes with this distribution.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of 
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See either    
the GNU General Public License or the Artistic License for more details.

You should have received a copy of the Artistic License with this
distribution, in the file named "Artistic".  If not, I'll be glad to provide
one.

You should also have received a copy of the GNU General Public License
along with this program in the file named "Copying". If not, write to the

        Free Software Foundation, Inc.                        
        59 Temple Place, Suite 330
        Boston, MA  02111-1307, USA                                     

or visit their web page on the internet at:                      

        http://www.gnu.org/copyleft/gpl.html.

=head1 See also:

Net::DNS::Codes(3), Net::DNS::ToolKit(3)

=cut

1;
