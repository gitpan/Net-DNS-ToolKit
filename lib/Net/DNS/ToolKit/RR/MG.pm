package Net::DNS::ToolKit::RR::MG;

use strict;
#use warnings;

use vars qw($VERSION);

$VERSION = do { my @r = (q$Revision: 0.02 $ =~ /\d+/g); sprintf "%d."."%02d" x $#r, @r };

require Net::DNS::ToolKit::RR::NS;

*get = \&Net::DNS::ToolKit::RR::NS::get;
*put = \&Net::DNS::ToolKit::RR::NS::put;
*parse = \&Net::DNS::ToolKit::RR::NS::parse;

=head1 NAME

Net::DNS::ToolKit::RR::MG - Resource Record Handler

=head1 SYNOPSIS

  DO NOT use Net::DNS::ToolKit::RR::MG
  DO NOT require Net::DNS::ToolKit::RR::MG

  Net::DNS::ToolKit::RR::MG is autoloaded by 
  class Net::DNS::ToolKit::RR and its methods
  are instantiated in a 'special' manner.

  use Net::DNS::ToolKit::RR;
  ($get,$put,$parse) = new Net::DNS::ToolKit::RR;

  ($newoff,$name,$type,$class,$ttl,$rdlength,
        $madname) = $get->MG(\$buffer,$offset);

  Note: the $get->MG method is normally called
  via:  @stuff = $get->next(\$buffer,$offset);

  ($newoff,@dnptrs)=$put->MG(\$buffer,$offset,\@dnptrs,
	$name,$type,$class,$ttl,$rdlength,$madname);

  $NAME,$TYPE,$CLASS,$TTL,$rdlength,$MADNAME) 
    = $parse->MG($name,$type,$class,$ttl,$rdlength,
        $madname);

=head1 DESCRIPTION

B<Net::DNS::ToolKit::RR:MG> appends an MG resource record to a DNS packet under
construction, recovers an MG resource record from a packet being decoded, and 
converts the numeric/binary portions of the resource record to human
readable form.

  Description from RFC1035.txt

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

    3.3.3. MG RDATA format (EXPERIMENTAL)

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                   MADNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

    where:

    MADNAME A <domain-name> which specifies a host which 
	has the specified mailbox.

=over 4

=item * @stuff = $get->MG(\$buffer,$offset);

  Get the contents of the resource record.

  USE: @stuff = $get->next(\$buffer,$offset);

  where: @stuff = (
  $newoff $name,$type,$class,$ttl,$rdlength,
  $madname );

All except the last item, B<$madname>, is provided by
the class loader, B<Net::DNS::ToolKit::RR>. The code in this method knows
how to retrieve B<$madname>.

  input:        pointer to buffer,
                offset into buffer
  returns:      offset to next resource,
                @common RR elements,
		MG Domain Name

=item * ($newoff,@dnptrs)=$put->MG(\$buffer,$offset,\@dnptrs,
	$name,$type,$class,$ttl,$rdlength,$madname);

Append an MG record to $buffer.

  where @common = (
	$name,$type,$class,$ttl);

The method will insert the $rdlength and $madname, then
pass through the updated pointer to the array of compressed names            

The class loader, B<Net::DNS::ToolKit::RR>, inserts the @common elements and
returns updated @dnptrs. This module knows how to insert its RDATA and
calculate the $rdlength.

  input:        pointer to buffer,
                offset (normally end of buffer), 
                pointer to compressed name array,
                @common RR elements,
		MG Domain Name
  output:       offset to next RR,
                new compressed name pointer array,
           or   empty list () on error.

=item * (@COMMON,$MADNAME) = $parse->MG(@common,$madname);

Converts binary/numeric field data into human readable form. The common RR
elements are supplied by the class loader, B<Net::DNS::ToolKit::RR>.
For MG RR's, this returns the $madname terminated with '.'

  input:	MG Domain Name
  returns:	MG Domain Name.

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
