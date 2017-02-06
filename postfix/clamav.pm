#!/usr/bin/perl
use strict;
use warnings;
# process the mail log and place the results in a file

# Copyright (C) 2009  Glen Pitt-Pladdy
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
#
# See: https://www.pitt-pladdy.com/blog/_20091122-164951_0000_Postfix_stats_on_Cacti_via_SNMP_/
#
package clamav;
our $VERSION = 20170206;
#
# Thanks for ideas, unhandled log lines, patches and feedback to:
#
# "jangrewe" https://github.com/jangrewe


sub register {
	my ( $lines, $ends ) = @_;
	push @$lines, \&analyse;
}



sub analyse {
	my ( $line, $number, $log, $stats ) = @_;
	my $origline = $line;
	if ( $line !~ s/^.+ clamav-milter\[\d+\]: Message [\dA-F]+ from <.+> to <.+> .+infected by\s+// ) { return; }
	# clam found something
	++$$stats{'clamav:found'};
	if ( $line =~ /(trojan)/i
		or $line =~ /Heuristics\.(phishing)\./i
		or $line =~ /(phishing)\./i
		or $line =~ /(fraud)\./i
		or $line =~ /(scam)\./i
		or $line =~ /(exploit)\./i
		or $line =~ /(virus)\./i
		or $line =~ /(worm)\./i
		or $line =~ /(malware)\./i
		or $line =~ /(spam)\./i
		or $line =~ /(archive)\./i
		or $line =~ /(suspect)\./i ) {
		# we know about this - count it
		++$$stats{"clamav:found:".lc ( $1 )};
	} else {
		++$$stats{'clamav:other'};
		print STDERR __FILE__." $VERSION:".__LINE__." $log:$number unknown: $origline\n";
	}
	return 1;
}





\&register;
