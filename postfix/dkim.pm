use strict;
use warnings;
# process the mail log lines for dkim-filter

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
# See: http://www.pitt-pladdy.com/blog/_20091122-164951%2B0000%20Postfix%20stats%20on%20Cacti%20%28via%20SNMP%29/
#
package dkim;
our $VERSION = 20121002;
#
# Thanks for ideas, unhandled log lines, patches and feedback to:
#


sub register {
	my ( $lines, $ends ) = @_;
	push @$lines, \&analyse;
}


sub analyse {
	my ( $line, $number, $log, $stats ) = @_;
	my $origline = $line;
	if ( $line !~ s/^.+ dkim-filter\[\d+\]:\s*// ) { return; }
	if ( $line =~ s/[0-9A-F]+\s"DKIM-Signature" header added$// ) {
		++$$stats{'dkim-filter:addedsignature'};
	} elsif ( $line =~ s/[0-9A-F]+:\sno signature data$// ) {
		++$$stats{'dkim-filter:nosignature'};
	} elsif ( $line =~ s/[0-9A-F]+.*\sSSL error:04077068:rsa routines:RSA_verify:bad signature$// ) {
		++$$stats{'dkim-filter:badsignature'};
	} elsif ( $line =~ s/[0-9A-F]+:\sbad signature data// ) {
		++$$stats{'dkim-filter:badsignaturedata'};
	} elsif ( $line =~ s/[0-9A-F]+:\skey retrieval failed$// ) {
		++$$stats{'dkim-filter:keyretrievalfail'};
	} elsif ( $line =~ s/[0-9A-F]+\sDKIM verification successful$// ) {
		++$$stats{'dkim-filter:verifysuccess'};
	} elsif ( $line =~ s/[0-9A-F]+\scan't parse From: header value //
		or $line =~ s/[0-9A-F]+\sno sender header found; accepting// ) {
		++$$stats{'dkim-filter:badheader'};
	} elsif ( $line =~ s/message has signatures from //
		or $line =~ s/[0-9A-F]+:\sdkim_eoh\(\): internal error from libdkim: ar_addquery\(\) for `.+' failed//	# maybe we shouldn't ignore this, but it appears to be ignored by postfix
		or $line =~ /[0-9A-F]+ SSL error:[0-9A-F]+:rsa /
		or $line =~ /[0-9A-F]+ failed to parse Authentication-Results: header/
		or $line =~ /[0-9A-F]+\sADSP query: ar_addquery\(\) for `_adsp\._domainkey\.[^\s]+' failed/
		or $line =~ /[0-9A-F]+\sADSP query: missing parameter\(s\) in policy data/
		or $line =~ /Sendmail DKIM Filter: connect\[0\]: mi_inet_pton failed/
		or $line =~ /message has signatures from/ ) {
		# ignore
	} elsif ( $line =~ s/Sendmail DKIM Filter v.+ starting// ) {
		# ignore
	} else {
		++$$stats{'dkim-filter:other'};
		print STDERR __FILE__." $VERSION:".__LINE__." $log:$number unknown: $origline\n";
	}
	return 1;	# it was for us!
}







\&register;
