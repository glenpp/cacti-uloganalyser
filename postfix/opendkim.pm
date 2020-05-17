use strict;
use warnings;
# process the mail log lines for opendkim

# Copyright (C) 2014-2015 Glen Pitt-Pladdy
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
# See: https://www.pitt-pladdy.com/blog/_20150213-225132_0000_opendkim_on_Cacti_via_SNMP/
#
package opendkim;
our $VERSION = 20200517;
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
	if ( $line !~ s/^.+ opendkim\[\d+\]:\s*// ) { return; }
	if ( $line =~ /^[0-9A-F]+: DKIM-Signature (header|field) added \([^\)]+\)/ ) {
		++$$stats{'opendkim:addedsignature'};
	} elsif ( $line =~ s/[0-9A-F]+.*\sSSL error:04091068:rsa routines:INT_RSA_VERIFY:bad signature$// ) {
		++$$stats{'opendkim:badsignature'};
	} elsif ( $line =~ s/[0-9A-F]+:\sbad signature data// ) {
		++$$stats{'opendkim:badsignaturedata'};
	} elsif ( $line =~ /^[0-9A-F]+: no signature data$/ ) {
		++$$stats{'opendkim:nosignature'};
	} elsif ( $line =~ /^[0-9A-F]+: no signing table match for '.+'$/ ) {
		# ignore - inconsequential: occurs when we get an internal sub-domain that isn't configured for signing
	} elsif ( $line =~ /^[0-9A-F]+: failed to parse [aA]uthentication-[rR]esults: header( field)?$/ ) {
		# ignore - inconsequential
	} elsif ( $line =~ /^[0-9A-F]+: .+ \[.+\] not internal$/ ) {
		# ignore - inconsequential
	} elsif ( $line =~ /^[0-9A-F]+: not authenticated$/ ) {
		# ignore - inconsequential
	} elsif ( $line =~ /^[0-9A-F]+: ADSP query: '_adsp\._domainkey\.[^']+' reply was unresolved CNAME$/ ) {
		# ignore - inconsequential: just couldn't lookup key
	} elsif ( $line =~ /^[0-9A-F]+: DKIM verification successful$/ ) {
		++$$stats{'opendkim:verifysuccess'};
	} elsif ( $line =~ s/[0-9A-F]+:\skey retrieval failed// ) {
		++$$stats{'opendkim:keyretrievalfail'};
	} elsif ( $line =~ s/^[0-9A-F]+: s=[^\s]+ d=[^\s]+ SSL// ) {
		# ignore
	} elsif ( $line =~ s/^ignoring header field 'X-CSA-Complaints;Require-Recipient-Valid-Since'// ) {
		# ignore
	} elsif ( $line =~ s/[0-9A-F]+:\ss=ED-DKIM-V3 d=.+ SSL error:0407006A:rsa routines:RSA_padding_check_PKCS1_type_1:block type is not 01; error:04067072:rsa routines:RSA_EAY_PUBLIC_DECRYPT:padding check failed// ) {
		# ignore - associated with "bad signature data" above TODO
	} elsif ( $line =~ s/^[0-9A-F]+: message has signatures from // ) {
		# ignore
	} elsif ( $line =~ s/^[0-9A-F]+: can't parse From: header value // ) {
		# ignore
	} elsif ( $line =~ s/OpenDKIM Filter: mi_stop=1//
			or $line =~ s/OpenDKIM Filter v\d[\.\d]+ terminating with status 0, errno = 0//
			or $line =~ s/OpenDKIM Filter: Opening listen socket on conn inet:\d+\@localhost//
			or $line =~ s/OpenDKIM Filter v\d[\.\d]+ starting \(args: [^\)]*\)// ) {
		# ignore start / stop stuff
	} else {
		++$$stats{'opendkim:other'};
		print STDERR __FILE__." $VERSION:".__LINE__." $log:$number unknown: $origline\n";
	}

# Typical good message:
#	not internal
#	verification successful


# TODO old rules TODO
#if ( $line =~ s/[0-9A-F]+\s"DKIM-Signature" header added$// ) {
#++$$stats{'opendkim:addedsignature'};
# elsif ( $line =~ s/[0-9A-F]+:\sno signature data$// ) {
#++$$stats{'opendkim:nosignature'};
#} elsif ( $line =~ s/[0-9A-F]+.*\sSSL error:04077068:rsa routines:RSA_verify:bad signature$// ) {
#++$$stats{'opendkim:badsignature'};
#} elsif ( $line =~ s/[0-9A-F]+:\sbad signature data// ) {
#++$$stats{'opendkim:badsignaturedata'};
#} elsif ( $line =~ s/[0-9A-F]+\sDKIM verification successful$// ) {
#++$$stats{'opendkim:verifysuccess'};
#	} elsif ( $line =~ s/[0-9A-F]+\scan't parse From: header value //
#		or $line =~ s/[0-9A-F]+\sno sender header found; accepting// ) {
#		++$$stats{'opendkim:badheader'};
#} elsif ( $line =~ s/message has signatures from //
#		or $line =~ s/[0-9A-F]+:\sdkim_eoh\(\): internal error from libdkim: ar_addquery\(\) for `.+' failed//	# maybe we shouldn't ignore this, but it appears to be ignored by postfix
#		or $line =~ /[0-9A-F]+ SSL error:[0-9A-F]+:rsa /
#		or $line =~ /[0-9A-F]+ failed to parse Authentication-Results: header/
#		or $line =~ /[0-9A-F]+\sADSP query: ar_addquery\(\) for `_adsp\._domainkey\.[^\s]+' failed/
#		or $line =~ /[0-9A-F]+\sADSP query: missing parameter\(s\) in policy data/
#		or $line =~ /[0-9A-F]+: syntax error: missing parameter\(s\) in signature data/
#		or $line =~ /Sendmail DKIM Filter: connect\[0\]: mi_inet_pton failed/
#		or $line =~ /message has signatures from/ ) {
#		# ignore
#	} elsif ( $line =~ s/Sendmail DKIM Filter v.+ starting// ) {
## ignore
#	} else {
#		++$$stats{'opendkim:other'};
#		print STDERR __FILE__." $VERSION:".__LINE__." $log:$number unknown: $origline\n";
#	}
	return 1;	# it was for us!
}







\&register;
