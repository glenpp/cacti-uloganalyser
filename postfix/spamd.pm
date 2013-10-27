#!/usr/bin/perl
use strict;
use warnings;
# process the mail log and place the results in a file

# Copyright (C) 2012  Glen Pitt-Pladdy
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
# See: https://www.pitt-pladdy.com/blog/_20091122-164951%2B0000%20Postfix%20stats%20on%20Cacti%20%28via%20SNMP%29/
#
package spamd;
our $VERSION = 20120421;
our $REQULOGANALYSER = 20120420;
#
# Thanks for ideas, unhandled log lines, patches and feedback to:
#
# "oneloveamaru"


sub register {
	my ( $lines, $ends, $uloganalyserver ) = @_;
	push @$lines, \&analyse;
	if ( ! defined $uloganalyserver or $uloganalyserver < $REQULOGANALYSER ) {
		die __FILE__.": FATAL - Requeire uloganalyser version $REQULOGANALYSER or higher\n";
	}
}



our $time = 0;
our $messages = 0;
sub analyse {
	my ( $line, $number, $log, $stats ) = @_;
	my $origline = $line;
	if ( $line !~ s/^.+ spamd\[\d+\]:\s+spamd:\s+// ) { return; }
	# spamd making this noise so let's look closer
	# ignore server, connection, setuid, creating, processing
	if ( $line =~ /^(server|connection from|setuid to|creating default_prefs:|failed to create readable default_prefs:|processing message|handle_user|still running as root:|handled cleanup of child pid)\s+/ ) { return; }
	# it's something we are interested in
	if ( $line =~ s/([\w\s]+) \(([\-\d\.]+)\/([\d\.]+)\) for .+:\d+ in ([\d\.]+) seconds, \d+ bytes\.$// ) {
		++$$stats{'spamd:total'};
		my ( $verdict, $score, $threshold, $proctime ) = ( $1, $2, $3, $4 );
		if ( $score >= $threshold * 3 ) {
			++$$stats{'spamd:spam3'};
		} elsif ( $score >= $threshold * 2 ) {
			++$$stats{'spamd:spam2'};
		} elsif ( $score >= $threshold ) {
			++$$stats{'spamd:spam1'};
		} elsif ( $score > 0 ) {
			++$$stats{'spamd:spam0'};
		} elsif ( $score <= -$threshold * 2 ) {
			++$$stats{'spamd:ham2'};
		} elsif ( $score <= -$threshold ) {
			++$$stats{'spamd:ham1'};
		} else {
			++$$stats{'spamd:ham0'};
		}
		# work out average processing time
		$time += $proctime;
		++$messages;
		$$stats{'spamd:avproctime'} = $time / $messages;
	} elsif ( $line =~ s/result: (.) ([\-\d]+) -\s+// ) {
		# this tells us less that we know from above - ignore it for now
	} else {
		++$$stats{'clamav:other'};
		print STDERR __FILE__." $VERSION:".__LINE__." $log:$number unknown: $origline\n";
	}
	return 1;
}





\&register;
