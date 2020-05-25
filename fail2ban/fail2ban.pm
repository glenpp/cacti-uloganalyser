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
# See: https://silent.pitt-pladdy.com/blog/_20130324-154457_0000_fail2ban_on_Cacti_via_SNMP/
#
package fail2ban;
our $VERSION = 20200525;
our $DEBUG = 0;
#
# Thanks for ideas, unhandled log lines, patches and feedback to:
#
# Voytek Eymont


sub register {
	my ( $lines, $ends ) = @_;
	push @$lines, \&analyse;
}


# update this to match your fail2ban configuration
our %CLASSES = (
	'postfix' => 'mail',
	'sasl' => 'mail',
	'postfix-local' => 'mail',
	'postfix-local2' => 'mail',
	'dovecot-local' => 'mail',
	'ssh' => 'ssh',
	'apache' => 'www',
	'apache-badbots' => 'www',
	'apache-nohome' => 'www',
	'apache-noscript' => 'www',
	'apache-overflows' => 'www',
	'apache-local' => 'www',
	'named-refused' => 'dns',
#	'' => '',
);



sub analyse {
	my ( $line, $number, $log, $stats ) = @_;
	my $origline = $line;
	my $multiply = 1;
	if ( $line !~ s/^.+? fail2ban\.(\w+)\s*:\s+(\w+)\s+//
		and $line !~ s/^.+? fail2ban\.(\w+)\s*\[\d+\]:\s+(\w+)\s+// ) { return; }
	my ( $component, $level ) = ( $1, $2 );
	# detect "message repeated N times:"
	if( $line =~ s/^message repeated (\d+) times: \[\s*(.+)\]$/$2/ ) {
		$multiply = $1;
	}
	if ( $level eq 'INFO' ) {
		if ( $line =~ s/^Exiting Fail2ban$//
				or $line =~ s/^Stopping all jails//	# also indicates jails cleared (reload)
		) {
			# reset counters on exit
			for (keys %$stats) {
				if ( /^fail2ban:banned:/ ) { $$stats{$_} = 0; }
			}
		} elsif ( 0	# placeholder for neatness
				# shutdown
				or $line =~ s/^Shutdown in progress\.\.\.//
				or $line =~ s/^Removed logfile: '\/[^\s]+//
				or $line =~ s/^Jail '[^']+' stopped//
				or $line =~ s/^Connection to database closed\.//
				or $line =~ s/^----------------------------------------//
				# startup
				or $line =~ s/^Starting Fail2ban v//
				or $line =~ s/^Connected to fail2ban persistent database//
				# startup jails
				or $line =~ s/^Creating new jail '[\w\-]+'//
				or $line =~ s/^Jail '[\w\-]+' uses (pyinotify|systemd|poller) \{\}$//
				or $line =~ s/^Initiated '(pyinotify|systemd|polling)' backend$//
				or $line =~ s/^maxLines: 1//
				#or $line =~ s/^Jail '[^']+' uses (poller|Gamin)//
				or $line =~ s/^Jail [\w\-]+ is not a JournalFilter instance$//
				or $line =~ s/^Added logfile: '\/[^\s]+//
				or $line =~ s/^encoding: UTF-8$//
				or $line =~ s/^maxRetry: \d+//
				or $line =~ s/^findtime: \d+//
				or $line =~ s/^banTime: \d+//
				or $line =~ s/^Jail '[\w\-]+' started//
				# detection
				or $line =~ s/^\[[\w\-]+\]\s+Found\s+[\da-f\.:]+(\s+-\s+.*)?$//	# detections TODO do we want to graph these even though they don't directly result in a ban
				# log rotation
				or $line =~ s/^rollover performed on \/var\/log\/fail2ban\.log$//
				# misc
				or $line =~ s/^\[[\w\-]+\] Added journal match for: //
				
		) {
			# ignore regular operation
		} else {
			warn __FILE__." $VERSION:".__LINE__." $log:$number unknown fail2ban: $origline\n";
		}
	} elsif ( $level eq 'WARNING' or $level eq 'NOTICE' ) {
		if ( $line =~ s/^\[([\w\-]+)\] (Restore )?Ban [\da-f\.:]+$// ) {
			if ( exists $CLASSES{$1} ) {
				if ( ! exists $$stats{"fail2ban:banned:$CLASSES{$1}"} ) {
					$$stats{"fail2ban:banned:$CLASSES{$1}"} = 0;
				}
				if ( $DEBUG ) { print "ban : fail2ban:banned:$CLASSES{$1}\n"; }
#print $$stats{"fail2ban:banned:$CLASSES{$1}"}." => ";
				$$stats{"fail2ban:banned:$CLASSES{$1}"} += $multiply;
				if ( $DEBUG ) { print $$stats{"fail2ban:banned:$CLASSES{$1}"}."\n"; }
			} else {
				warn __FILE__." $VERSION:".__LINE__." $log:$number unknown class \"$1\" fail2ban: $origline\nupdate %CLASSES to match your configuration\n";
				$$stats{"fail2ban:banned:other"} += $multiply;
			}
		} elsif ( $line =~ s/\[([^\]]+)\] Unban ([\da-f\.:]+)$// ) {
			if ( exists $CLASSES{$1} ) {
				if ( ! exists $$stats{"fail2ban:banned:$CLASSES{$1}"} ) {
					$$stats{"fail2ban:banned:$CLASSES{$1}"} = 0;
				}
				if ( $DEBUG ) { print "unban : fail2ban:banned:$CLASSES{$1}\n"; }
#print $$stats{"fail2ban:banned:$CLASSES{$1}"}." => ";
				$$stats{"fail2ban:banned:$CLASSES{$1}"} -= $multiply;
				if ( $$stats{"fail2ban:banned:$CLASSES{$1}"} < 0 ) { $$stats{"fail2ban:banned:$CLASSES{$1}"} = 0; }
				if ( $DEBUG ) { print $$stats{"fail2ban:banned:$CLASSES{$1}"}."\n"; }
			} else {
				warn __FILE__." $VERSION:".__LINE__." $log:$number unknown class \"$1\" fail2ban: $origline\nupdate %CLASSES to match your configuration\n";
				$$stats{"fail2ban:banned:other"} -= $multiply;
				if ( $$stats{"fail2ban:banned:other"} < 0 ) { $$stats{"fail2ban:banned:other"} = 0; }
			}
		} elsif ( $line =~ s/\[([^\]]+)\] ([\da-f\.:]+) already banned$// ) {
			# ignore
		} elsif ( $line =~ s/^\[[\w\-]+\] Flush ticket\(s\) with // ) {
			# ignore
		} else {
			warn __FILE__." $VERSION:".__LINE__." $log:$number unknown fail2ban: $origline\n";
		}
	} else {
		warn __FILE__." $VERSION:".__LINE__." $log:$number unknown fail2ban: $origline\n";
	}
	return 1;
}





\&register;
