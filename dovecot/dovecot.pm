use strict;
use warnings;
# process the mail log and place the results in a file

# Copyright (C) 2009-2012  Glen Pitt-Pladdy
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
# See: http://www.pitt-pladdy.com/blog/_20110625-123333%2B0100%20Dovecot%20stats%20on%20Cacti%20%28via%20SNMP%29/
#
package dovecot;
our $VERSION = 20120809;
#
# Thanks for ideas, unhandled log lines, patches and feedback to:
#
# Daniele Palumbo
# Przemek Orzechowski
# "Alex"
# Voytek Eymont


sub register {
	my ( $lines, $ends ) = @_;
	push @$lines, \&analyse;
}






sub analyse {
	my ( $line, $number, $log, $stats ) = @_;
	my $origline = $line;
	my $multiply = 1;
	if ( $line !~ s/^.+? dovecot: // ) { return; }
	# detect "message repeated N times:"
	if( $line =~ s/^message repeated (\d+) times: \[\s*(.+)\]$/$2/ ) {
		$multiply = $1;
	}
	# on with the lines...
	if ( $line =~ s/auth\(\w+\): [\w\-]+\(.+\): // ) {
		if ( $line =~ s/^unknown user$// ) {
			$$stats{'dovecot:auth:unknownuser'} += $multiply;
		} elsif ( $line =~ s/^Password mismatch// ) {
			$$stats{'dovecot:auth:passwordmismatch'} += $multiply;
		} elsif ( $line =~ s/^Username contains disallowed character.*$// ) {
			$$stats{'dovecot:auth:disallowedchar'} += $multiply;
		} elsif ( $line =~ s/^Empty username$// ) {
			$$stats{'dovecot:auth:emptyusername'} += $multiply;
		} else {
			$$stats{'dovecot:auth:other'} += $multiply;
			print STDERR __FILE__." $VERSION:".__LINE__." $log:$number unknown dovecot: $origline\n";
		}
	} elsif ( $line =~ s/^(imap|pop3|managesieve)-login: // ) {
		my $protocol = $1;
		$$stats{"dovecot:$protocol:login"} += $multiply;
		if ( $line =~ s/^Login: // ) {
			$$stats{"dovecot:$protocol:login:success"} += $multiply;
			if ( $line =~ / method=(\w+),/ ) {
				if ( $1 eq 'PLAIN' ) {
					$$stats{"dovecot:$protocol:loginmethod:plain"} += $multiply;
				} elsif ( $1 eq 'LOGIN' ) {
					$$stats{"dovecot:$protocol:loginmethod:login"} += $multiply;
				} elsif ( $1 eq 'CRAM-MD5' ) {
					$$stats{"dovecot:$protocol:loginmethod:crammd5"} += $multiply;
				} elsif ( $1 eq 'DIGEST-MD5' ) {
					$$stats{"dovecot:$protocol:loginmethod:digestmd5"} += $multiply;
				} elsif ( $1 eq 'APOP' ) {	# POP3 only
					$$stats{"dovecot:$protocol:loginmethod:apop"} += $multiply;
				} elsif ( $1 eq 'NTLM' ) {
					$$stats{"dovecot:$protocol:loginmethod:ntlm"} += $multiply;
				} elsif ( $1 eq 'GSS-SPNEGO' ) {
					$$stats{"dovecot:$protocol:loginmethod:gssspnego"} += $multiply;
				} elsif ( $1 eq 'GSSAPI' ) {
					$$stats{"dovecot:$protocol:loginmethod:gssapi"} += $multiply;
				} elsif ( $1 eq 'RPA' ) {
					$$stats{"dovecot:$protocol:loginmethod:rpa"} += $multiply;
				} elsif ( $1 eq 'ANONYMOUS' ) {
					$$stats{"dovecot:$protocol:loginmethod:anonymous"} += $multiply;
				} elsif ( $1 eq 'OTP' ) {
					$$stats{"dovecot:$protocol:loginmethod:otp"} += $multiply;
				} elsif ( $1 eq 'SKEY' ) {
					$$stats{"dovecot:$protocol:loginmethod:skey"} += $multiply;
				} elsif ( $1 eq 'EXTERNAL' ) {
					$$stats{"dovecot:$protocol:loginmethod:external"} += $multiply;
				} else {
					$$stats{"dovecot:$protocol:loginmethod:other"} += $multiply;
					print STDERR __FILE__." $VERSION:".__LINE__." $log:$number unknown dovecot: $origline\n";
				}
			}
			if ( $line =~ /lip=[\da-f\.:]+$/ or $line =~ /lip=[\da-f\.:]+, mpid=\d+$/ ) {
				$$stats{"dovecot:$protocol:crypto:none"} += $multiply;
			} elsif ( $line =~ /lip=[\da-f\.:]+, TLS$/ or $line =~ /lip=[\da-f\.:]+, mpid=\d+, TLS$/ ) {
				$$stats{"dovecot:$protocol:crypto:tls"} += $multiply;
			} elsif ( $line =~ /lip=[\da-f\.:]+, secured$/ or $line =~ /lip=[\da-f\.:]+, mpid=\d+, secured$/ ) {
				$$stats{"dovecot:$protocol:crypto:ssl"} += $multiply;
			} else {
				$$stats{"dovecot:$protocol:crypto:other"} += $multiply;
				print STDERR __FILE__." $VERSION:".__LINE__." $log:$number unknown dovecot: $origline\n";
			}
		} elsif ( $line =~ s/^Disconnected[:\s]*// ) {
			$$stats{"dovecot:$protocol:login:disconnected"} += $multiply;
			# some dovecot versions give extra info TODO
			if ( $line =~ s/^Inactivity // ) {
				# TODO not currently used
			}
			if ( $line =~ s/^\(no auth attempts( in \d+ secs)?\):// ) {
				$$stats{"dovecot:$protocol:login:disconnected:noauthattempt"} += $multiply;
			} elsif ( $line =~ s/^\(auth failed, \d+ attempts( in \d+ secs)?\):// ) {
				$$stats{"dovecot:$protocol:login:disconnected:authfailed"} += $multiply;
			} elsif ( $line =~ s/^\(disconnected while authenticating\):// ) {
				$$stats{"dovecot:$protocol:login:disconnected:authenticating"} += $multiply;
			} elsif ( $line =~ s/^\(tried to use disabled plaintext auth\):// ) {
				$$stats{"dovecot:$protocol:login:disconnected:disabledauthmethod"} += $multiply;
			} else {
				$$stats{"dovecot:$protocol:login:disconnected:other"} += $multiply;
				print STDERR __FILE__." $VERSION:".__LINE__." $log:$number unknown dovecot: $origline\n";
			}
		} elsif ( $line =~ s/^Aborted login[:\s]*// ) {
			$$stats{"dovecot:$protocol:login:aborted"} += $multiply;
			if ( $line =~ s/^\(no auth attempts( in \d+ secs)?\):// ) {
				$$stats{"dovecot:$protocol:login:aborted:noauthattempt"} += $multiply;
			} elsif ( $line =~ s/^\(auth failed, \d+ attempts( in \d+ secs)?\):// ) {
				$$stats{"dovecot:$protocol:login:aborted:authfailed"} += $multiply;
			} elsif ( $line =~ s/^\(tried to use disabled plaintext auth\):// ) {
				$$stats{"dovecot:$protocol:login:aborted:disabledauthmethod"} += $multiply;
			} else {
				$$stats{"dovecot:$protocol:login:aborted:other"} += $multiply;
				print STDERR __FILE__." $VERSION:".__LINE__." $log:$number unknown dovecot: $origline\n";
			}
		} elsif ( $line =~ s/^Maximum number of connections from user\+IP exceeded // ) {
			$$stats{"dovecot:$protocol:login:maxconnections"} += $multiply;
		} else {
			$$stats{"dovecot:$protocol:login:other"} += $multiply;
			print STDERR __FILE__." $VERSION:".__LINE__." $log:$number unknown dovecot: $origline\n";
		}
	} elsif ( $line =~ s/(IMAP|POP3|MANAGESIEVE|imap|pop3|managesieve)(\([^\)]+\))?: // ) {
		my $protocol = lc $1;
		# harvest data stats if available
		if ( $line =~ s/\s* top=\d+\/(\d+), retr=\d+\/(\d+), del=\d+\/\d+, size=\d+$// ) {
			$$stats{"dovecot:$protocol:bytes:out"} += ( $1 + $2 ) * $multiply;
		} elsif ( $line =~ s/\s* bytes=(\d+)\/(\d+)$// ) {
			$$stats{"dovecot:$protocol:bytes:in"} += $1 * $multiply;
			$$stats{"dovecot:$protocol:bytes:out"} += $2 * $multiply;
		} elsif ( $line =~ s/\s* in=(\d+) out=(\d+)$// ) {
			$$stats{"dovecot:$protocol:bytes:in"} += $1 * $multiply;
			$$stats{"dovecot:$protocol:bytes:out"} += $2 * $multiply;
		}
		# event types
		if ( $line =~ s/Disconnected[:\s]*// ) {
			$line =~ s/Disconnected[:\s]*//;	# some versions repeat
			$$stats{"dovecot:$protocol:disconnect"} += $multiply;
			if ( $line =~ /^for inactivity/ ) {
				$$stats{"dovecot:$protocol:disconnect:inactivity"} += $multiply;
			} elsif ( $line =~ /^Logged out/ ) {
				$$stats{"dovecot:$protocol:disconnect:loggedout"} += $multiply;
			} elsif ( $line =~ /^in IDLE/ ) {
				$$stats{"dovecot:$protocol:disconnect:idle"} += $multiply;
			} elsif ( $line =~ /^in APPEND/ ) {
				$$stats{"dovecot:$protocol:disconnect:append"} += $multiply;
			} elsif ( $line eq ''
				or $line eq 'Disconnected' ) {
				$$stats{"dovecot:$protocol:disconnect:none"} += $multiply;
			} else {
				$$stats{"dovecot:$protocol:disconnect:other"} += $multiply;
				print STDERR __FILE__." $VERSION:".__LINE__." $log:$number unknown dovecot: $origline\n";
			}
		} elsif ( $line =~ s/Connection closed// ) {
			$$stats{"dovecot:$protocol:connclosed"} += $multiply;
		} elsif ( $line =~ s/Server shutting down\.// ) {
			# ignore
		} elsif ( $line =~ s/Error: write\(.+\) failed: Broken pipe// ) {
			# ignore - probably relates to above shutdown
		} else {
			print STDERR __FILE__." $VERSION:".__LINE__." $log:$number unknown dovecot: $origline\n";
		}
	} elsif ( $line =~ s/deliver\([^\)]+\):\s*.*: saved mail to\s*// ) {
		# also see lmtp below - some versions use that instead
		$$stats{'dovecot:deliver'} += $multiply;
		if ( $line eq 'INBOX' ) {
			$$stats{'dovecot:deliver:inbox'} += $multiply;
		} else {
			$$stats{'dovecot:deliver:elsewhere'} += $multiply;
		}
	} elsif ( $line =~ s/^lmtp\([^\)]+\): *// ) {
		# also see deliver above - some versions use that instead
		if ( $line =~ s/Connect from local// ) {
			# ignore
		} elsif ( $line =~ s/\w+: msgid=.+: saved mail to\s*// ) {
			if ( $line eq 'INBOX' ) {
				$$stats{'dovecot:deliver:inbox'} += $multiply;
			} else {
				$$stats{'dovecot:deliver:elsewhere'} += $multiply;
			}
		} elsif ( $line =~ s/\w+: msgid=.+: save failed // ) {
				$$stats{'dovecot:deliver:fail'} += $multiply;
		} elsif ( $line =~ s/Disconnect from local: Client quit \(in reset\)// ) {
			# ignore
		} elsif ( $line =~ s/Disconnect from local: Connection closed \(in reset\)// ) {
			# ignore
		} else {
			print STDERR __FILE__." $VERSION:".__LINE__." $log:$number unknown dovecot: $origline\n";
		}
	} elsif ( $line =~ s/ssl-build-param: SSL parameters regeneration completed// ) {
		# ignore
	} elsif ( $line =~ s/auth-worker\(default\): mysql: Connected to localhost \(.+\)//
			or $line =~ s/auth-worker\(\d+\): mysql\([^\)]+\): Connected to database .+// ) {
		# ignore
	} elsif ( $line =~ s/Killed with signal 15 //
		or $line =~ s/master: Warning: Killed with signal 15 //
		or $line =~ s/Dovecot v.+ starting up//
		or $line =~ s/master: Warning: SIGHUP received - reloading configuration// ) {
		# ignore
	} elsif ( $line =~ s/auth: Warning: auth client \d+ disconnected with \d+ pending requests:\s*// ) {
		# ignore - don't think this merits graphing and is more informational/debug
	} else {
		print STDERR __FILE__." $VERSION:".__LINE__." $log:$number unknown dovecot: $origline\n";
	}
	return 1;
}





\&register;
