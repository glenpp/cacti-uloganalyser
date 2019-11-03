use strict;
use warnings;
# process the mail log and place the results in a file

# Copyright (C) 2009-2014  Glen Pitt-Pladdy
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
# See: https://www.pitt-pladdy.com/blog/_20110625-123333_0100_Dovecot_stats_on_Cacti_via_SNMP_/
#
package dovecot;
our $VERSION = 20191103;
our $REQULOGANALYSER = 20131006;

our $IGNOREERRORS = 1;

# places we should look for this
our @DOVEADM = (
	'/usr/sbin/doveadm',
	'/usr/bin/doveadm',
);
#
# Thanks for ideas, unhandled log lines, patches and feedback to:
#
# Daniele Palumbo
# Przemek Orzechowski
# "Alex"
# Voytek Eymont
# Jean Deram
# Alessio
# "skeletor"
# "methilnet"


sub register {
	my ( $lines, $ends, $uloganalyserver ) = @_;
	push @$lines, \&analyse;
	push @$ends, \&wrapup;
	if ( ! defined $uloganalyserver or $uloganalyserver < $REQULOGANALYSER ) {
		die __FILE__.": FATAL - Requeire uloganalyser version $REQULOGANALYSER or higher\n";
	}
}


sub wrapup {
	my $stats = shift;
	# see if we can run "doveadm"
	foreach ('imap', 'managesieve', 'pop3' ) {
		$$stats{"dovecot:sessions:$_"} = 0;
		$$stats{"dovecot:users:$_"} = 0;
	}
	my %users;
	foreach my $doveadm (@DOVEADM) {
#		if ( -f '/tmp/testdoveadm' and open my $da, '<', '/tmp/testdoveadm' ) { print "WARNING - non production\n";	# for testing
		if ( -x $doveadm and open my $da, '-|', "$doveadm who 2>&1" ) {
			while ( defined ( my $line = <$da> ) ) {
				chomp $line;
				$line =~ s/\s+$//;
				if ( $line =~ /^([^\s]+)\s+(\d+)\s+(\w+)\s+\([^\)]+\)\s+\([^\)]+\)$/ ) {
					if ( $3 ne 'imap' and $3 ne 'managesieve' and $3 ne 'pop3' ) {
						warn __FILE__." $VERSION:".__LINE__." \"doveadm who\" unknown dovecot: $line\n";
						next;
					}
					# store this number
					$$stats{"dovecot:sessions:$3"} += $2;
					if ( ! exists $users{$3}{$1} ) {
						$users{$3}{$1} = 1;
						++$$stats{"dovecot:users:$3"};
					}
				} elsif ( $line !~ /^username\s+#\s+proto\s+\(pids\)\s+\(ips\)$/ ) {
					warn __FILE__." $VERSION:".__LINE__." \"doveadm who\" unknown dovecot: $line\n";
				}
			}
			close $da;
			last;
		}
	}
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
	if ( $line =~ s/auth(\(\w+\))?: [\w\-]+\(.+\): // ) {
		if ( $line =~ s/^unknown user$// ) {
			$$stats{'dovecot:auth:unknownuser'} += $multiply;
		} elsif ( $line =~ s/^Password mismatch// ) {
			$$stats{'dovecot:auth:passwordmismatch'} += $multiply;
		} elsif ( $line =~ s/^Username contains disallowed character.*$//
				or $line =~ s/^Username character disallowed by auth_username_chars:.*$// ) {
			$$stats{'dovecot:auth:disallowedchar'} += $multiply;
		} elsif ( $line =~ s/^Empty username$// ) {
			$$stats{'dovecot:auth:emptyusername'} += $multiply;
		} elsif ( $line =~ s/^invalid input//
				or $line =~ s/^Invalid base64 data in continued response$// ) {
			$$stats{'dovecot:auth:invalidinput'} += $multiply;
		} elsif ( $line =~ s/^Request \d+\.\d timeouted after \d+ secs, state=\d+$//
				or $line =~ s/^Request timed out waiting for client to continue authentication \(\d+ secs\)// ) {
			$$stats{'dovecot:auth:timeouted'} += $multiply;
		} else {
			$$stats{'dovecot:auth:other'} += $multiply;
			warn __FILE__." $VERSION:".__LINE__." $log:$number unknown dovecot: $origline\n";
		}
	} elsif ( $line =~ s/auth: Debug: // ) {
		# ignore debug stuff
	} elsif ( $line =~ s/^(imap|pop3|managesieve)-login: // ) {
		my $protocol = $1;
		$$stats{"dovecot:$protocol:login"} += $multiply;
		if ( $line =~ s/^Login: // or $line =~ s/^proxy\([^\)]+\): started proxying to [\da-f\.:]+ // ) {
			$$stats{"dovecot:$protocol:login:success"} += $multiply;
# TODO may be Disconnected, in which case not success TODO
			my $crypto = 'none';
			my $local;
			my $remote;
			while ( $line ) {
				if ( $line =~ s/user=<[^>]*>, // or $line =~ s/user=<[^>]*>$// ) {
					# not used
				} elsif ( $line =~ s/method=(\w+|\w+-\w+), // or $line =~ s/method=(\w+|\w+-\w+)$// ) {
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
						warn __FILE__." $VERSION:".__LINE__." $log:$number unknown dovecot: $origline\n";
					}
				} elsif ( $line =~ s/rip=([\da-f\.:]+), // or $line =~ s/rip=([\da-f\.:]+)$// ) {
					$remote = $1;
				} elsif ( $line =~ s/lip=([\da-f\.:]+), // or $line =~ s/lip=([\da-f\.:]+)$// ) {
					$local = $1;
				} elsif ( $line =~ s/mpid=\d+, // or $line =~ s/mpid=\d+$// ) {
				} elsif ( $line =~ s/secured, // or $line =~ s/secured$// ) {
					if ( defined ( $local ) and defined ( $remote )
						and ( $local eq '127.0.0.1' or $local eq '::1' )
						and ( $remote eq '127.0.0.1' or $remote eq '::1' ) ) {
						# this will happen when no crypto is in use and the conenction is local
					} else {
						$$stats{"dovecot:$protocol:crypto:ssl"} += $multiply;
						$crypto = 'ssl';
					}
				} elsif ( $line =~ s/TLS, // or $line =~ s/TLS$// or $line =~ s/TLS: Disconnected// ) {
					$$stats{"dovecot:$protocol:crypto:tls"} += $multiply;
					$crypto = 'tls';
				} elsif ( $line =~ s/session=<[^>]*>, // or $line =~ s/session=<[^>]*>$// ) {
					# not used for now
				} else {
					$$stats{"dovecot:$protocol:crypto:other"} += $multiply;
					warn __FILE__." $VERSION:".__LINE__." $log:$number unknown dovecot: $origline\n";
					warn __FILE__." $VERSION:".__LINE__." $log:$number unknown dovecot SEGMENT: $line\n";
					last;
				}
				$line =~ s/^, //;
			}
			if ( $crypto eq 'none' ) {
				$$stats{"dovecot:$protocol:crypto:none"} += $multiply;
			}
		} elsif ( $line =~ s/^(Disconnected)[:\s]*// or $line =~ s/^(proxy)\([^\)]+\): disconnecting [\da-f\.:]+ // ) {
			my $type = lc $1;
			if ( $type eq 'disconnected' ) { $type = 'login'; }
			$$stats{"dovecot:$protocol:login:disconnected"} += $multiply;
			# some dovecot versions give extra info TODO
			if ( $line =~ s/^Inactivity during authentication \(/\(/ ) {
				# TODO not currently used
			} elsif ( $line =~ s/^Inactivity \(/\(/ ) {
				# TODO not currently used
			} elsif ( $line =~ s/^Too many invalid commands // ) {
				# TODO not currently used
			} elsif ( $line =~ s/^Connection queue full // ) {
				# TODO not currently used
			} elsif ( $line !~ /^\(/ ) {
				warn __FILE__." $VERSION:".__LINE__." $log:$number unknown dovecot: $origline\n";
			}
			if ( $line =~ s/^\(no auth attempts( in \d+ secs)?\):// ) {
				$$stats{"dovecot:$protocol:login:disconnected:noauthattempt"} += $multiply;
			} elsif ( $line =~ s/^\(auth failed, \d+ attempts( in \d+ secs)?\):// ) {
				$$stats{"dovecot:$protocol:login:disconnected:authfailed"} += $multiply;
			} elsif ( $line =~ s/^\(disconnected while authenticating(, waited \d+ secs)?\)://
				or $line =~ s/^\(client didn't finish SASL auth, waited \d+ secs\):// ) {
				$$stats{"dovecot:$protocol:login:disconnected:authenticating"} += $multiply;
			} elsif ( $line =~ s/^\(tried to use disabled plaintext auth\):// ) {
				$$stats{"dovecot:$protocol:login:disconnected:disabledauthmethod"} += $multiply;
			} elsif ( $line =~ s/^\(disconnected before greeting(, waited \d+ secs)?\):// ) {
				$$stats{"dovecot:$protocol:login:disconnected:beforegreeting"} += $multiply;
			} elsif ( $type eq 'proxy' and $line =~ s/^\(Disconnected by server\)// ) {
				$$stats{"dovecot:$protocol:login:disconnected:proxybyserver"} += $multiply;
			} elsif ( $type eq 'proxy' and $line =~ s/^\(Disconnected by client\)// ) {
				$$stats{"dovecot:$protocol:login:disconnected:proxybyclient"} += $multiply;
			} else {
				$$stats{"dovecot:$protocol:login:disconnected:other"} += $multiply;
				warn __FILE__." $VERSION:".__LINE__." $log:$number unknown dovecot: $origline\n";
			}
		} elsif ( $line =~ s/^Aborted login[:\s]*// ) {
			$$stats{"dovecot:$protocol:login:aborted"} += $multiply;
			if ( $line =~ s/^\(no auth attempts( in \d+ secs)?\):// ) {
				$$stats{"dovecot:$protocol:login:aborted:noauthattempt"} += $multiply;
			} elsif ( $line =~ s/^\(auth failed, \d+ attempts( in \d+ secs)?\):// ) {
				$$stats{"dovecot:$protocol:login:aborted:authfailed"} += $multiply;
			} elsif ( $line =~ s/^\(tried to use disabled plaintext auth\):// ) {
				$$stats{"dovecot:$protocol:login:aborted:disabledauthmethod"} += $multiply;
			} elsif ( $line =~ s/^\(disconnected before greeting(, waited \d+ secs)?\):// ) {
				$$stats{"dovecot:$protocol:login:disconnected:beforegreeting"} += $multiply;
			} else {
				$$stats{"dovecot:$protocol:login:aborted:other"} += $multiply;
				warn __FILE__." $VERSION:".__LINE__." $log:$number unknown dovecot: $origline\n";
			}
		} elsif ( $line =~ s/^Maximum number of connections from user\+IP exceeded // ) {
			$$stats{"dovecot:$protocol:login:maxconnections"} += $multiply;
		} elsif ( $IGNOREERRORS and
			( $line =~ s/Fatal: Error reading configuration: Timeout reading config from //
			or $line =~ s/Fatal: master: service\([\w+\-]+\): child \d+ killed with signal 9//
			or $line =~ s/Warning: Auth process not responding, delayed sending greeting: //
			) ) {
			# ignore errors
		} else {
			$$stats{"dovecot:$protocol:login:other"} += $multiply;
			warn __FILE__." $VERSION:".__LINE__." $log:$number unknown dovecot: $origline\n";
		}
	} elsif ( $line =~ s/^(IMAP|POP3|MANAGESIEVE|imap|pop3|managesieve)(\([^\)]+\))?(, session=<\w+>)?: // ) {
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
			} elsif ( $line =~ /^in APPEND/
				or $line =~ /^EOF while appending/ ) {	# assuming same thing but in debug
				$$stats{"dovecot:$protocol:disconnect:append"} += $multiply;
			} elsif ( $line =~ /Internal error occurred\. Refer to server log for more information\./ ) {
				$$stats{"dovecot:$protocol:disconnect:internalerror"} += $multiply;
			} elsif ( $line eq ''
				or $line eq 'Disconnected' ) {
				$$stats{"dovecot:$protocol:disconnect:none"} += $multiply;
			} elsif ( $IGNOREERRORS and
				( $line =~ s/\w+ session state is inconsistent, please relogin\.// ) ) {
				# ignore error
			} else {
				$$stats{"dovecot:$protocol:disconnect:other"} += $multiply;
				warn __FILE__." $VERSION:".__LINE__." $log:$number unknown dovecot: $origline\n";
			}
		} elsif ( $line =~ s/Logged out// ) {
			# 2.2 on this changes from Disconnected - Logged out
			$$stats{"dovecot:$protocol:disconnect:loggedout"} += $multiply;
		} elsif ( $line =~ s/Connection closed// ) {
			$$stats{"dovecot:$protocol:connclosed"} += $multiply;
		} elsif ( $line =~ s/Server shutting down\.// ) {
			# ignore
		} elsif ( $line =~ s/Error: write\(.+\) failed: Broken pipe// ) {
			# ignore - probably relates to above shutdown
		} elsif ( $IGNOREERRORS and
			( $line =~ s/Error: Corrupted index cache file \/.*\/dovecot\.index\.cache: Broken physical size for mail UID \d+//
			or $line =~ s/Error: read\([^\)]+\) failed: Input\/output error \(FETCH for mailbox INBOX UID \d+\)//
			or $line =~ s/Error: Cached message size smaller than expected \(\d+ < \d+\)//
			or $line =~ s/Error: Maildir filename has wrong S value, renamed the file from \/.* to \/.*//
			or $line =~ s/Error: Corrupted index cache file//
			or $line =~ s/Error: Internal error occurred\. Refer to server log for more information\.//
			or $line =~ s/Error: user [^:]+: Error reading configuration: Timeout reading config from//
			or $line =~ s/Fatal: master: service\([\w+\-]+\): child \d+ killed with signal 9//
			or $line =~ s/Warning: Auth server restarted \(pid \d+ -> \d+\), aborting auth//
			or $line =~ s/Error: Corrupted transaction log file //
			or $line =~ s/Warning: Maildir [^:]+: UIDVALIDITY changed//
			or $line =~ s/Error: [^\s]+ reset, view is now inconsistent//
			or $line =~ s/Warning: Maildir: Scanning \/.+\/(new|cur) took \d+ seconds \(\d+ readdir\(\)s, 0 rename\(\)s to cur\/, why=0x24\)$//
			or $line =~ s/Warning: Maildir \/.+: Synchronization took \d+ seconds \(0 new msgs, 0 flag change attempts, 0 expunge attempts\)$//
			or $line =~ s/Warning: Transaction log file \/.+\.log was locked for \d+ seconds$//
			) ) {
				# ignore errors
		} else {
			warn __FILE__." $VERSION:".__LINE__." $log:$number unknown dovecot: $origline\n";
		}
	} elsif ( $line =~ s/(deliver|lda)\([^\)]+\)(<\d+><[\w\+]+>)?:\s*// ) {
		# also see lmtp below - some versions use that instead
		if ( $line =~ s/.* saved mail to\s*// ) {
			$line =~ s/^'(.+)'$/$1/;	# strips quotes seen in some versions/configurations
			$$stats{'dovecot:deliver'} += $multiply;
			if ( $line eq 'INBOX' ) {
				$$stats{'dovecot:deliver:inbox'} += $multiply;
			} else {
				$$stats{'dovecot:deliver:elsewhere'} += $multiply;
			}
		} elsif ( $line =~ s/.*: save failed to\s*// ) {
				$$stats{'dovecot:deliver:fail'} += $multiply;
		} elsif ( $line =~ s/sieve:\s*msgid=[^:]+:\s*// ) {
				$$stats{'dovecot:deliver:sieve'} += $multiply;
		} else {
			warn __FILE__." $VERSION:".__LINE__." $log:$number unknown dovecot: $origline\n";
print ">$line\n";
		}
	} elsif ( $line =~ s/^lmtp\([^\)]+\): *// ) {
		# also see deliver above - some versions use that instead
		if ( $line =~ s/Connect from local// ) {
			# ignore
		} elsif ( $line =~ s/^[^\s]+:( sieve:)? msgid=.+:\s+(saved mail to|stored mail into mailbox)\s*// ) {
			$line =~ s/^'(.+)'$/$1/;	# strips quotes seen in some versions/configurations
			$$stats{'dovecot:deliver'} += $multiply;
			if ( $line eq 'INBOX' ) {
				$$stats{'dovecot:deliver:inbox'} += $multiply;
			} else {
				$$stats{'dovecot:deliver:elsewhere'} += $multiply;
			}
		} elsif ( $line =~ s/^[^\s]+:( sieve:)? msgid=.+:\s+(forwarded to)\s+// ) {
			# generic sieve function not relating to mailbox sorting
			$$stats{'dovecot:deliver:sieve'} += $multiply;
		} elsif ( $line =~ s/\w+: msgid=.+: save failed to\s*// ) {
				$$stats{'dovecot:deliver:fail'} += $multiply;
		} elsif ( $line =~ s/Disconnect from local: Client quit \(in reset\)// ) {
			# ignore
		} elsif ( $line =~ s/Disconnect from local: Connection closed \(in reset\)// ) {
			# ignore
		} elsif ( $line =~ s/Disconnect from local: Connection closed \(in DATA finished\)// ) {
			# ignore
		} elsif ( $line =~ s/Disconnect from local: Successful quit// ) {
			# ignore
		} elsif ( $IGNOREERRORS and
			( $line =~ s/^Warning: Transaction log file \/.+\.log was locked for \d+ seconds$//
			or $line =~ s/^Warning: Maildir \/.+: Synchronization took \d+ seconds \(\d+ new msgs, 0 flag change attempts, 0 expunge attempts\)// ) ) {
			# ignore error
		} else {
			warn __FILE__." $VERSION:".__LINE__." $log:$number unknown dovecot: $origline\n";
			warn __FILE__." $VERSION:".__LINE__." $log:$number unknown dovecot: $line\n";
		}
	} elsif ( $line =~ s/master:\s*// ) {
		# TODO graph TODO TODO TODO TODO TODO
		if ( $line =~ s/Warning:\s*// ) {
			$$stats{"dovecot:master:warning"} += $multiply;
			if ( $line =~ s/service\(([^\)]+)\): process_limit \(\d+\) reached, client connections are being dropped// ) {
				my $service = $1;
				$$stats{"dovecot:master:warning:proclimit"} += $multiply;
#				if ( $service eq 'imap-login'
#					or $service eq 'managesieve-login'
#					or $service eq 'pop3-login' ) {
#					$$stats{"dovecot:master:warning:proclimit:$service"} += $multiply;
#				} else {
#					$$stats{"dovecot:master:warning:proclimit:other"} += $multiply;
#					warn __FILE__." $VERSION:".__LINE__." $log:$number unknown dovecot: $origline\n";
#				}
			} elsif ( $line =~ s/Killed with signal 15 // ) {
				# ignore - normal shutdown behaviour
			} elsif ( $line =~ s/SIGHUP received - reloading configuration// ) {
				# ignore - normal reload behaviour
			} else {
				$$stats{"dovecot:master:warning:other"} += $multiply;
				warn __FILE__." $VERSION:".__LINE__." $log:$number unknown dovecot: $origline\n";
			}
		} elsif ( $line =~ s/Error:\s*// ) {
			if ( $IGNOREERRORS and
				( $line =~ s/service\(([^\)]+)\): command startup failed, throttling for \d+ secs//
				or $line =~ s/service\(([\w\-]+)\): Initial status notification not received in 30 seconds, killing the process// ) ) {
				# ignore error
			} else {
				warn __FILE__." $VERSION:".__LINE__." $log:$number unknown dovecot: $origline\n";
			}
		} elsif ( $line =~ s/Dovecot v.+ starting up// ) {
			# ignore - normal shutdown behaviour
		} elsif ( $IGNOREERRORS and
			( $line =~ s/^auth-worker: Fatal: service\(auth-worker\): child \d+ killed with signal 9$// ) ) {
			# ignore
		} else {
			warn __FILE__." $VERSION:".__LINE__." $log:$number unknown dovecot: $origline\n";
		}
	} elsif ( $line =~ s/ssl-build-param: SSL parameters regeneration completed// ) {
		# ignore
	} elsif ( $line =~ s/auth-worker\(default\): mysql: Connected to localhost \(.+\)//
			or $line =~ s/auth-worker\(\d+\): mysql\([^\)]+\): Connected to database .+// ) {
		# ignore
	} elsif ( $line =~ s/auth-worker\(\d+\): sql\([^,]+,\d+\.\d+\.\d+.\d+,(<[^>]+>)?\): (unknown user|Password mismatch)$// ) {
		# ignore - auth-worker authentication problems manifest as *-login messages
	} elsif ( $line =~ s/auth-worker\(\d+\): Debug:\s*// ) {
		# ignore debug messages
	} elsif ( $line =~ s/Killed with signal 15 // ) {
		# ignore - normal stop behaviour
	} elsif ( $line =~ s/^ssl-params:\s*// ) {
		if ( $line =~ s/^Generating SSL parameters// ) {
			# ignore
		} elsif ( $line =~ s/^SSL parameters regeneration completed// ) {
			# ignore
		} else {
			warn __FILE__." $VERSION:".__LINE__." $log:$number unknown dovecot: $origline\n";
		}
	} elsif ( $line =~ s/auth: Warning: auth client \d+ disconnected with \d+ pending requests:\s*// ) {
		# ignore - don't think this merits graphing and is more informational/debug
	} elsif ( $line =~ s/doveadm: Debug: This is Dovecot's debug log\s*//
		or $line =~ s/doveadm: This is Dovecot's info log\s*//
		or $line =~ s/doveadm: Warning: This is Dovecot's warning log\s*//
		or $line =~ s/doveadm: Error: This is Dovecot's error log\s*//
		or $line =~ s/doveadm: Fatal: This is Dovecot's fatal log\s*// ) {
		# ignore debug messages
	} elsif ( $IGNOREERRORS and
		( $line =~ s/auth: Error: Master requested auth for nonexistent client \d+//
		or $line =~ s/^auth-worker\(\d+\): Error: sql\(.+\): Password query failed: Not connected to database$//
		or $line =~ s/^auth-worker\(\d+\): Error: mysql: Query failed, retrying: Lost connection to MySQL server during query$//
		or $line =~ s/^auth-worker\(\d+\): Error: mysql\(.+\): Connect failed to database \(\w+\): Can't connect to MySQL server on '.+' \(111\) - waiting for \d+ seconds before retry$//
		or $line =~ s/^auth-worker\(\d+\): Error: mysql: Query timed out \(no free connections for \d+ secs\): SELECT username as user, password, '.+' as .+, '.+' as userdb_mail, \d+ as .+, .+ as .+ FROM mailbox WHERE username = '.+' AND active = '1'$//
		or $line =~ s/^auth-worker\(\d+\): Error: mysql\(.+\): Connect failed to database \(\w+\): Lost connection to MySQL server at 'reading initial communication packet', system error: 0 - waiting for \d+ seconds before retry$//
		or $line =~ s/^auth-worker: Error: sql\(.+\): Password query failed: Not connected to database$//
		or $line =~ s/^auth: Error: auth worker: Aborted request: Lookup timed out$//
		or $line =~ s/^auth: Error: auth worker: Aborted request: Internal auth worker failure$//
		or $line =~ s/^auth: Error: (PLAIN|LOGIN)\(.+\): Request \d+\.1 timeouted after \d+ secs, state=1$//
		or $line =~ s/^auth: Warning: auth workers: Auth request was queued for \d+ seconds, \d+ left in queue \(see auth_worker_max_count\)$//
		or $line =~ s/^stats: Warning: Session \w+ \(user .+\) appears to have crashed, disconnecting it$//
		or $line =~ s/^stats: Warning: Couldn't find session GUID: bfb8f031c7507652981f0000c8b6dbb1$//
		) ) {
		# ignore error
	} elsif ( $line =~ s/^Dovecot v\d+\.\d+\.\d+ starting up \(core dumps disabled\)$//
		or $line =~ s/^dovecot: SIGHUP received - reloading configuration// ) {
		# ignore startup / restart / reload
	} else {
		warn __FILE__." $VERSION:".__LINE__." $log:$number unknown dovecot: $origline\n";
	}
	return 1;
}





\&register;
