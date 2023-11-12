use strict;
use warnings;
# process the mail log and place the results in a file

# Copyright (C) 2009-2023  Glen Pitt-Pladdy
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
# See: https://github.com/glenpp/cacti-uloganalyser/tree/master/postfix
#
package postfix;
our $VERSION = 20231022;
our $REQULOGANALYSER = 20131006;

our $IGNOREERRORS = 1;
our $INCLUDETLSPROXY = 0;	# include tlsproxy connections and TLS stats with smtpd

#
# Thanks for ideas, unhandled log lines, patches and feedback to:
#
# "Ronny"
# Scott Merrill
# "Charles"
# Przemek Przechowski
# "Denho"
# Horst Simon
# "oneloveamaru"
# Grzegorz Dajuk
# Voytek Eymont
# "byrdhuntr"
# "bluemm"
# "Simon Beckett"
# "EmTeedee"



our $QUEUEDIR = "/var/spool/postfix";
our @deferreasons;


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
	# get queue stats
	use File::Find;
	foreach my $queue ('maildrop', 'incoming', 'hold', 'active', 'deferred') {
		$$stats{"postfix:queue:$queue"} = 0;
		find ( sub { if ( -f $File::Find::name ) { ++$$stats{"postfix:queue:$queue"}; } },
			"$QUEUEDIR/$queue" );
	}


	# if we got anything in @deferreasons then make noise about it
	if ( @deferreasons > 0 ) {
		print "Deferral reasons: postfix-loganalyser $VERSION\n";
		print "==============================================\n";
		print "Please check these contain no private or identifying information and\n";
		print "contribute them back at: http://www.pitt-pladdy.com/blog/_contact/\n";
		print "Your contribution will be credited with your name in this script unless\n";
		print "you request otherwise\n";
		print "\n";
		print "You can also send other log lines above, but please ensure you modify them\n";
		print "so that you don't pass on any private or identifying information\n";
		print "\n";
		foreach my $deferreason (@deferreasons) {
			$deferreason =~ s/^(\d+)://;
			print __FILE__.":$1 version $VERSION\n";
			# get postfix component out - it can look like a host
			my $postfixcomp = '';
			if ( $deferreason =~ s/^.* (postfix\/\w+)\[\d+\]:\s*// ) {
				$postfixcomp = "$1\\[\\d+\\]:\\s*";
			}
			# anonymise email addresses
			$deferreason =~ s/<[^>]+@[^>]+>/<.+>/g;
			# anonymise host addresses
			$deferreason =~ s/[\w\.\-]+\[[\w\.:]+\]/[\\w\\.\\-]+\\[[\\w\\.:]+\\]/g;
			# hopefully that's all we need to anonymise
			print "$postfixcomp$deferreason\n";
		}
	}
}









sub analyse {
	my ( $line, $number, $log, $stats ) = @_;
	my $origline = $line;
	if ( $line !~ s/^.+ postfix\/([\w\-]+\[\d+\]:.*)$/$1/ ) { return; }
############################## pickup ##############################
	if ( $line =~ /^pickup\[\d+\]:/ ) {
		# sent locally
		++$$stats{'postfix:pickup'};
############################### snmpd ##############################
	} elsif ( $line =~ s/^smtpd\[\d+\]:\s*// ) {
		if ( $line =~ s/^connect from\s*// ) {
			# inbound snmp connection
			++$$stats{'postfix:smtpd:connect'};
			# get ipv4/ipv6 stats
			if ( $line =~ s/^.*\[[\d+.]+\]// ) {
				++$$stats{'postfix:smtpd:connect:ipv4'};
			} elsif ( $line =~ s/^.*\[[\da-f:]+(%eth\d)?\]// ) {
				++$$stats{'postfix:smtpd:connect:ipv6'};
			} elsif ( $line =~ s/^.*\[unknown\]// ) {
				# ignore - it was so brief we didn't get the address
			} else {
				warn __FILE__." $VERSION:".__LINE__." $log:$number unknown: $origline\n";
			}
		} elsif ( $line =~ s/lost connection after\s*// ) {
			# lost snmp connection
			++$$stats{'postfix:smtpd:lostconnection'};
		} elsif ( $line =~ s/timeout after\s*// ) {
			# timeout snmp connection
			++$$stats{'postfix:smtpd:timeoutconnection'};
		} elsif ( $line =~ s/^[0-9A-F]+: client=// ) {
			# queued message
			++$$stats{'postfix:smtpd:QUEUED'};
		} elsif ( $line =~ s/^NOQUEUE:\s*//
			or $line =~ s/^[0-9A-F]+: (reject:\s*)/$1/ ) {	# some versions/config seem to give reject after queueing
			# rejected for some reason
			++$$stats{'postfix:smtpd:NOQUEUE'};
			if ( $line =~ s/^reject: (RCPT|VRFY) from\s*// ) {
				++$$stats{'postfix:smtpd:NOQUEUE:reject'};
				if ( $line =~ s/^.*: Relay access denied;\s*// ) {
					# trying to relay
					++$$stats{'postfix:smtpd:NOQUEUE:reject:Relay'};
				} elsif ( $line =~ s/^.*: Helo command rejected:\s+// ) {
					# bad HELO sent
					++$$stats{'postfix:smtpd:NOQUEUE:reject:HELO'};
				} elsif ( $line =~ s/^.*: .+ Service unavailable; (Client host|Sender address) \[[^\]]+\] blocked using\s+// ) {
					# RBL stopped it
					++$$stats{'postfix:smtpd:NOQUEUE:reject:RBL'};
				} elsif ( $line =~ s/^.*: Recipient address rejected:\s*// ) {
					# don't like recipient
					++$$stats{'postfix:smtpd:NOQUEUE:reject:Recipient'};
					if ( $line =~ s/^need fully-qualified address;//i ) {
						# recipient address not fully qualified
						++$$stats{'postfix:smtpd:NOQUEUE:reject:Recipient:fullyquallifiedaddr'};
					} elsif ( $line =~ s/^.*\s*Greylisted\s*//i or $line =~ s/\s451 .*Please try again later//i
						or $line =~ s/^.*\s450\s.+\sTry again later or login[\.\s]//i ) {
						# greylisted
						++$$stats{'postfix:smtpd:NOQUEUE:reject:Recipient:Greylisted'};
					} elsif ( $line =~ s/^Access denied;//i ) {
						# explicitly denied
						++$$stats{'postfix:smtpd:NOQUEUE:reject:Recipient:denied'};
					} elsif ( $line =~ s/^User unknown in (local recipient|relay recipient|virtual alias) table;//i ) {
						# don't know this user
						++$$stats{'postfix:smtpd:NOQUEUE:reject:Recipient:unknownuser'};
					} else {
						# some other reason
						++$$stats{'postfix:smtpd:NOQUEUE:reject:Recipient:other'};
						# don't report customised rejections
						#warn __FILE__." $VERSION:".__LINE__." $log:$number unknown: $origline\n";
					}
				} elsif ( $line =~ s/^.*: Sender address rejected:\s*// ) {
					# don't like sender
					++$$stats{'postfix:smtpd:NOQUEUE:reject:Sender'};
					if ( $line =~ s/^Access denied;//i
							or $line =~ s/^Your mail is not welcome here[^;]*;//i ) {
						# explicitly denied
						++$$stats{'postfix:smtpd:NOQUEUE:reject:Sender:denied'};
					} elsif ( $line =~ s/^Domain not found;//i ) {
						# invalid sender domain
						++$$stats{'postfix:smtpd:NOQUEUE:reject:Sender:domain'};
					} elsif ( $line =~ s/^need fully-qualified address;//i ) {
						# sender address not fully qualified
						++$$stats{'postfix:smtpd:NOQUEUE:reject:Sender:fullyquallifiedaddr'};
					} elsif ( $line =~ s/^Malformed DNS server reply;//i ) {
						# bad dns
						++$$stats{'postfix:smtpd:NOQUEUE:reject:Sender:malformeddns'};
					} elsif ( $line =~ s/^not logged in;//i ) {
						# login required to use this address
						++$$stats{'postfix:smtpd:NOQUEUE:reject:Sender:notloggedin'};
					} elsif ( $line =~ s/^not owned by user [^\s]+;//i
							or $line =~ s/^User unknown in virtual mailbox table;//i ) {	# technically a different thing, but the same type of problem - sending address not allowed
						# using an address their login doesn't allow
						++$$stats{'postfix:smtpd:NOQUEUE:reject:Sender:addrnotowned'};
					} else {
						# some other reason
						++$$stats{'postfix:smtpd:NOQUEUE:reject:Sender:other'};
						warn __FILE__." $VERSION:".__LINE__." $log:$number unknown: $origline\n";
					}
				} elsif ( $line =~ s/^.* Client (address|host) rejected:\s*// ) {
					# don't like client
					++$$stats{'postfix:smtpd:NOQUEUE:reject:Client'};
					if ( $line =~ s/^Access denied;//i ) {
						# explicitly denied
						++$$stats{'postfix:smtpd:NOQUEUE:reject:Client:denied'};
					} elsif ( $line =~ s/cannot find your (reverse )?hostname//i ) {
						# DNS failure
						++$$stats{'postfix:smtpd:NOQUEUE:reject:Client:DNS'};
					} elsif ( $line =~ s/sender address does not match client hostname//i ) {
						# freemail checks - custom message
						++$$stats{'postfix:smtpd:NOQUEUE:reject:Client:freemailmismatch'};
					} else {
						# some other reason
						++$$stats{'postfix:smtpd:NOQUEUE:reject:Client:other'};
						warn __FILE__." $VERSION:".__LINE__." $log:$number unknown: $origline\n";
					}
				} else {
					# other rejection
					++$$stats{'postfix:smtpd:NOQUEUE:reject:other'};
					warn __FILE__." $VERSION:".__LINE__." $log:$number unknown: $origline\n";
				}
			} elsif ( $line =~ s/^reject: MAIL from\s*.+: 552 5\.3\.4 Message size exceeds fixed limit// ) {
				++$$stats{'postfix:smtpd:NOQUEUE:toobig'};
			} elsif ( $line =~ s/^reject: DATA from [\w\.\-]+\[[\w\.:]+\]: 503 5\.5\.0 <DATA>: Data command rejected: Improper use of SMTP command pipelining;// ) {
				++$$stats{'postfix:smtpd:NOQUEUE:pipelining'};
			} elsif ( $line =~ s/^milter-reject: RCPT from [\w\.\-]+\[[\w\.:]+\]: 550 5\.7\.1 // ) {
				++$$stats{'postfix:smtpd:NOQUEUE:milter'};
			} else {
				# other
				++$$stats{'postfix:smtpd:NOQUEUE:other'};
				warn __FILE__." $VERSION:".__LINE__." $log:$number unknown: $origline\n";
			}
		} elsif ( $line =~ s/^setting up TLS connection from\s*// ) {
			# we are at least trying - TODO currently not used
			++$$stats{'postfix:smtpd:TLS'};
		} elsif ( $line =~ s/^Trusted TLS connection established from // ) {
			# trusted TLS
			++$$stats{'postfix:smtpd:TLS:Trusted'};
		} elsif ( $line =~ s/^Anonymous TLS connection established from // ) {
			# anonymous TLS
			++$$stats{'postfix:smtpd:TLS:Anonymous'};
		} elsif ( $line =~ s/^Untrusted TLS connection established from\s*// ) {
			# untrusted TLS #
			++$$stats{'postfix:smtpd:TLS:Untrusted'};
		} elsif ( $line =~ s/^certificate verification failed for\s*//
			or $line =~ s/^client certificate verification failed for\s*// ) {
			# certificate verification failed for some reason
			++$$stats{'postfix:smtpd:TLS:certverifyfail'};
			if ( $line =~ s/^.*:\s*self-signed certificate$// ) {
				# they are using self-signed certificates
				++$$stats{'postfix:smtpd:TLS:certverifyfail:selfsigned'};
			} elsif ( $line =~ s/^.*:\s*untrusted issuer.*$// ) {
				# they are using an CA we don't recognise
				++$$stats{'postfix:smtpd:TLS:certverifyfail:untrusted'};
			} elsif ( $line =~ s/^.*:\s*certificate has expired.*$// ) {
				# they are using an expired certificate
				++$$stats{'postfix:smtpd:TLS:certverifyfail:expired'};
			} elsif ( $line =~ s/^.*:\s*not designated for use as a client certificate$// ) {
				# they are using a certificate not meant for this
				++$$stats{'postfix:smtpd:TLS:certverifyfail:notclient'};
			} else {
				# some other unknown reason
				warn __FILE__." $VERSION:".__LINE__." $log:$number unknown: $origline\n";
				++$$stats{'postfix:smtpd:TLS:certverifyfail:other'};
			}
#		} elsif ( $line =~ s/^[^\s]+: Untrusted: subject_CN=, issuer=[^,]+, fingerprint=[\dA-F:]+$// ) {
			# ignore - alredy should be caught before
		} elsif ( $line =~ s/^SSL_accept error from // ) {
			# anonymous TLS
			++$$stats{'postfix:smtpd:SSL:error'};
			# TODO expand on this
		} elsif ( $line =~ s/^warning:\s*// ) {
			# warnings
			++$$stats{'postfix:smtpd:warning'};
			# TODO expand on this TODO
			# warning: unknown[89.248.172.122]: SASL LOGIN authentication failed: Invalid authentication mechanism
			# warning: some.dom[1.2.3.4]: SASL PLAIN authentication failed:
		} elsif ( $line =~ s/^[\w\.\-]+\[[\w\.:]+\]: (Tr|Untr)usted: subject_CN=.+, issuer=.+, fingerprint=.+$// ) {
			# ignore - alredy should be caught before
		} elsif ( $line =~ s/^TLSv1 with cipher // ) {
			# ignore - alredy should be caught before
		} elsif ( $line =~ s/^table hash:\/.+ has changed -- restarting$// ) {
			# ignore - alredy should be caught before
		} elsif ( $line =~ s/^too many errors after\s+// ) {
			# ignore - alredy should be caught before
		} elsif ( $line =~ s/^disconnect from // ) {
			# ignore - not interested
		} elsif ( $line =~ s/^improper command pipelining after \w+ from // ) {
			# ignore - likely spammers, but maybe log this in the longer term TODO
		} elsif ( $line =~ s/^proxy-(accept|reject):\s*// ) {
			# ignore - https://github.com/glenpp/cacti-uloganalyser/issues/1
		} else {
			# some other type
			++$$stats{'postfix:smtpd:other'};
			warn __FILE__." $VERSION:".__LINE__." $log:$number unknown: $origline\n";
		}
############################### smtp ###############################
	} elsif ( $line =~ s/^smtp\[\d+\]:\s*// ) {
		if ( $line =~ s/^connect to // ) {
			# connection (attempted)
			++$$stats{'postfix:smtp:connect'};
			smtpd_ip ( $line, $origline, $number, $log, $stats );
			# what went wrong?
			if ( $line =~ s/^.+: No route to host$// ) {
				# failed connection - no route to host
				++$$stats{'postfix:smtp:noroute'};
			} elsif ( $line =~ s/^.+: Connection timed out$// ) {
				# failed connection - time out (vanishing packets?)
				++$$stats{'postfix:smtp:timeout'};
			} elsif ( $line =~ s/^.+: Network is unreachable$// ) {
				# failed connection - unreachable destination
				++$$stats{'postfix:smtp:unreachable'};
			} elsif ( $line =~ s/^.+: Connection refused$// ) {
				# failed connection - refused (nothing listening on that port)
				++$$stats{'postfix:smtp:connrefused'};
			} else {
				# some other type
				++$$stats{'postfix:smtp:connother'};
				warn __FILE__." $VERSION:".__LINE__." $log:$number unknown: $origline\n";
			}
		} elsif ( $line =~ s/^[0-9A-F]+: lost connection with .+ while //i ) {
			# failed connection - lost
			++$$stats{'postfix:smtp:lostconnection'};
		} elsif ( $line =~ s/^[0-9A-F]+: conversation with .+ timed out while //i ) {
			# failed connection - time out (vanishing packets?)
			++$$stats{'postfix:smtp:timeout'};
		} elsif ( $line =~ s/^setting up TLS connection to\s*// ) {
			# we are at least trying - currently not used
			++$$stats{'postfix:smtp:TLS'};
		} elsif ( $line =~ s/^SSL_connect error to .+:25: lost connection$// ) {
			# lost connection in SSL connection setup
			++$$stats{'postfix:smtp:TLS'};
			++$$stats{'postfix:smtp:lostconnection'};
		} elsif ( $line =~ s/^Trusted TLS connection established to\s*// ) {
			# trusted TLS
			++$$stats{'postfix:smtp:TLS:Trusted'};
		} elsif ( $line =~ s/^Anonymous TLS connection established to\s*// ) {
			# anonymous TLS
			++$$stats{'postfix:smtp:TLS:Anonymous'};
		} elsif ( $line =~ s/^Untrusted TLS connection established to\s*// ) {
			# untrusted TLS
			++$$stats{'postfix:smtp:TLS:Untrusted'};
		} elsif ( $line =~ s/^Verified TLS connection established to\s*// ) {
			# verified TLS
			++$$stats{'postfix:smtp:TLS:Verified'};
		} elsif ( $line =~ s/^certificate verification failed for\s*//
			or $line =~ s/^server certificate verification failed for\s*// ) {
			# certificate verification failed for some reason
			++$$stats{'postfix:smtp:TLS:certverifyfail'};
			if ( $line =~ s/^.*:\s*self-signed certificate$// ) {
				# they are using self-signed certificates
				++$$stats{'postfix:smtp:TLS:certverifyfail:selfsigned'};
			} elsif ( $line =~ s/^.*:\s*untrusted issuer.*$// ) {
				# they are using an CA we don't recognise
				++$$stats{'postfix:smtp:TLS:certverifyfail:untrusted'};
			} elsif ( $line =~ s/^.*:\s*certificate has expired.*$// ) {
				# they are using an expired certificate
				++$$stats{'postfix:smtp:TLS:certverifyfail:expired'};
			} else {
				# some other unknown reason
				warn __FILE__." $VERSION:".__LINE__." $log:$number unknown: $origline\n";
				++$$stats{'postfix:smtp:TLS:certverifyfail:other'};
			}
		} elsif ( $line =~ s/^[0-9A-F]+: Cannot start TLS: handshake failure// ) {
			++$$stats{'postfix:smtp:TLS:failtostart'};	# not used as TLS with lost connection above takes care of this
		} elsif ( $line =~ s/^Host offered STARTTLS: // ) {
			# ignore
		} elsif ( $line =~ s/^warning:\s*// ) {
			# warnings
			++$$stats{'postfix:smtp:warning'};
			# TODO does this really mean a connection? Nope! Probably no connection at all
#			# connection
#			++$$stats{'postfix:smtp:connect'};
#			smtpd_ip ( $line, $origline, $log, $number );
			# TODO do more indepth analysis ? TODO
		} elsif ( $line =~ s/^[0-9A-F]+: host .+ (said|refused to talk to me): \s*// ) {
			# this happens on all but the last connections to a list of MXs
			# we ignore any further analysis of the specific error message here as
			# we are logging them on a per-delivery attempt basis rather than a 
			# per-connection basis.  For now anyway....
			# connection
			++$$stats{'postfix:smtp:connect'};
			smtpd_ip ( $line, $origline, $number, $log, $stats );
		} elsif ( $line =~ s/^[0-9A-F]+: to=.* status=deferred \((.*)\)"?$/$1/ ) {	# seem to be getting a stray quote from some people TODO
			# deferred 
			++$$stats{'postfix:smtp:deferred'};
			# connection
			++$$stats{'postfix:smtp:connect'};
			smtpd_ip ( $line, $origline, $number, $log, $stats );
			# this line happens when a delivery attempt (multiple MXs) fails after optinos have been exhausted
			# further analysis
			my $message = $line;
			my $smtpcode;
			my $esmtpcode;
			if ( $message =~ s/^(delivery temporarily suspended: )?host [\w\.\-]+\[[\w\.:]+\] (said|refused to talk to me): (4[25][01234]|433|45[79]|55[04])[ \-]// ) {
				$smtpcode = $3;
				if ( $message =~ s/^#?(\d\.\d\.\d)\s+//		# as per RFC2034 - "must preface the text part"
					or $message =~ s/\s*\(#(\d\.\d\.\d)\)// ) {	# qmail puts esmtp codes at the end in this format
					$esmtpcode = $1;
				} 
			} else {
				$message = '';
			}
			if ( ( defined $esmtpcode and
					(	# specific ESMTP codes from RFC1893 - these do seem more consistently used than SMTP codes
						# See http://tools.ietf.org/html/rfc1893
						# IMPORTANT: These codes should only be specific (ie. not "other" codes like 4.x.0) else we risk wrongly identifying status:
					$esmtpcode eq '4.2.2'	# Mailbox full
					or $esmtpcode eq '4.3.1'	# Mail system full
					or $esmtpcode eq '4.3.2'	# System not accepting network messages
					or $esmtpcode eq '4.3.5'	# System incorrectly configured
					or $esmtpcode eq '4.4.1'	# No answer from host
					or $esmtpcode eq '4.4.2'	# Bad connection
					or $esmtpcode eq '4.4.3'	# Directory server failure
					or $esmtpcode eq '4.4.4'	# Unable to route
					or $esmtpcode eq '4.4.5'	# Mail system congestion
					or $esmtpcode eq '4.4.6'	# Routing loop detected
					or $esmtpcode eq '4.4.7'	# Delivery time expired
					) )
				or ( $message ne '' and (
					$message =~ s/Cannot process .+ GRD failure//i
					or $message =~ s/Domain size limit exceeded//i	# user has exceeded their limit with their hosting provider
					or $message =~ s/Don't use the Backup MX '.+' while the Primary MX is available[ \-]+//i	# and how does it know if it's available to us or not?
					or $message =~ s/Internal server error//i
					or $message =~ s/inusfficient system storage//i
					or $message =~ s/load too high//i
					or $message =~ s/Mailbox disabled//i	# should normally bounce, hence broken server
					or $message =~ s/Mailbox not found//i	# should normally bounce, hence broken server
					or $message =~ s/mailbox unavailable//i
					or $message =~ s/No PTR record available in DNS//i
					or $message =~ s/not accepting (messages|network messages)//i
					or $message =~ s/over quota//i
					or $message =~ s/queue file write error//i
					or $message =~ s/qq read error//i
					or $message =~ s/qqt failure//i
					or $message =~ s/rate that is limited//i
					or $message =~ s/Requested action (aborted|not taken): local error in processing//i
					or $message =~ s/Requested action not taken: mailbox unavailable//i
					or $message =~ s/Requested action aborted: try again later//i
					or $message =~ s/Resources unavailable temporarily//i
					or $message =~ s/Server not available//i
					or $message =~ s/Service (not available|Unavailable|is unavailable)//i
					or $message =~ s/system resources//i
					or $message =~ s/Temporary (Resources unavailable|failure|lookup failure|service error)//i
					or $message =~ s/Too many (concurrent|connections|simultaneous connections)//i	# TODO this could actually be a form of greylisting too - ie. we don't know if it's overload or anti-spam
					or $message =~ s/Too much load//i
					or $message =~ s/trouble in home directory//i
					or $message =~ s/Unable to accept this email at the moment//i
					or $message =~ s/undeliverable address: unknown user//i	# should normally bounce, hence broken server
					or $message =~ s/Unexpected failure//i
					or $message =~ s/Recipient address rejected: User unknown in (local|virtual) (recipient|mailbox) table//i	# should normally bounce, hence broken server
					or $message =~ s/^Requested action aborted\s*//i
					or $message =~ s/Server configuration problem//i
					or $message =~ s/Recipient address rejected: temporary server error //i
					or $message =~ s/error in error handling //i
				) )
				or $line =~ s/^.* Connection refused$//i
				or $line =~ s/^.* Connection timed out$//i	# TODO should this be mixed up with in-conversation trimeouts below?
				or $line =~ s/^connect to [\w\.\-]+\[[\w\.:]+\]:25: No route to host$//i
				or $line =~ s/mail for .+ loops back to myself//i ) {	# TODO - many other possible reasons to add
				# other side is broken
				++$$stats{'postfix:smtp:deferred:brokenserver'};
			} elsif ( ( defined $esmtpcode and
					(	# specific ESMTP codes from RFC1893 - these do seem more consistently used than SMTP codes
						# IMPORTANT: These codes should only be specific (ie. not "other" codes like 4.x.0) else we risk wrongly identifying status:
					$esmtpcode eq '4.2.1'		# Mailbox diabled (temporary) eg. rate limiting
					or $esmtpcode eq '4.7.0'	# non-descript security related delay - assume greylist
					or $esmtpcode eq '4.7.1'	# Delivery not authorized, message refused
				) )
				or ( $message ne '' and (
				$message =~ s/closing connection//
				or $message =~ s/^connect to [\w\.\-]+\[[\w\.:]+\]:25: Connection timed out//i
				or $message =~ s/Could not complete recipient verify callout//i
				or $message =~ s/Could not complete sender verify callout//i
				or $message =~ s/\(DYN:T1\) +http:\/\/postmaster\.info\.aol\.com\/errors\/421dynt1\.html//i
				or $message =~ s/^.*gr[ea]ylist.*$//i
				or $message =~ s/^.*Gr[ea]y-list.*$//i
				or $message =~ s/^.*g-r-[ea]-y-l-i-s-t.*$//i
				or $message =~ s/ http:\/\/kb\.mimecast\.com\/Mimecast_Knowledge_Base\/Administration_Console\/Monitoring\/Mimecast_SMTP_Error_Codes#451 //	# old
				or $message =~ s/^IP temporarily blacklisted - https:\/\/community\.mimecast\.com\/docs\/DOC-1369#451 //	# 20160718
				or $message =~ s/Internal resource temporarily unavailable - http:\/\/www\.mimecast\.com\/knowledgebase\/KBID10473\.htm//
				or $message =~ s/Internal resource temporarily unavailable - https:\/\/community\.mimecast\.com\/docs\/DOC-1369#451//
				or $message =~ s/Maybe later is better//i
				or $message =~ s/Message has been refused by antispam//i
				or $message =~ s/message is probably spam//i
				or $message =~ s/Message temporarily deferred//i
				or $message =~ s/not yet authorized//i
				or $message =~ s/Please refer to http:\/\/help\.yahoo\.com\/help\/us\/mail\/defer\/defer-06\.html//
				or $message =~ s/Please visit http:\/\/www\.google\.com\/mail\/help\/bulk_mail\.html//
				or $message =~ s/http:\/\/www\.google\.com\/mail\/help\/bulk_mail\.html//
				or $message =~ s/see http:\/\/postmaster\.yahoo\.com\/errors\/421-ts02\.html//
				or $message =~ s/Sender address deferred by rule//i
				or $message =~ s/Sender address verification in progress//i
				or $message =~ s/service temporarily unavailable//i
				or $message =~ s/Sprobuj za pietnascie sekund//i
				or $message =~ s/Recipient address rejected: Too many recent unknown recipients from //i
				or $message =~ s/temporary envelope failure//i	# not completey certain if this is greylist or brokenserver
				or $message =~ s/Temporary authentication failure//i	# not completey certain if this is greylist or brokenserver
				or $message =~ s/Temporarily blocked for \d+ seconds//i
				or $message =~ s/Temporarily rejected//i
				or $message =~ s/The user you are trying to contact is receiving mail too quickly//i
				or $message =~ s/Too many messages for this recipient at the moment //i
				or $message =~ s/Too many recipients received from the sender //i	# this is possibly a misleading message that it greylists over a threshold .... maybe
				or $message =~ s/too much mail from //i
				or $message =~ s/Unable to validate [^\s]+ with the MX mailserver for 451 [^\s]+ \(tested with a fake bounce back\)//
				or $message =~ s/unverified address: Address (lookup failed|verification in progress)//i
				or $message =~ s/visit http:\/\/support\.google\.com\/mail\/bin\/answer\.py\?answer=6592//
				or $message =~ s/^.*will not accept any messages to this user within\s*//
				or $message =~ s/(try again|please retry|retry later|try later|deferring connection)//i ) )
				) {	# TODO - many other possible reasons to add
				# we got greylisted
				++$$stats{'postfix:smtp:deferred:greylist'};
#			} elsif ( $line =~ s/^host [\w\.\-]+\[[\w\.:]+\] refused to talk to me: 550 rejected because of not in approved list//i ) {
#				# presumably a misconfigured server - other side is broken TODO or maybe greylisting TODO
#				++$$stats{'postfix:smtp:deferred:brokenserver'};
			} elsif ( $line =~ s/^Host or domain not found//i
				or $line =~ s/^Host or domain name not found//i
				# these are remote so may be treated separately later TODO
				or $message =~ s/^<.+>: Sender address rejected: Domain not found//i
				or $message =~ s/^<.+>: Sender address rejected: unverified address: Host or domain name not found\. Name service error for //i
				or $message =~ s/^<.+>: Sender address rejected: undeliverable address: Host or domain name not found. Name service error for //i
				or $message =~ s/^Sender verification failed//
				or $message =~ s/^<.+>: Recipient address rejected: Domain not found//i
				or $message =~ s/^:  \(DNS:NR\)  http:\/\/postmaster\.info\.aol\.com\/errors\/421dnsnr.html \(in reply to end of DATA command\)$//
				or $message =~ s/^Domain of sender address [^\s]+ does not resolve//i
				or $message =~ s/^Refused\. The domain of your sender address has no mail exchanger//
				or $message =~ s/^This system is configured to reject mail from .+ ?\[.+\] \(DNS reverse lookup failed\)//i ) {
				# dns is broken
				++$$stats{'postfix:smtp:deferred:dnserror'};
			} elsif ( $line =~ s/^lost connection with //i ) {
				# lost connection
				++$$stats{'postfix:smtp:deferred:lostconnection'};
			} elsif ( $line =~ s/^.*timeout.*$//i
				or $line =~ s/^.*timed out.*$//i ) {
				# connection timed out
				++$$stats{'postfix:smtp:deferred:timeout'};
			} elsif ( $line =~ s/^.*Network is unreachable.*$//i ) {
				# ignore - alredy should be caught before
				--$$stats{'postfix:smtp:connect'};	# don't want to increment twice
				smtpd_ip ( $line, $origline, $number, $log, $stats );
			} elsif ( $message =~ s/^Your host has been blacklisted//i ) {
				# the other side is telling us we are blacklisted
				++$$stats{'postfix:smtp:deferred:blacklisted'};
			} elsif ( defined ( $smtpcode ) and $smtpcode == 554 and $message =~ s/^[\w\-\.]+\.[\w\-\.]+$//i	# returning a fqdn as a message
				) {
				# we can't tell why - insufficient / ambigous info
				++$$stats{'postfix:smtp:deferred:indeterminate'};
			} else {
				# some other
				++$$stats{'postfix:smtp:deferred:other'};
				# don't squark directly about this - add to the lists of new stuff
#print "*>$smtpcode $esmtpcode\n->$message\n";
				push @deferreasons, __LINE__.":\"$origline\"\n";
				push @deferreasons, __LINE__.":\$message: \"$message\"\n";
			}
		} elsif ( $line =~ s/^[0-9A-F]+: to=.* status=bounced \((.*)\)$/$1/ ) {
			# bounced - failed message
			++$$stats{'postfix:smtp:bounced'};
			# connection
			++$$stats{'postfix:smtp:connect'};
			smtpd_ip ( $line, $origline, $number, $log, $stats );
			# TODO do more indepth analysis TODO
		} elsif ( $line =~ s/^[0-9A-F]+: to=.* status=sent \(250[ \-]// ) {
			# sent - success
			++$$stats{'postfix:smtp:sent'};
			# connection
			++$$stats{'postfix:smtp:connect'};
			smtpd_ip ( $line, $origline, $number, $log, $stats );
		} elsif ( $line =~ s/^[\w\.\-]+\[[\w\.:]+\]:\d+: re-using session with untrusted certificate, look for details earlier in the log// ) {
			# ignore
		} elsif ( $line =~ s/^[0-9A-F]+: enabling PIX .*// ) {
			# ignore
		} elsif ( $line =~ s/^[0-9A-F]+: sender non-delivery notification// ) {
			# ignore
		} elsif ( $line =~ s/^[0-9A-F]+: breaking line > \d+ bytes with <CR><LF>SPACE// ) {
			# ignore
		} else {
			# some other
			++$$stats{'postfix:smtp:other'};
			warn __FILE__." $VERSION:".__LINE__." $log:$number unknown: $origline\n";
		}
########################## local delivery ##########################
	} elsif ( $line =~ s/^(local|virtual|pipe)\[\d+\]:\s*// ) {
		if ( $line =~ s/^[0-9A-F]+: to=.* status=sent\s*// ) {
			# delivered locally
			++$$stats{'postfix:local:sent'};
			if ( $line =~ s/^\(delivered to maildir\)// ) {
				# delivered to maildir
				++$$stats{'postfix:local:sent:maildir'};
			} elsif ( $line =~ s/^\(delivered to file:\s*[^\)]*\)// ) {
				# delivered to file
				++$$stats{'postfix:local:sent:file'};
			} elsif ( $line =~ s/^\(delivered to mailbox\)// ) {
				# delivered to file
				++$$stats{'postfix:local:sent:mailbox'};
			} elsif ( $line =~ s/^\(delivered to command:\s*[^\)]*\)// ) {
				# delivered to command
				++$$stats{'postfix:local:sent:command'};
			} elsif ( $line =~ s/^\(forwarded as [0-9A-F]+\)// ) {
				# forwarded on
				++$$stats{'postfix:local:sent:forwarded'};
			} elsif ( $line =~ s/^\(delivered via dovecot service.*\)// ) {	# TODO do better than .*
				# delivery to dovecot
				++$$stats{'postfix:local:sent:dovecot'};
			} elsif ( $line =~ s/^\(delivered via zarafa service\)// ) {
				# delivery to zarafa
				++$$stats{'postfix:local:sent:zarafa'};
			} elsif ( $line =~ s/^\(delivered via mailman service\)// ) {
				# delivery to a mailing list manager (MLM)
				++$$stats{'postfix:local:sent:mlm'};
			} else {
				# some other
				++$$stats{'postfix:local:sent:other'};
				warn __FILE__." $VERSION:".__LINE__." $log:$number unknown: $origline\n";
			}
		} elsif ( $line =~ s/^[0-9A-F]+: to=.* status=deferred\s*// ) {
			# something went wrong
			++$$stats{'postfix:local:deferred'};
		} elsif ( $line =~ s/^[0-9A-F]+: to=.* status=bounced\s*// ) {
			# something went very wrong
			++$$stats{'postfix:local:bounced'};
		} elsif ( $IGNOREERRORS and
			( $line =~ s/^warning: database \/etc\/aliases.db is older than source file \/etc\/aliases$// ) ) {
			# ignore error
		} else {
			# some other
			++$$stats{'postfix:local:other'};
			warn __FILE__." $VERSION:".__LINE__." $log:$number unknown: $origline\n";
		}
	} elsif ( $line =~ s/^lmtp\[\d+\]:\s*// ) {	# TODO
		if ( $line =~ s/^[0-9A-F]+: to=.* status=sent\s*// ) {
			# delivered
			++$$stats{'postfix:lmtp:sent'};
		} elsif ( $line =~ s/^[0-9A-F]+: to=.* status=deferred\s*// ) {
			# something went wrong
			++$$stats{'postfix:lmtp:deferred'};
		} elsif ( $line =~ s/^[0-9A-F]+: to=.* status=bounced\s*// ) {
			# something went very wrong
			++$$stats{'postfix:lmtp:bounced'};
		} elsif ( $line =~ s/^connect to [\w\.\-]+\[[\w\.:]+\]:\d+: Connection refused// ) {
			# service not there - this should result in deferred line so no need to record
		} else {
			# some other
			++$$stats{'postfix:lmtp:other'};
			warn __FILE__." $VERSION:".__LINE__." $log:$number unknown: $origline\n";
		}
	} elsif ( $line =~ s/^postdrop\[\d+\]:\s*// ) {
		# possible things to monitor: TODO
		# /^warning: uid=\d+: File too large$/
	} elsif ( $line =~ s/^sendmail\[\d+\]:\s*// ) {
		# possible things to monitor: TODO
		# /^fatal: .+\(\d+\): message file too big/
	} elsif ( $line =~ s/^bounce\[\d+\]:\s*// ) {
		# ignore.... for now anyway
	} elsif ( $line =~ s/^anvil\[\d+\]:\s*// ) {
		# ignore
	} elsif ( $line =~ s/^qmgr\[\d+\]:\s*// ) {
		# ignore
	} elsif ( $line =~ s/^scache\[\d+\]:\s*// ) {
		# ignore
	} elsif ( $line =~ s/^cleanup\[\d+\]:\s*// ) {
		if ( $line =~ s/^[0-9A-F]+: milter-reject: END-OF-MESSAGE from [\w\.\-]+\[[\w\.:]+\]: 5\.7\.1 Blocked by SpamAssassin;\s*// ) {
			# de-queued by cleanup
			--$$stats{'postfix:smtpd:QUEUED'};
			# mark as caught by spamassassin
			++$$stats{'postfix:cleanup:spamassassin'};
		} else {
			# ignore
		}
	} elsif ( $line =~ s/^error\[\d+\]:\s*// ) {
		# ignore
	} elsif ( $line =~ s/^(postfix-)?script\[\d+\]:\s*// ) {
		# ignore - the likes of:
		# postfix/postfix-script[\d+]: starting the Postfix mail system
	} elsif ( $line =~ s/^trivial-rewrite\[\d+\]:\s*// ) {
		if ( $line =~ s/^table hash:.+ has changed -- restarting// ) {
			# ignore
		} elsif ( $IGNOREERRORS and
			( $line =~ s/^fatal: proxy:mysql:\/.+\(0,lock|fold_fix\): table lookup problem$// ) ) {
			# ignore error
		} else {
			# useful to know of others
			warn __FILE__." $VERSION:".__LINE__." $log:$number unknown: $origline\n";
		}
	} elsif ( $line =~ s/^master\[\d+\]:\s*// ) {
		if ( $line =~ s/^terminating on signal 15$// ) {
			# ignore stops
		} elsif ( $line =~ s/^daemon started -- version [0-9\.]+, configuration \/etc\/postfix$// ) {
			# ignore starts
		}
	} elsif ( $line =~ s/^policy-spf\[\d+\]:\s*// ) {
		if ( $line =~ s/: SPF None \(No applicable sender policy available\): \s*//i
			or $line =~ s/^Policy action=PREPEND Received-SPF: none //i
			or $line =~ s/^Policy action=DUNNO//i ) {	# TODO not sure on this - some stuff that was "none" is now DUNNO, but "none" is still used for others
			++$$stats{'postfix:policy:policy-spf:none'};
		} elsif ( $line =~ s/: Policy action=PREPEND X-Comment: SPF skipped for whitelisted relay//
			or $line =~ s/^Policy action=PREPEND Authentication-Results: .+; none \(SPF not checked for whitelisted relay\)$// ) {
			++$$stats{'postfix:policy:policy-spf:whitelisted'};
		} elsif ( $line =~ s/: SPF Pass //i
			or $line =~ s/^Policy action=PREPEND Received-SPF: pass //i ) {
			++$$stats{'postfix:policy:policy-spf:pass'};
		} elsif ( $line =~ s/: SPF Neutral //i
			or $line =~ s/^Policy action=PREPEND Received-SPF: neutral //i
			or $line =~ s/: SPF NeutralByDefault //i
			or $line =~ s/: SPF neutral-by-default //i ) {
			++$$stats{'postfix:policy:policy-spf:neutral'};
		} elsif ( $line =~ s/: SPF SoftFail //i
			or $line =~ s/^Policy action=PREPEND Received-SPF: softfail //i ) {
			++$$stats{'postfix:policy:policy-spf:softfail'};
		} elsif ( $line =~ s/: SPF Fail //i
			or $line =~ s/^Policy action=550 Please see http:\/\/www\.openspf\.(net|org)\/Why\?// ) {
			++$$stats{'postfix:policy:policy-spf:fail'};
		} elsif ( $line =~ s/: SPF TempError //i
			or $line =~ s/^Policy action=DEFER_IF_PERMIT SPF-Result=[^:]+: 'SERVFAIL' // ) {	# presuming DNS was previously classed as temp
			++$$stats{'postfix:policy:policy-spf:temperror'};
		} elsif ( $line =~ s/: SPF PermError //i
			or $line =~ s/^Policy action=PREPEND Received-SPF: permerror //i ) {
			++$$stats{'postfix:policy:policy-spf:permerror'};


#		} elsif ( $line =~ s/: Policy action=PREPEND X-Comment: SPF skipped for whitelisted relay//
#			or $line =~ s/: Policy action=PREPEND Received-SPF: none //
#			or $line =~ s/: Policy action=PREPEND Received-SPF: neutral //
#			or $line =~ s/: Policy action=PREPEND Received-SPF: pass //
#			or $line =~ s/: Policy action=PREPEND Received-SPF: permerror //
#			or $line =~ s/: Policy action=DEFER_IF_PERMIT //
#			or $line =~ s/: Policy action=DUNNO//
#			or $line =~ s/handler sender_policy_framework: is decisive\.//
#			or $line =~ s/handler exempt_relay: is decisive\.// ) {
#			# ignore
		} else {
			++$$stats{'postfix:policy:policy-spf:other'};
			warn __FILE__." $VERSION:".__LINE__." $log:$number unknown: $origline\n";
		}
	} elsif ( $line =~ s/^postsuper\[\d+\]:\s*// ) {
		# ignore
	} elsif ( $line =~ s/^dnsblog\[\d+\]:\s*// ) {
		# ignore - details of rbl
	} elsif ( $line =~ s/^postscreen\[\d+\]:\s*// ) {
		# ignore - currently not supported by this
	} elsif ( $line =~ s/^tlsproxy\[\d+\]:\s*// ) {
		# treat as smtpd if enabled else ignore as not supported by this
		if ( $INCLUDETLSPROXY ) {
			# note - this is largely a repeat of smtpd code above - TODO improve this
			# TODO for now we'll only include the cases we have examples of
			#if ( $line =~ s/^setting up TLS connection from\s*// ) {
			#	# we are at least trying - TODO currently not used
			#	++$$stats{'postfix:smtpd:TLS'};
			#} elsif ( $line =~ s/^Trusted TLS connection established from // ) {
			#	# trusted TLS
			#	++$$stats{'postfix:smtpd:TLS:Trusted'};
			#}
			if ( $line =~ s/^Anonymous TLS connection established from // ) {
				# anonymous TLS
				++$$stats{'postfix:smtpd:TLS:Anonymous'};
			#} elsif ( $line =~ s/^Untrusted TLS connection established from\s*// ) {
			#	# untrusted TLS #
			#	++$$stats{'postfix:smtpd:TLS:Untrusted'};
			#} elsif ( $line =~ s/^certificate verification failed for\s*//
			#	or $line =~ s/^client certificate verification failed for\s*// ) {
			#	# certificate verification failed for some reason
			#	++$$stats{'postfix:smtpd:TLS:certverifyfail'};
			#	if ( $line =~ s/^.*:\s*self-signed certificate$// ) {
			#		# they are using self-signed certificates
			#		++$$stats{'postfix:smtpd:TLS:certverifyfail:selfsigned'};
			#	} elsif ( $line =~ s/^.*:\s*untrusted issuer.*$// ) {
			#		# they are using an CA we don't recognise
			#		++$$stats{'postfix:smtpd:TLS:certverifyfail:untrusted'};
			#	} elsif ( $line =~ s/^.*:\s*certificate has expired.*$// ) {
			#		# they are using an expired certificate
			#		++$$stats{'postfix:smtpd:TLS:certverifyfail:expired'};
			#	} elsif ( $line =~ s/^.*:\s*not designated for use as a client certificate$// ) {
			#		# they are using a certificate not meant for this
			#		++$$stats{'postfix:smtpd:TLS:certverifyfail:notclient'};
			#	} else {
			#		# some other unknown reason
			#		warn __FILE__." $VERSION:".__LINE__." $log:$number unknown: $origline\n";
			#		++$$stats{'postfix:smtpd:TLS:certverifyfail:other'};
			#	}
	#		} elsif ( $line =~ s/^[^\s]+: Untrusted: subject_CN=, issuer=[^,]+, fingerprint=[\dA-F:]+$// ) {
				# ignore - alredy should be caught before
			#} elsif ( $line =~ s/^SSL_accept error from // ) {
			#	# anonymous TLS
			#	++$$stats{'postfix:smtpd:SSL:error'};
			#	# TODO expand on this
			} elsif ( $line =~ s/^CONNECT from // ) {
				# inbound snmp connection
				++$$stats{'postfix:smtpd:connect'};
				# get ipv4/ipv6 stats
				if ( $line =~ s/^.*\[[\d+.]+\]// ) {
					++$$stats{'postfix:smtpd:connect:ipv4'};
				} elsif ( $line =~ s/^.*\[[\da-f:]+(%eth\d)?\]// ) {
					++$$stats{'postfix:smtpd:connect:ipv6'};
				} elsif ( $line =~ s/^.*\[unknown\]// ) {
					# ignore - it was so brief we didn't get the address
				} else {
					warn __FILE__." $VERSION:".__LINE__." $log:$number unknown: $origline\n";
				}
			} elsif ( $line =~ s/^DISCONNECT // ) {
				# ignore
			} else {
				# some other type
				++$$stats{'postfix:smtpd:other'};
				warn __FILE__." $VERSION:".__LINE__." $log:$number unknown: $origline\n";
			}
		}
	} elsif ( $IGNOREERRORS and
		( $line =~ s/proxymap\[\d+\]: warning: connect to mysql server .+: Can't connect to MySQL server on '.+' \(111\)$// ) ) {
		# ignore error
	} else {
		warn __FILE__." $VERSION:".__LINE__." $log:$number unknown: $origline\n";
	}
}





# since there are so many places that log smtp connects, best to break this off
sub smtpd_ip {
	my ( $line, $origline, $number, $log, $stats, $dec ) = @_;
	my $direction = 1;
	if ( defined $dec and $dec ) { $direction = -1; }
	# get ipv4/ipv6 stats
	if ( $origline =~ /\[[\d\.]+\]:25/
		or $origline =~ /\[[\d\.]+\] said:/
		or $origline =~ /\[[\d\.]+\] refused to talk to me:/ ) {
		$$stats{'postfix:smtp:connect:ipv4'} += $direction;
	} elsif ( $origline =~ /\[[\da-f:]+\]:25/
		or $origline =~ /\[[\da-f:]+\] said:/
		or $origline =~ /\[[\da-f:]+\] refused to talk to me:/ ) {
		$$stats{'postfix:smtp:connect:ipv6'} += $direction;
	} elsif ( $origline =~ /Host or domain name not found/
		or $origline =~ /warning: network_biopair_interop: error writing/
		or $origline =~ /Host found but no data record of requested type/
		or $origline =~ /warning: no MX host for [^\s]+ has a valid address record/
		or $origline =~ /mail for [^\s]+ loops back to myself/ ) {
		# ignore - there is no address
	} elsif ( $origline =~ /\[[\d\.]+\]:\d+,/ ) {
		# handle deliveries to custom ports, do this last to avoid false hits
		$$stats{'postfix:smtp:connect:ipv4'} += $direction;
	} elsif ( $origline =~ /\[[\da-f:]+\]\d+,/ ) {
		$$stats{'postfix:smtp:connect:ipv6'} += $direction;
	} else {
		warn __FILE__." $VERSION:".__LINE__." $log:$number unknown: $origline\n";
	}
}



\&register;
