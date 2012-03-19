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
# See: http://www.pitt-pladdy.com/blog/_20091122-164951_0000_Postfix_stats_on_Cacti_via_SNMP_/
#
package postfix;
our $VERSION = 20120319;
#
# Thanks for ideas, unhandled log lines, patches and feedback to:
#
# "Ronny"
# Scott Merrill
# "Charles"
# Przemek Przechowski



our $QUEUEDIR = "/var/spool/postfix";
our @deferreasons;


sub register {
	my ( $lines, $ends ) = @_;
	push @$lines, \&analyse;
	push @$ends, \&wrapup;
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
			# get postfix compoent out - it can look like a host
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
	if ( $line !~ /^.+ postfix\/[\w\-]+\[\d+\]:\s*/ ) { return; }
############################## pickup ##############################
	if ( $line =~ /^.+ postfix\/pickup\[\d+\]:/ ) {
		# sent locally
		++$$stats{'postfix:pickup'};
############################### snmpd ##############################
	} elsif ( $line =~ s/^.+ postfix\/smtpd\[\d+\]:\s*// ) {
		if ( $line =~ s/^connect from\s*// ) {
			# inbound snmp connection
			++$$stats{'postfix:smtpd:connect'};
			# get ipv4/ipv6 stats
			if ( $line =~ s/^.*\[[\d+.]+\]// ) {
				++$$stats{'postfix:smtpd:connect:ipv4'};
			} elsif ( $line =~ s/^.*\[[\da-f:]+\]// ) {
				++$$stats{'postfix:smtpd:connect:ipv6'};
			} elsif ( $line =~ s/^.*\[unknown\]// ) {
				# ignore - it was so brief we didn't get the address
			} else {
				print STDERR __FILE__." $VERSION:".__LINE__." $log:$number unknown: $origline\n";
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
		} elsif ( $line =~ s/^NOQUEUE:\s*// ) {
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
				} elsif ( $line =~ s/^.*: .+ Service unavailable; Client host \[[\w\.:]+\] blocked using\s+// ) {
					# RBL stopped it
					++$$stats{'postfix:smtpd:NOQUEUE:reject:RBL'};
				} elsif ( $line =~ s/^.*: Recipient address rejected:\s*// ) {
					# don't like recipient
					++$$stats{'postfix:smtpd:NOQUEUE:reject:Recipient'};
					if ( $line =~ s/^need fully-qualified address;//i ) {
						# recipient address not fully qualified
						++$$stats{'postfix:smtpd:NOQUEUE:reject:Recipient:fullyquallifiedaddr'};
					} elsif ( $line =~ s/^.*\s*Greylisted\s*//i or $line =~ s/451 .*Please try again later//i ) {
						# greylisted
						++$$stats{'postfix:smtpd:NOQUEUE:reject:Recipient:Greylisted'};
					} elsif ( $line =~ s/^Access denied;//i ) {
						# explicitly denied
						++$$stats{'postfix:smtpd:NOQUEUE:reject:Recipient:denied'};
					} elsif ( $line =~ s/^User unknown in (local|relay) recipient table;//i ) {
						# don't know this user
						++$$stats{'postfix:smtpd:NOQUEUE:reject:Recipient:unknownuser'};
					} else {
						# some other reason
						++$$stats{'postfix:smtpd:NOQUEUE:reject:Recipient:other'};
						# don't report customised rejections
						#print STDERR __FILE__." $VERSION:".__LINE__." $log:$number unknown: $origline\n";
					}
				} elsif ( $line =~ s/^.*: Sender address rejected:\s*// ) {
					# don't like sender
					++$$stats{'postfix:smtpd:NOQUEUE:reject:Sender'};
					if ( $line =~ s/^Access denied;//i ) {
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
					} elsif ( $line =~ s/^not owned by user [^\s]+;//i ) {
						# using an address their login doesn't allow
						++$$stats{'postfix:smtpd:NOQUEUE:reject:Sender:addrnotowned'};
					} else {
						# some other reason
						++$$stats{'postfix:smtpd:NOQUEUE:reject:Sender:other'};
						print STDERR __FILE__." $VERSION:".__LINE__." $log:$number unknown: $origline\n";
					}
				} else {
					# other rejection
					++$$stats{'postfix:smtpd:NOQUEUE:reject:other'};
					print STDERR __FILE__." $VERSION:".__LINE__." $log:$number unknown: $origline\n";
				}
			} else {
				# other
				++$$stats{'postfix:smtpd:NOQUEUE:other'};
				print STDERR __FILE__." $VERSION:".__LINE__." $log:$number unknown: $origline\n";
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
				print STDERR __FILE__." $VERSION:".__LINE__." $log:$number unknown: $origline\n";
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
			# TODO expand on this
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
		} else {
			# some other type
			++$$stats{'postfix:smtpd:other'};
			print STDERR __FILE__." $VERSION:".__LINE__." $log:$number unknown: $origline\n";
		}
############################### smtp ###############################
	} elsif ( $line =~ s/^.+ postfix\/smtp\[\d+\]:\s*// ) {
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
				print STDERR __FILE__." $VERSION:".__LINE__." $log:$number unknown: $origline\n";
			}
		} elsif ( $line =~ s/^setting up TLS connection to\s*// ) {
			# we are at least trying - currently not used
			++$$stats{'postfix:smtp:TLS'};
		} elsif ( $line =~ s/^Trusted TLS connection established to\s*// ) {
			# trusted TLS
			++$$stats{'postfix:smtp:TLS:Trusted'};
		} elsif ( $line =~ s/^Untrusted TLS connection established to\s*// ) {
			# untrusted TLS
			++$$stats{'postfix:smtp:TLS:Untrusted'};
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
				print STDERR __FILE__." $VERSION:".__LINE__." $log:$number unknown: $origline\n";
				++$$stats{'postfix:smtp:TLS:certverifyfail:other'};
			}
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
		} elsif ( $line =~ s/^[0-9A-F]+: to=.* status=deferred \((.*)\)$/$1/ ) {
			# deferred 
			++$$stats{'postfix:smtp:deferred'};
			# connection
			++$$stats{'postfix:smtp:connect'};
			smtpd_ip ( $line, $origline, $number, $log, $stats );
			# this line happens when a delivery attempt (multiple MXs) fails after optinos have been exhausted
			# further analysis
			my $message = $line;
			if ( $message !~ s/^(delivery temporarily suspended: ){0,1}host [\w\.\-]+\[[\w\.:]+\] (said|refused to talk to me): (4[25][0124]|554)[ \-]// ) { $message = ''; }
				else { $message =~ s/\d\.\d\.\d //; }
			if ( ( $message ne '' and (
				$message =~ s/Cannot process .+ GRD failure//i
				or $message =~ s/inusfficient system storage//i
				or $message =~ s/load too high//i
				or $message =~ s/No PTR record available in DNS//i
				or $message =~ s/not accepting (messages|network messages)//i
				or $message =~ s/over quota//i
				or $message =~ s/queue file write error//i
				or $message =~ s/rate that is limited//i
				or $message =~ s/Requested action (aborted|not taken): local error in processing//i
				or $message =~ s/Requested action not taken: mailbox unavailable//i
				or $message =~ s/Requested action aborted: try again later//i
				or $message =~ s/Resources unavailable temporarily//i
				or $message =~ s/Service (not available|Unavailable|is unavailable)//i
				or $message =~ s/system resources//i
				or $message =~ s/Temporary (Resources unavailable|failure|lookup failure)//i
				or $message =~ s/Too much load//i
				or $message =~ s/Too many (concurrent|connections)//i
				or $message =~ s/Unable to accept this email at the moment//i
				or $message =~ s/Unexpected failure//i
				) )
				or $line =~ s/^.* Connection refused$//i
				or $line =~ s/^.* Connection timed out$//i
				or $line =~ s/mail for .+ loops back to myself//i ) {	# TODO - many other possible reasons to add
				# other side is broken
				++$$stats{'postfix:smtp:deferred:brokenserver'};
			} elsif ( $message ne '' and (
				$message =~ s/closing connection//
				or $message =~ s/^connect to [\w\.\-]+\[[\w\.:]+\]:25: Connection timed out//i
				or $message =~ s/Could not complete recipient verify callout//i
				or $message =~ s/Could not complete sender verify callout//i
				or $message =~ s/\(DYN:T1\) http:\/\/postmaster\.info\.aol\.com\/errors\/421dynt1\.html//i
				or $message =~ s/^.*gr[ea]ylist.*$//i
				or $message =~ s/^.*Gr[ea]y-list.*$//i
				or $message =~ s/Maybe later is better//i
				or $message =~ s/Message has been refused by antispam//i
				or $message =~ s/not yet authorized//i
				or $message =~ s/Please refer to http:\/\/help\.yahoo\.com\/help\/us\/mail\/defer\/defer-06\.html//
				or $message =~ s/see http:\/\/postmaster\.yahoo\.com\/errors\/421-ts02\.html//
				or $message =~ s/Recipient address rejected: Too many recent unknown recipients from //i
				or $message =~ s/Temporarily rejected//i
				or $message =~ s/unverified address: Address verification in progress//i
				or $message =~ s/(try again|please retry|retry later|try later)// ) ) {	# TODO - many other possible reasons to add
				# we got greylisted
				++$$stats{'postfix:smtp:deferred:greylist'};
			} elsif ( $line =~ s/^host [\w\.\-]+\[[\w\.:]+\] refused to talk to me: 550 rejected because of not in approved list//i ) {
				# presumably a misconfigured server - other side is broken
				++$$stats{'postfix:smtp:deferred:brokenserver'};
			} elsif ( $line =~ s/^Host or domain not found//i
				or $line =~ s/^Host or domain name not found//i
				or $line =~ s/^Domain not found//i ) {
				# dns is broken
				++$$stats{'postfix:smtp:deferred:dnserror'};
			} elsif ( $line =~ s/^.*timeout.*$//i ) {
				# connection timed out
				++$$stats{'postfix:smtp:deferred:timeout'};
			} elsif ( $line =~ s/^.*Network is unreachable.*$//i ) {
				# ignore - alredy should be caught before
				--$$stats{'postfix:smtp:connect'};	# don't want to increment twice
				smtpd_ip ( $line, $origline, $number, $log, $stats );
			} else {
				# some other
				++$$stats{'postfix:smtp:deferred:other'};
				# don't squark directly about this - add to the lists of new stuff
				push @deferreasons, __LINE__.":$origline\n";
				push @deferreasons, __LINE__.":\$message: $message\n";
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
		} elsif ( $line =~ s/^[0-9A-F]+: enabling PIX .*// ) {
			# ignore
		} elsif ( $line =~ s/^[0-9A-F]+: sender non-delivery notification// ) {
		} else {
			# some other
			++$$stats{'postfix:smtp:other'};
			print STDERR __FILE__." $VERSION:".__LINE__." $log:$number unknown: $origline\n";
		}
########################## local delivery ##########################
	} elsif ( $line =~ s/^.+ postfix\/(local|virtual|pipe)\[\d+\]:\s*// ) {
		if ( $line =~ s/^[0-9A-F]+: to=.* status=sent\s*// ) {
			# delivered locally
			++$$stats{'postfix:local:sent'};
			if ( $line =~ s/^\(delivered to maildir\)// ) {
				# delivered to maildir
				++$$stats{'postfix:local:sent:maildir'};
			} elsif ( $line =~ s/^\(delivered to file:\s*[^\)]*\)// ) {
				# delivered to file
				++$$stats{'postfix:local:sent:file'};
			} elsif ( $line =~ s/^\(delivered to command:\s*[^\)]*\)// ) {
				# delivered to command
				++$$stats{'postfix:local:sent:command'};
			} elsif ( $line =~ s/^\(forwarded as [0-9A-F]+\)// ) {
				# forwarded on
				++$$stats{'postfix:local:sent:forwarded'};
			} elsif ( $line =~ s/^\(delivered via dovecot service\)// ) {
				# delivery to dovecot
				++$$stats{'postfix:local:sent:dovecot'};
			} else {
				# some other
				++$$stats{'postfix:local:sent:other'};
				print STDERR __FILE__." $VERSION:".__LINE__." $log:$number unknown: $origline\n";
			}
		} elsif ( $line =~ s/^[0-9A-F]+: to=.* status=deferred\s*// ) {
			# something went wrong
			++$$stats{'postfix:local:deferred'};
		} elsif ( $line =~ s/^[0-9A-F]+: to=.* status=bounced\s*// ) {
			# something went very wrong
			++$$stats{'postfix:local:bounced'};
		} else {
			# some other
			++$$stats{'postfix:local:other'};
			print STDERR __FILE__." $VERSION:".__LINE__." $log:$number unknown: $origline\n";
		}
	} elsif ( $line =~ s/^.+ postfix\/postdrop\[\d+\]:\s*// ) {
		# possible things to monitor: TODO
		# /^warning: uid=\d+: File too large$/
	} elsif ( $line =~ s/^.+ postfix\/sendmail\[\d+\]:\s*// ) {
		# possible things to monitor: TODO
		# /^fatal: .+\(\d+\): message file too big/
	} elsif ( $line =~ s/^.+ postfix\/bounce\[\d+\]:\s*// ) {
		# ignore.... for now anyway
	} elsif ( $line =~ s/^.+ postfix\/anvil\[\d+\]:\s*// ) {
		# ignore
	} elsif ( $line =~ s/^.+ postfix\/qmgr\[\d+\]:\s*// ) {
		# ignore
	} elsif ( $line =~ s/^.+ postfix\/cleanup\[\d+\]:\s*// ) {
		# ignore
	} elsif ( $line =~ s/^.+ postfix\/error\[\d+\]:\s*// ) {
		# ignore
	} elsif ( $line =~ s/^.+ postfix\/master\[\d+\]:\s*// ) {
		if ( $line =~ s/^terminating on signal 15$// ) {
			# ignore stops
		} elsif ( $line =~ s/^daemon started -- version [0-9\.]+, configuration \/etc\/postfix$// ) {
			# ignore starts
		}
	} elsif ( $line =~ s/^.+ postfix\/policy-spf\[\d+\]:\s*// ) {
		if ( $line =~ s/: SPF None \(No applicable sender policy available\): \s*//i ) {
			++$$stats{'postfix:policy:policy-spf:none'};
		} elsif ( $line =~ s/: Policy action=PREPEND X-Comment: SPF skipped for whitelisted relay// ) {
			++$$stats{'postfix:policy:policy-spf:whitelisted'};
		} elsif ( $line =~ s/: SPF Pass //i ) {
			++$$stats{'postfix:policy:policy-spf:pass'};
		} elsif ( $line =~ s/: SPF Neutral //i
			or $line =~ s/: SPF NeutralByDefault //i
			or $line =~ s/: SPF neutral-by-default //i ) {
			++$$stats{'postfix:policy:policy-spf:neutral'};
		} elsif ( $line =~ s/: SPF SoftFail //i ) {
			++$$stats{'postfix:policy:policy-spf:softfail'};
		} elsif ( $line =~ s/: SPF Fail //i ) {
			++$$stats{'postfix:policy:policy-spf:fail'};
		} elsif ( $line =~ s/: SPF TempError //i ) {
			++$$stats{'postfix:policy:policy-spf:temperror'};
		} elsif ( $line =~ s/: SPF PermError //i ) {
			++$$stats{'postfix:policy:policy-spf:permerror'};
		} elsif ( $line =~ s/: Policy action=PREPEND X-Comment: SPF skipped for whitelisted relay//
			or $line =~ s/: Policy action=PREPEND Received-SPF: none //
			or $line =~ s/: Policy action=PREPEND Received-SPF: neutral //
			or $line =~ s/: Policy action=PREPEND Received-SPF: pass //
			or $line =~ s/: Policy action=PREPEND Received-SPF: softfail //
			or $line =~ s/: Policy action=PREPEND Received-SPF: permerror //
			or $line =~ s/: Policy action=DEFER_IF_PERMIT //
			or $line =~ s/: Policy action=DUNNO//
			or $line =~ s/: Policy action=550 Please see http:\/\/www\.openspf\.org\/Why?//
			or $line =~ s/handler sender_policy_framework: is decisive\.//
			or $line =~ s/handler exempt_relay: is decisive\.// ) {
			# ignore
		} else {
			++$$stats{'postfix:policy:policy-spf:other'};
			print STDERR __FILE__." $VERSION:".__LINE__." $log:$number unknown: $origline\n";
		}
	} else {
		print STDERR __FILE__." $VERSION:".__LINE__." $log:$number unknown: $origline\n";
	}
}





# since there are so many places that log smtp connects, best to break this off
sub smtpd_ip {
	my ( $line, $origline, $number, $log, $stats, $dec ) = @_;
	my $direction = 1;
	if ( defined $dec and $dec ) { $direction = -1; }
	# get ipv4/ipv6 stats
	if ( $origline =~ /\[[\d\.]+\]:25/
		or $origline =~ /\[[\d\.]+\] said:/ ) {
		$$stats{'postfix:smtp:connect:ipv4'} += $direction;
	} elsif ( $origline =~ /\[[\da-f:]+\]:25/
		or $origline =~ /\[[\da-f:]+\] said:/ ) {
		$$stats{'postfix:smtp:connect:ipv6'} += $direction;
	} elsif ( $origline =~ /Host or domain name not found/
		or $origline =~ /warning: network_biopair_interop: error writing/
		or $origline =~ /Host found but no data record of requested type/
		or $origline =~ /warning: no MX host for [^\s]+ has a valid address record/
		or $origline =~ /mail for [^\s]+ loops back to myself/ ) {
		# ignore - there is no address
	} else {
		print STDERR __FILE__." $VERSION:".__LINE__." $log:$number unknown: $origline\n";
	}
}



\&register;
