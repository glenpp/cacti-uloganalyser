
# Dovecot stats on Cacti (via SNMP)

If you're unfamiliar with my work on the above then please read the articles [above](../) before starting. This article assumes you have the basics in place that are described above.

## Dovecot Plugin

Throw dovecot.pm in your plugin directory for the Universal Log Analyser, and add "dovecot" as a module to the command line so that this module gets loaded.

Not much more to it than that. The remainder of the article assumes your stats file is /var/local/snmp/mail so if it isn't you will need to tweak things to match your install.

It's worth checking the stats file to verify that dovecot stats are in fact being picked up by the plugin.

## SNMP Scripts

First, ensure that your SNMP is configured and working as described in my 

## SNMP basics article.

These provide the link for snmpd to pick up the stats and assuming they are in /etc/snmp the config from snmpd.conf-dovecot in /etc/snmp/snmpd.conf

Extension scripts for snmpd are named dovecot-stats-* - put them in a suitable place.... like /etc/snmp

You should be able to run these scripts manually and they should spit back the current info from the stats file. Remember to restart snmpd so that the new config is picked up and we should be ready to go.

## Cacti Template

Import cacti_host_template_dovecot.xml into your Cacti and add graphs as usual.

After that, assuming everything is working then after a couple data samples content should start to appear on the graphs.

If not then check the data at each step: the stats file, SNMP scripts, snmpwalk from the Cacti server, check Cacti Poller log for errors, and try Cacti in debug mode for graphs and data sources to see if that shows anything.

I will post example graphs once my ones are mature enough to have some useful data on them.

