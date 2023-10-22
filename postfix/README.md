# Postfix stats on Cacti (via SNMP)

This makes use of [Universal Log Analyser](../) for processing logs.

## Postfix Stats

Postfix produces a minimum of statistics it's self, but as is common in Unix, it does produce comprehensive logs of activity which provides plenty of material for generating statistics from.

There are already a load of logfile analysers around, but for the purposes of this monitoring, I decided the best thing was to write my own and then it would be easy to make it work exactly how I wanted for producing stats.

We rely on my [Universal Log Analyser](../) to use the plugins provided here. Please refer to that article and get that working first and then continue configuration for this article.

There are 4 plugins in this case: postfix.pm, opendkim.pm, clamav.pm and spamd.pm

These are in the tarball (see later). Place the plugins in the plugin directory (default is **/etc/snmp/uloganalyser-plugin/**)

One feature I have built into the plugin is that it outputs any lines that it does not completely understand. Cron will email this back to the administrator. This means that over time the script can be enhanced to extract more information from the logs. If you want to ignore this then just send all the output to /dev/null in the cron job.

## Update on DKIM

This work goes back many years and this DKIM plugin here is really outdated and no longer being maintained. Since then things have moved to Open DKIM which is where the effort has been going.

## Getting Postfix stats over SNMP

Like discussed elsewhere, Postfix logfiles require root privilege to access, and snmpd runs as a low privilege user. What I do is have a CRON job that reads this data and stores it in files for snmpd to access via extension scripts.

To collect logs (adjust as needed) and store counters in **/var/local/snmp/mail** run collection via CRON every 5 minutes (or to match your Cacti polling time) with something like:

```sh
#!/bin/sh

# run postfix stats
/etc/snmp/uloganalyser \
    /var/log/mail.log.1 \
    /var/log/mail.log \
    /var/local/snmp/mail \
    postfix opendkim clamav spamd
```

This is fully compatible with my [dovecot stats plugin](../dovecot/) and you can just add "dovecot" on the end to add those stats into the same file and analyse the logs in one shot. Likewise, plugins you don't use may be left off.

From there, I have a load of small scripts for each aspect of the stats I monitor. One thing to consider when writing these scripts is to ensure that if more parameters are added to them, they are all added to the ends of the scripts to ensure that the order of the data given to snmpd does not change.

These scripts are in the tarball (see later) and are all named postfix-stats-\*, clamav-stats or dkim-stats. I place these scripts (make them executable first: chmod +x postfix-stats-*) in /etc/snmp/

In **/etc/snmp/snmpd.conf** add the lines from snmpd.conf-clamav, snmpd.conf-opendkim, snmpd.conf-postfix and snmpd.conf-spamd, as appropriate.

Once you have added all this in you can test these scripts by running them from the command line, and via SNMP by appending the appropriate SNMP OID to the "snmpwalk" commands shown previously.

## Cacti Templates

I have generated some basic Cacti Templates for these Postfix and other stats: cacti_graph_template_clamav.xml, cacti_graph_template_opendkim.xml, cacti_host_template_postfix.xml and cacti_host_template_spamd_monitoring.xml

Simply import this template, and add the graphs you want to the appropriate device graphs in Cacti. It should just work if your SNMP is working correctly for that device (ensure other SNMP parameters are working for that device).

