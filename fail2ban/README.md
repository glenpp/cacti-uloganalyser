# fail2ban on Cacti via SNMP

fail2ban is a popular intrusion (and abuse) protection tool that is normally used to update firewall rules based on failed authentication attempts logged.

For example if there are repeated failed attempts on your ssh port then that IP will be banned for several minutes, even hours. That means that brute force attacks from one source are practically impossible. More often than not attacks are on SMTP servers (spammers looking for a relay) or web forms / forums and it can be used equally well there.

## fail2ban to SNMP

First up ensure you get to grips with those first then you will need the [universal log analyser](../). Place that where you keep the plugins and add to **/etc/snmp/local-snmp/** cronjob discussed [elsewhere](../):

```sh
# run fail2ban stats
/etc/snmp/uloganalyser \
    /var/log/fail2ban.log.1 \
    /var/log/fail2ban.log \
    /var/local/snmp/fail2ban \
    fail2ban
```

That tells uloganalyser to process fail2ban logs with the fail2ban plugin, putting the results in **/var/local/snmp/fail2ban**. From there a snmpd extension script (fail2ban-stats) picks up the data.

Place that in a suitable place (eg. /etc/snmp/) and add the config from snmpd.conf-fail2ban to your **/etc/snmp/snmpd.conf**, restarting snmpd after.

## SNMP to Cacti

At this point your Cacti host definition needs to be working for SNMP and you should be able to simply import the template and add the graph.

## Extending

This is only a very small template as I only expose very limited services to the outside world, but it's easy to add more categories:

- In fail2ban.pm add classifications mapping the definitions in jail.conf and jail.local to a classification. These look for things like "... fail2ban.actions: WARNING [postfix] Ban \*\*\*.\*\*\*.\*\*\*.\*\*\* ..." in fail2ban logs to determine what classes of service are being banned.
- If you add a new classification then:
	- add it to the fail2ban-stats script so it's also available to snmpd
	- create a new data template in Cacti for that classification
	- add that to the graph template

