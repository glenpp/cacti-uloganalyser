# Universal Log Analyser and snmpd extension scripts

Cacti Templates, data collection with Universal Loganalyser and plugins via SNMP

This is a master Log Analyser script and a number of plugins (with Cacti Templates) for use with snmpd for shipping data to Cacti.

Test Data, much of which has been sent in by users, may contain identifying information and so is excluded from Git.


## How it works

This uses a quick and dirty Perl plugin setup where the plugins you wish to use are simply tacked onto the end of the command line. This allows multiple instances of the script to be used, looking at different logs, with different plugins, and storing the results in a different place, or in the same if you prefer (but ensure the script is not run concurrently with the same results file - it will get messy!)

Plugins are simply Perl modules which return a reference to a function to register the plugin. The register functions are run to collect up the stuff that actually does the work inside the plugin, but we will go into plugin internals later.

The script will handle loading and saving of results as well as tracking where we where in the log file(s) and continuing on from the same place which makes the plugins rather simple - they just need to recognise events in the line they are given and count them.

Secondly, basic shell scripts can be used in the snmpd config to find the relevant data and return it for transmission via SNMP. These can either be universal and you specify the data fields on the command line (great for just a few), or treat them more as config files and hard-code the data fields into the script which is probably more manageable when many fields are returned in one query.

## Master (this) Script

I currently have this in /etc/snmp with the cron jobs and other stuff that collects data for snmpd, though now that it has outgrown it's original design this location is more for historic reasons than actually being the best place to put it.

Plugins currently go in /etc/snmp/uloganalyser-plugin, again for historic reasons more than anything.

The arguments for running the script are:

```sh
uloganalyser <old logfile> <current logfile> <statsfile> <plugin> [plugin] ...
```

Beyond the stuff that the original postfix-loganalyser script had, this just adds a list of the plugins you want to use. For maximum efficiency, you also want to order the plugins by most frequently used first as this avoids passing the lines to plugins which are least likely to handle them.

The usual stuff applies: make it executable, put it in an appropriate place, put it in a cron job with appropriate privilege to read log files and write the stats file.

Typically you would have this run from a cron job to keep the stats file up to date. Running the config described in my SNMP basics article this script would go in /etc/snmp/local-snmp-cronjob something like:

```sh
/etc/snmp/uloganalyser \
    /var/log/mail.log.0 \
    /var/log/mail.log \
    /var/local/snmp/mail \
    plugin1 plugin2 plugin3 plugin4
```

## Meet the Plugins

I will be publishing the plugins for the mail stuff I have done when they are ready, but for now download a demo plugin which you can use as a basis for your own.

Going through this part by part:

### Register

This is passed a set of references to arrays from the master script which hold references to the functions to do the actual work. Currently there are only two plus the uloganalyser version:

- Line processors array ref - these functions are passed log lines to parse and count up events in
- End processors array ref - these run after the logs have been processed and may collect other information that is not in the logs or report about unhandled content in the logs
- uloganalyser version number - this allows you to check you have a sufficiently recent uloganalyser version

Really all the register function does is add references to any functions in the module that handle either of these to the appropriate array. There is absolutely no reason why you can't have multiple line processors or end processors in one module so long as the register function adds them in.

The register function runs before log processing so you could also use it to run any other stuff needed before log processing starts (eg. you may need to retrieve remote logs, flush log buffers or dump a log from a database).

After running the register function, the master script knows what needs to be executed in the module and that's about it.

### Line processors

These take 4 arguments so will start off like this:

```perl
my ( $line, $number, $log, $stats ) = @_;
```

They are the (chomped) log line, the line number in the log, the log file that is being processed, and a reference to the %stats hash where the statistics are collected.

The first thing the processor needs to do is figure out if the line is one it is responsible for so and if not return null, so something like this is a good idea:

```perl
if ( $line !~ s/^.+ demo[d+]:s*// ) { return; }
```

After that it's just matching events and counting them:

```perl
if ( $line =~ s/^stuff happened:s*// ) {
        ++$$stats{'demo:stuffhappened'};
} elsif ...... and so on
```

It's also worth having the script get noisy about stuff it doesn't understand so that you can go and update/fix it:

```perl
} else {
        ++$$stats{'demo:other'};
        print STDERR __FILE__." $VERSION:".__LINE__." $log:$number unknown: $origlinen";
}
```

And finally, we need to return 1 so that the master knows we have picked up this line and there is no need to process the same line further:

```perl
return 1;
```

That's all there needs to be to a line processor.

### End processor

This is just a function which is called with a reference to the %stats hash to collect up statistics. There is nothing more to it than that. It will probably kick off allong the lines of:

```perl
my $stats = shift;
```

After which it may do stuff like set values depending on stuff it has collected round the system:

$$stats{"demo:some:stuff:collected"} = $datacollected;

It's essentially just there to mop up and as such you can use it for whatever you need - eg. cleaning up temporary files etc.

### Wrapping up

Perl modules have to return a value else it gets annoyed, but this value is also passed back and returned by require in the master script so a really easy way of passing a reference to our register function. Thus we wrap up the plugin with:

```perl
\&register;
```

And that's all there is to it.

When it starts the master script will run the register function and then any further stuff added into the arrays by the register function. Simple as that!

### Connecting the stats to snmpd

For this I am using the extend option in snmpd.conf which allows addition of an external program/script who's output is passed on by snmpd when it gets queried:

```perl
extend  demo /path/to/script
```

First up we can look at a really simple universal script - just dump the parameters on the command line and we're done:

```sh
#!/bin/sh
PATH=/bin:/usr/bin
STATSFILE=/var/local/snmp/datafile
# pick up the requested fields
for param in $@; do
        printf "%dn" `grep ^$param= $STATSFILE | cut -d '=' -f 2`
done
```

Or where many different field are used in one query then we may want to treat this more as a config file - we can specify parameters within the script:

```sh
#!/bin/sh
PATH=/bin:/usr/bin
STATSFILE=/var/local/snmp/datafile
# fields we are looking for
parameters="demo:parameter1 demo:parameter2"
# pick up the requested fields
for param in $parameters; do
        printf "%dn" `grep ^$param= $STATSFILE | cut -d '=' -f 2`
done
```

Or we can do the same thing one-by-one:

```perl
#!/bin/sh
PATH=/bin:/usr/bin
STATSFILE=/var/local/snmp/datafile
# pick up fields
printf "%dn" `grep ^demo:parameter1= $STATSFILE | cut -d '=' -f 2`
printf "%dn" `grep ^demo:parameter2= $STATSFILE | cut -d '=' -f 2`
printf "%dn" `grep ^demo:parameter3= $STATSFILE | cut -d '=' -f 2`
```


## Plugins in this repo

### Postfix, DKIM, ClamaAV, Spamd Templates
[postfix/](postfix/)

### Dovecot Templates
[dovecot/](dovecot/)

### Fail2ban Templates
[fail2ban/](fail2ban/)


