# Cryptolog

Cryptolog is a tool for anonymizing webserver logs. It reads log file entries from the standard input and writes to the standard output or a logfile.

The filter replaces IP addresses in each entry with a hashed version of the IP. It makes logs that look like this:
```
67.169.69.72 - - [12/May/2011:17:58:07 -0700] "GET / HTTP/1.1" 200 430
```
Look like this instead:
```
UkezVh - - [12/May/2011:17:58:07 -0700] "GET / HTTP/1.1" 200 430
```

Cryptolog runs the MD5 hash on an IP address using a random key. By default, the key is rotated every 24 hours. This means that within any 24-hour window, requests from the same IP will display with same hash. The key is discarded at the end of each 24-hour period.

## Arguments

`--outfile`: Path to which Cryptolog should write filtered output. Defaults to standard out.

`--salt-lifetime`: Interval after which to rotate the hash salt. Defaults to 24 hours.

`--replace-all-matches`: If true (default), Cryptolog will filter all instances of IP addresses in each log entry. If false, Cryptolog will only filter the first match in each entry.

## Configuring Apache

Edit the Apache CustomLog line to pipe output to Cryptolog, ex:
```
CustomLog "| /usr/bin/cryptolog" combined`
```

## Configuring Nginx

Nginx doesn't allow piping output in the config. Instead, configure Cryptolog to read from a named pipe.
```
$ mfifo /var/log/nginx/.access.pipe
$ cryptolog </var/log/nginx/.access.pipe &
```

In your nginx config, set the access log to write to that pipe:
```
access_log /var/log/nginx/.access.pipe main
```

Note that Cryptolog must begin reading from the pipe before nginx starts.
