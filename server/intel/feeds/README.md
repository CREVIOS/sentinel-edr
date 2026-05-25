# Threat-intel IOC feeds

Drop indicator files here (`*.txt`, `*.csv`, `*.ioc`). One indicator per line:

    <value>                              # type auto-detected, severity=high
    <value>,<type>,<severity>,<source>   # explicit (type: hash|ip|domain)

`#` lines are comments. Filename (sans ext) is the default source. The server loads this
directory at startup (SENTINEL_IOC_DIR, default `intel/feeds`). Populate from OTX / abuse.ch /
MISP exports or https://github.com/Bert-JanP/Open-Source-Threat-Intel-Feeds via a cron sync.
