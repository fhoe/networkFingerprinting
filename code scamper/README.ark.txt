=============================================================================
                            Archipelago Data Archive
=============================================================================


This is the top-level directory for downloading data collected by the
Archipelago (Ark) measurement infrastructure.  Ark data is organized at the
highest level into broad measurement 'activities', one directory per
activity.  Each activity directory is organized in whatever way is most
suited to the activity; that is, there is no standard directory structure
across activities.

The following is an overview of the available datasets, grouped by activity.

============================================================================
Team-Probing Activity
============================================================================

  ---------------------------------------------------------------------
  NOTE ON ANALYSIS TOOLS
  ---------------------------------------------------------------------

  You can analyze team-probing data (available in the 'warts' format)
  with the sc_analysis_dump tool included in the 'scamper' distribution,
  which you can download from

     http://www.wand.net.nz/scamper/

  The sc_analysis_dump tool prints out information about each trace
  in an easy-to-parse textual format (one trace per line).  You would
  typically write a perl script to analyze the output of sc_analysis_dump.
  
  Another tool you may want to consider is the warts-dump tool, which
  is also included in the scamper distribution.  The output of warts-dump
  is somewhat less easy to parse, but warts-dump prints out practically
  all information contained in a warts file.

  Finally, you can write your analysis scripts in the Ruby language
  using rb-wartslib, an easy-to-use Ruby binding to the warts I/O
  library.  You can learn more about it at

     http://rb-wartslib.rubyforge.org/

  Ruby is a great scripting language and well worth learning for its
  own sake.  See http://www.ruby-lang.org
  ---------------------------------------------------------------------

Team-probing activity data is in the subdirectory "team-probing".

In team probing, a set of Ark nodes work together as a team to do
large-scale Internet topology measurements, using the scamper measurement
tool to perform traceroutes.

Team probing data is organized into lists and teams.  A list defines a
logical set of destinations.  However, unlike with skitter, a list does not
necessarily mean a fixed set of destinations over time.  A list may be
merely a conceptual grouping of destinations according to some purpose,
goal, or technique.  For example, list 7 is called allpref24, and the data
consists of traces to randomly selected destinations in every routed /24.
Thus, the set of destinations covered by list 7 changes every cycle, but
the list itself retains its conceptual identity.

More than one team can probe the same list, and an Ark monitor can change
teams over time.


...........................................................................
Files Overview
...........................................................................

For greater convenience, we provide the *same* team-probing data in two
different forms, as hourly files and as daily files.  The set of files you
use will depend on your needs, but you only need to download one set of
files.  If you simply want historical data, then only download daily files.
If you need the latest traces in a timely manner (because you're performing
time-sensitive analysis or follow-up measurements), then download the
hourly files.

For list 7 and team 1, the hourly and daily files are in the following
directories:

   team-probing/list-7.allpref24/team-1/hourly
   team-probing/list-7.allpref24/team-1/daily

The list directory has the general form "list-<list#>.<listname>".

...........................................................................
Hourly Files
...........................................................................

You should download hourly files to get the latest traces in a timely
manner.  Normally, hourly files are pushed out to the public download
directory when all the traces for a given hour have been processed by Ark.
However, Ark tries to avoid holding onto data for too long in internal
buffers.  In particular, if the processing of an hourly file takes too long
for some reason (such as if Ark is temporarily unable to download traces
from a remote Ark monitor), then Ark will push out the hourly file to the
download area without waiting for all the traces in that hour to be
processed.  This ensures that hourly data is made available within 1-2
hours of its collection by Ark itself most of the time.

The hourly directory contains a sliding window of the last 10 days of hourly
files (actually, an hourly file is not deleted until it is *made available
for download* for at least 10 days, so an hourly file may still be retained
even if it is older than 10 days according to the calendar).

The following is an example of an hourly file:

   00021515.hourly.l7.t1.20071016-22.nrt-jp.warts.gz

The general naming scheme is

   <seqnum>.hourly.l<list#>.t<team#>.<date>-<hour>.<monitor>.warts.gz

where

   <seqnum> is a strictly increasing sequence number,
   <list#> is the list number,
   <team#> is the team number,
   <date> is the date of the first trace in the file (UTC),
   <hour> is the hour of the first trace in the file (UTC), and
   <monitor> is the monitor name in the form <airport-code>-<country-code>.

The sequence number is an important field.  You should check for the
presence of new files by periodically (say, every hour or half hour)
listing the hourly directory and looking for files that have a sequence
number greater than the highest sequence number you've downloaded before.

The sequence number also allows Ark to create multiple files for the same
hour and monitor.  For example, there could be the following set of files:

   00021515.hourly.l7.t1.20071016-22.nrt-jp.warts.gz
   00021516.hourly.l7.t1.20071016-22.nrt-jp.warts.gz
   00021517.hourly.l7.t1.20071016-22.nrt-jp.warts.gz

This will happen if Ark pushes out partial hourly files as a way of
ensuring that data is made available in a timely manner.

NOTE: The traces in hourly files (and also daily files) are NOT sorted by
      timestamp.  They are only approximately sorted.  Also, although the
      timestamp of the first trace in a file will fall within the date and
      hour recorded in the filename, it is possible (and in fact likely)
      for the file to also contain a small number of traces from the last
      few minutes of the previous hour.  This is a logical consequence of
      the fact that the traces are not strictly sorted by timestamp.

...........................................................................
Daily Files
...........................................................................

You should download daily files to get historical data, since every
collected daily file is archived and made permanently available.

Daily files are organized in the following directory structure

   team-probing/list-7.allpref24/team-1/daily/<YYYY>/cycle-<YYYYMMDD>

(in the case of the daily files for list 7 and team 1), where

   <YYYY> is the year of the traces (UTC), and
   <YYYYMMDD> is the start date of a given cycle (UTC).

A cycle is a single pass through a given destination list.  For example, in
the case of list 7, a cycle is a single pass through every routed /24.
Data is organized first by cycle rather than first by monitor, because each
monitor only probes a subset of the destinations in a complete cycle, since
the work of probing the full destination list is divided up among the
monitors.  A monitor-oriented directory organization would make it harder
to obtain complete cycles of data.

Within the cycle directory, there is a daily file per monitor per day;
for example:

   daily.l7.t1.c000042.20071029.syd-au.warts.gz

The general naming scheme is

   daily.l<list#>.t<team#>.c<cycle#>.<date>.<monitor>.warts.gz

where

   <list#> is the list number,
   <team#> is the team number,
   <cycle#> is the cycle number,
   <date> is the date of the first trace in the file (UTC), and
   <monitor> is the monitor name in the form <airport-code>-<country-code>.

         -----------------------------------------------------------

Unlike hourly files, there is no guarantee on the timeliness of daily files.
Daily files are meant for archiving, and thus are only created when all the
data making up a given daily file is fully available.  This means that the
creation of individual daily files can be subject to arbitrarily long delays
as a result of failures in the system.  This also means that a cycle
directory may be missing some daily files even though a subsequent cycle
directory exists.

For example, suppose there are three monitors X, Y, and Z, and suppose there
are the following cycle directories:

   .../daily/2007/cycle-20070928
          daily.X
          daily.Y
          daily.Z
   .../daily/2007/cycle-20071001
          daily.X
          daily.Y

Now, suppose the creation of the daily file for monitor Z is delayed for
cycle-20071001.  This delay will not prevent the remaining monitors from
advancing to the next cycle (cycle-20071004), unless there is a serious
systemwide failure.  Hence, it's possible for the download directory to look
like the following at some point in time:

   .../daily/2007/cycle-20070928
          daily.X
          daily.Y
          daily.Z
   .../daily/2007/cycle-20071001
          daily.X
          daily.Y
   .../daily/2007/cycle-20071004
          daily.X
          daily.Y

The important point to observe is that the creation of a subsequent cycle
directory (cycle-20071004) does NOT necessarily mean that the previous cycle
directory (cycle-20071001) is complete.

On a related note, a complete cycle directory will not necessarily have a
daily file from every monitor (in the team).  Therefore, you can't simply
look at whether a cycle directory contains a daily file from all monitors
(of the team) to determine whether the cycle is complete or incomplete.  In
the above example, suppose monitor Z goes down from 20071002 to 20071008,
then the remaining monitors (X & Y) will completely probe all destinations
by themselves in cycle-20071004, so cycle-20071004 will *never* have daily
files from monitor Z, even after monitor Z is brought back up.

There is currently no indication of cycle completeness _within_ the directory
of a cycle.  However, whenever a cycle becomes complete, an entry is written
to cycle-completion.log, which you may find, for example, in the subdirectory
team-probing/list-7.allpref24/team-1/daily.  This log lists the last 30
completed cycles.  You can assume that any cycles older than the cycles
listed in this log file are complete.

         -----------------------------------------------------------

If you would like to download daily files as they are produced (that is,
keep up with the creation of the daily files just as you can keep up with
the creation of the hourly files), then you'll want to examine the
daily-file creation log at

  team-probing/list-7.allpref24/team-1/daily/daily-creation.log

(in the case of the daily files for list 7 and team 1--there is a separate
log file for each combination of list and team).

Think of this like an RSS feed for daily file creation--check it once or
twice a day and download any new listed files (daily files are typically
created between 1-2am UTC, so check a few hours after that).

The log file is atomically updated (that is, you will never see an
inconsistent or partial file), and it lists the last 300 daily files created
(which is approximately 1 month of daily files for a team of 8 monitors).

         -----------------------------------------------------------

NOTE: The traces in daily files (and also hourly files) are NOT sorted by
      timestamp.  They are only approximately sorted.  Also, although the
      timestamp of the first trace in a file will fall within the date
      recorded in the filename, it is possible (and in fact likely) for the
      file to also contain a small number of traces from the last few
      minutes of the previous day.  This is a logical consequence of the
      fact that the traces are not strictly sorted by timestamp.


...........................................................................
Related Datasets
...........................................................................

There are two related datasets that may be of interest for topology analysis.

 * team-probing/list-7.allpref24/dns-names:

   This dataset provides fully-qualified DNS domain names for IP addresses
   seen in the IPv4 Routed /24 Topology dataset.

 * team-probing/list-7.allpref24/cycle-aslinks:

   This dataset provides AS links derived from the IPv4 Routed /24 Topology
   dataset.

Please see the README.txt file in the dataset directories.


# $Id: README.ark.txt,v 1.8 2008/06/20 00:45:51 youngh Exp $
