Network packet analyser. Made using the PCAP library in C.

.compile.
  $ make

.execute.
  $ ./analyzer <options>

.options.
  -i <interface> : interface to use for the live analysis
  -o <file_name> : file to use for the offline analysis
  -f <filter> : capture filter
  -v <1..3> : verbosity level (1: low, 2: normal, 3: high)
If no interface is selected, one is automatically assigned.
If no verbosity level is selected, the level is set to 1 by default.
