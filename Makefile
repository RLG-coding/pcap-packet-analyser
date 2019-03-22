analyzer: delete analyzer.c
	gcc analyzer.c -o analyzer -lpcap

delete:
	rm -rf analyzer