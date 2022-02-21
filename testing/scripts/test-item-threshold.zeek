# @TEST-EXEC: zeek -r $TRACES/ticks.pcap item-threshold %INPUT
# @TEST-EXEC: cat intel.log > output
# @TEST-EXEC: cat .stdout >> output
# @TEST-EXEC: btest-diff output

# @TEST-START-FILE intel_plain.dat
#fields	indicator	indicator_type	meta.source	meta.desc
2.0.0.0	Intel::ADDR	source1	this host is bad
# @TEST-END-FILE

# @TEST-START-FILE intel_threshold.dat
#fields	indicator	indicator_type	meta.source	meta.desc	meta.matching_threshold
3.0.0.0	Intel::ADDR	source1	this host is bad	4
# @TEST-END-FILE

redef Intel::read_files += { "intel_plain.dat", "intel_threshold.dat" };
redef enum Intel::Where += { SOMEWHERE };
redef Intel::default_matching_threshold = 3;

# Wait for intel data to be loaded
global intel_data = 0;

event zeek_init()
	{
	suspend_processing();
	}

hook Intel::filter_item(item: Intel::Item)
	{
	++intel_data;
	if ( intel_data == 2 )
		continue_processing();
	}

# Test scenario

global runs = 0;

event connection_established(c: connection)
	{
	print fmt(">> Run %s:", runs);
	switch (runs)
		{
		case 1:
			print "Trigger: 2.0.0.0";
			Intel::seen([$host=2.0.0.0, $where=SOMEWHERE]);
			print "Trigger: 3.0.0.0";
			Intel::seen([$host=3.0.0.0, $where=SOMEWHERE]);
			break;
		case 2:
			print "Trigger: 2.0.0.0";
			Intel::seen([$host=2.0.0.0, $where=SOMEWHERE]);
			break;
		case 3:
			print "Trigger: 2.0.0.0";
			Intel::seen([$host=2.0.0.0, $where=SOMEWHERE]);
			print "Trigger: 3.0.0.0";
			Intel::seen([$host=3.0.0.0, $where=SOMEWHERE]);
			# Hit reported for 2.0.0.0
			break;
		case 5:
			print "Trigger: 2.0.0.0";
			Intel::seen([$host=2.0.0.0, $where=SOMEWHERE]);
			print "Trigger: 3.0.0.0";
			Intel::seen([$host=3.0.0.0, $where=SOMEWHERE]);
			break;
		case 6:
			print "Trigger: 2.0.0.0";
			Intel::seen([$host=2.0.0.0, $where=SOMEWHERE]);
			print "Trigger: 3.0.0.0";
			Intel::seen([$host=3.0.0.0, $where=SOMEWHERE]);
			# Hit reported for 3.0.0.0
			break;
		case 7:
			print "Trigger: 2.0.0.0";
			Intel::seen([$host=2.0.0.0, $where=SOMEWHERE]);
			# Hit reported for 2.0.0.0
			break;
		}

	++runs;
	}

event Intel::log_intel(rec: Intel::Info)
	{
	print fmt("Hit on %s has been logged!", rec$seen$indicator);
	}
