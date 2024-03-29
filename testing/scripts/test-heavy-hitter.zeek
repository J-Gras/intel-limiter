# @TEST-EXEC: zeek -r $TRACES/ticks.pcap heavy-hitter %INPUT
# @TEST-EXEC: cat intel.log > output
# @TEST-EXEC: cat .stdout >> output
# @TEST-EXEC: btest-diff output

redef enum Intel::Where += { SOMEWHERE };
redef Intel::heavy_hitter_interval = 4sec;
redef Intel::heavy_hitter_threshold = 2;
redef table_expire_interval = 2sec;

event zeek_init()
	{
	Intel::insert([$indicator="1.0.0.0", $indicator_type=Intel::ADDR, $meta=[$source="source1"]]);
	Intel::insert([$indicator="2.0.0.0", $indicator_type=Intel::ADDR, $meta=[$source="source1"]]);
	}

global runs = 0;

event connection_established(c: connection)
	{
	# FIXME: Recent matches counter won't be incresed if the same
	#        indicator is seen multiple times in a run.
	print fmt(">> Run %s:", runs);
	switch (runs)
		{
		case 1:
			print "Trigger: 1.0.0.0";
			Intel::seen([$host=1.0.0.0, $where=SOMEWHERE]);
			print "Trigger: 2.0.0.0";
			Intel::seen([$host=2.0.0.0, $where=SOMEWHERE]);
			break;
		case 2:
			print "Trigger: 1.0.0.0";
			Intel::seen([$host=1.0.0.0, $where=SOMEWHERE]);
			print "Trigger: 2.0.0.0";
			Intel::seen([$host=2.0.0.0, $where=SOMEWHERE]);
			break;
		case 3:
			print "Trigger: 1.0.0.0";
			Intel::seen([$host=1.0.0.0, $where=SOMEWHERE]);
			break;
		case 4:
			print "Trigger: 1.0.0.0";
			Intel::seen([$host=1.0.0.0, $where=SOMEWHERE]);
			# Hit should not be reported anymore
			break;
		case 6:
			print "Trigger: 2.0.0.0";
			Intel::seen([$host=2.0.0.0, $where=SOMEWHERE]);
			# Hit should be reported
			break;
		}

	++runs;
	}

event Intel::log_intel(rec: Intel::Info)
	{
	print fmt("Hit on %s has been logged!", rec$seen$indicator);
	}
