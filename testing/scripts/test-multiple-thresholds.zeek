# @TEST-EXEC: zeek -r $TRACES/ticks.pcap item-threshold %INPUT
# @TEST-EXEC: cat intel.log > output
# @TEST-EXEC: cat .stdout >> output
# @TEST-EXEC: btest-diff output

redef enum Intel::Where += { SOMEWHERE };
redef Intel::default_matching_threshold = 3;

event zeek_init()
	{
	Intel::insert([$indicator="2.0.0.0", $indicator_type=Intel::ADDR, $meta=[
		$source="source1", $matching_threshold=2]]);
	Intel::insert([$indicator="2.0.0.0", $indicator_type=Intel::ADDR, $meta=[
		$source="source2", $matching_threshold=4]]);
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
			print "Trigger: 2.0.0.0";
			Intel::seen([$host=2.0.0.0, $where=SOMEWHERE]);
			break;
		case 2:
			print "Trigger: 2.0.0.0";
			Intel::seen([$host=2.0.0.0, $where=SOMEWHERE]);
			# Hit reported for 2.0.0.0 - 1 meta
			break;
		case 3:
			print "Trigger: 2.0.0.0";
			Intel::seen([$host=2.0.0.0, $where=SOMEWHERE]);
			break;
		case 5:
			print "Trigger: 2.0.0.0";
			Intel::seen([$host=2.0.0.0, $where=SOMEWHERE]);
			# Hit reported for 2.0.0.0 - 2 meta
			break;
		case 6:
			print "Trigger: 2.0.0.0";
			Intel::seen([$host=2.0.0.0, $where=SOMEWHERE]);
			break;
		case 7:
			print "Trigger: 2.0.0.0";
			Intel::seen([$host=2.0.0.0, $where=SOMEWHERE]);
			# Hit reported for 2.0.0.0 - 1 meta
			break;
		}

	++runs;
	}

event Intel::log_intel(rec: Intel::Info)
	{
	print fmt("Hit on %s has been logged!", rec$seen$indicator);
	}
