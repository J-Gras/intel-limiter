# @TEST-SERIALIZE: comm
#
# @TEST-EXEC: btest-bg-run manager-1 ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=manager-1 zeek %INPUT
# @TEST-EXEC: btest-bg-run worker-1  ZEEKPATH=$ZEEKPATH:.. CLUSTER_NODE=worker-1 zeek -r $TRACES/ticks.pcap --pseudo-realtime %INPUT
# @TEST-EXEC: btest-bg-wait -k 13
# @TEST-EXEC: btest-diff manager-1/intel.log

# @TEST-START-FILE cluster-layout.zeek
redef Cluster::nodes = {
	["manager-1"] = [$node_type=Cluster::MANAGER, $ip=127.0.0.1, $p=37757/tcp],
	["worker-1"]  = [$node_type=Cluster::WORKER,  $ip=127.0.0.1, $p=37760/tcp, $manager="manager-1"],
};
# @TEST-END-FILE

@load heavy-hitter

module Intel;

redef enum Intel::Where += { SOMEWHERE };
redef Intel::heavy_hitter_interval = 4sec;
redef Intel::heavy_hitter_threshold = 2;
redef table_expire_interval = 2sec;
redef Log::default_rotation_interval=0sec;

# Manager

@if ( Cluster::local_node_type() == Cluster::MANAGER )
event Cluster::node_up(name: string, id: string)
	{
	# Insert the data once all workers are connected.
	if ( Cluster::worker_count == 1 )
		{
		Intel::insert([$indicator="1.0.0.0", $indicator_type=Intel::ADDR, $meta=[$source="source1"]]);
		Intel::insert([$indicator="23.23.23.23", $indicator_type=Intel::ADDR, $meta=[$source="end"]]);
		}
	}
@endif

# Worker

@if ( Cluster::local_node_type() == Cluster::WORKER )
event zeek_init()
	{
	suspend_processing();
	}

global worker_data = 0;
event Intel::insert_indicator(item: Intel::Item)
	{
	# Run test on worker-1 when all items have been inserted
	if ( Cluster::node == "worker-1" )
		{
		++worker_data;
		if ( worker_data == 2 )
			continue_processing();
		}
	}

global runs = 0;
event connection_established(c: connection)
	{
	switch (runs)
		{
		case 1:
			Intel::seen([$host=1.0.0.0, $where=SOMEWHERE]);
			break;
		case 2:
			Intel::seen([$host=1.0.0.0, $where=SOMEWHERE]);
			break;
		case 3:
			Intel::seen([$host=1.0.0.0, $where=SOMEWHERE]);
			break;
		case 4:
			Intel::seen([$host=1.0.0.0, $where=SOMEWHERE]);
			# Hit should not be reported anymore
			break;
		case 5:
			Intel::seen([$host=1.0.0.0, $where=SOMEWHERE]);
			# Hit should not be reported anymore
			break;
		case 6:
			# Terminate
			Intel::seen([$host=23.23.23.23, $where=SOMEWHERE]);
			break;
		}

	++runs;
	}
@endif

# Shutdown logic

event die()
	{
	terminate();
	}

event Intel::log_intel(rec: Intel::Info)
	{
	if ( "end" in rec$sources )
		schedule 2sec { die() };
	}

event Cluster::node_down(name: string, id: string)
	{
	# Cascading termination
	schedule 2sec { die() };
	}
