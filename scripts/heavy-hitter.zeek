##! This script adds heavy hitter suppression for the intelligence framework.

@load base/frameworks/intel

module Intel;

export {
	## Heavy hitter interval specifying the time frame to count hits for.
	## If more than :zeek:id:`heavy_hitter_threshold` hits are reported
	## during that time frame, the indicator will be removed.
	option heavy_hitter_interval: interval = 1min;

	## Heavy hitter threshold specifying the number of allowed hits per
	## :zeek:id:`heavy_hitter_interval`. A value of 0 disables heavy hitter
	## suppression.
	option heavy_hitter_threshold: count = 0;
}

global intel_hits: table[string, Type] of count &default=0 &write_expire=heavy_hitter_interval;

event Intel::match(s: Seen, items: set[Item])
	{
	for ( item in items )
		{
		intel_hits[item$indicator, item$indicator_type] += 1;

		if ( heavy_hitter_threshold > 0 &&
			 intel_hits[item$indicator, item$indicator_type] > heavy_hitter_threshold )
			{
			remove(item);
			# In a cluster, hits will be generated but not logged until
			# the worker receives the remove from the manager.
			Reporter::warning(fmt("Intel framework removed heavy hitter: %s.", item));
			}
		}
	}
