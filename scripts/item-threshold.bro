##! This script adds per item expiration for the intelligence framework.

@load base/frameworks/intel

module Intel;

export {
	## Default matching threshold for for single intelligence items that is
	## used in case the loaded intel file does not specify expire metadata.
	option default_matching_threshold: count = 1;

	redef record MetaData += {
		## Matching threshold for the intelligence item. The intelligence
		## framework reports only a hit for an item after this number of
		## occurences have been observed. In case of multiple meta data
		## instances, each instance will be treated separately.
		matching_threshold: count &default=default_matching_threshold;

		## Internal value: Keeps track of the number of matches in context of
		## that single item.
		recent_matches: count &default=0;
	};
}

hook extend_match(info: Info, s: Seen, items: set[Item]) &priority=10
	{
	local matched_items: set[Item];

	for ( item in items )
		{
		item$meta$recent_matches += 1;
		if ( item$meta$matching_threshold <= item$meta$recent_matches )
			{
			add matched_items[item];
			item$meta$recent_matches = 0;
			}
		# Update recent matches counter
		insert(item);
		}

	if ( |matched_items| < 1 )
		# Prevent logging if there was no match at all
		break;
	else
		items = matched_items;
	}
