# Intel Limiter 

This package provides a threshold mechanism for Zeek's intelligence framework on per item basis.

## Installation

The scripts are available as package for the [Bro/Zeek Package Manager](https://github.com/zeek/package-manager) and can be installed using the following command: `bro-pkg install intel-limiter`

## General Usage

To enable per item thresholds make sure the package is loaded: `bro-pkg load intel-limiter`

Once enabled, intel items might specify a new meta data field `meta.matching_threshold`, which denotes the number of matches that must be seen to trigger a match. By default (e.g. if the intel file does not specify the additional meta data) the threshold is set to one, which can be adapted using the `default_matching_threshold` option. The following example shows an intel file that contains two IPs, which will cause a match after three and five hits.
```
#fields	indicator	indicator_type	meta.source	meta.desc	meta.matching_threshold
10.0.0.23	Intel::ADDR	source_a	This host is bad	3
10.0.0.42	Intel::ADDR	source_b	This host is bad	5
```
Once a match is triggered, the internal match counter will be reset and the next match is triggered after the threshold is reached again. The threshold counters are managed per item. If two items that are obtained from different sources share the *same* indicator, thresholds do not interfere. For example, if thresholds of two and four are specified for a single indicator, every fourth time the indicator is seen a hit containing all meta data will be generated, while every second reporting will cause a match containing only the meta data of the item that defines the threshold of two.

**Note:** As Bro 2.6 does not pass modified hook parameters along the chain, hits will be reported in the correct frequency but contain the meta data of all items.

## Background

The script `item-threshold.bro` implements per item thresholds and is loaded by default. Per item thresholds are realized using two additional meta data fields:
* `matching_threshold` defines the number of reports required to trigger a match
* `recent_matches` implements a counter for recent matches

To prevent matching of an item before the specified threshold is reached, the script handles the `extend_match` hook of the intelligence framework and checks the number of recent hits.
For further details on the intel framework see the corresponding [blog post](https://blog.zeek.org/2016/12/the-intelligence-framework-update.html).
