# Intel Limiter 

This package provides limiting mechanisms for Zeek's intelligence framework. This encompasses matching thresholds on per item basis and a heavy hitter suppression.

## Installation

The scripts are available as package for the [Zeek Package Manager](https://github.com/zeek/package-manager) and can be installed using the following command: `zkg install intel-limiter`

## General Usage

To enable per item thresholds and heavy hitter suppression make sure the package is loaded: `zkg load intel-limiter`

### Matching Thresholds

With the package loaded, intel items might specify a new meta data field `meta.matching_threshold`, which denotes the number of matches that must be seen to trigger a match. By default (e.g. if the intel file does not specify the additional meta data) the threshold is set to one, which can be adapted using the `default_matching_threshold` option. The following example shows an intel file that contains two IPs, which will cause a match after three and five hits.
```
#fields	indicator	indicator_type	meta.source	meta.desc	meta.matching_threshold
10.0.0.23	Intel::ADDR	source_a	This host is bad	3
10.0.0.42	Intel::ADDR	source_b	This host is bad	5
```
Once a match is triggered, the internal match counter will be reset and the next match is triggered after the threshold is reached again. The threshold counters are managed per item. If two items that are obtained from different sources share the *same* indicator, thresholds do not interfere. For example, if thresholds of two and four are specified for a single indicator, every fourth time the indicator is seen a hit containing all meta data will be generated, while every second reporting will cause a match containing only the meta data of the item that defines the threshold of two.

**Note:** Since version 2.6, Zeek does not pass modified hook parameters along the chain. Thus, hits will be reported in the correct frequency but contain the meta data of all items.

### Heavy Hitter Suppression

To enable heavy hitter suppression, a heavy hitter interval and threshold have to be specified. The option `heavy_hitter_interval` defines the time window in which at most `heavy_hitter_threshold` hits might occur. If more hits are observed in that time window, the indicator is removed. By default the threshold is set to zero which disables suppression. When removing an heavy hitter, a reporter warning is generated to inform the user about the removal.

## Background

The script `item-threshold.zeek` implements per item thresholds and is loaded by default. Per item thresholds are realized using two additional meta data fields:
* `matching_threshold` defines the number of reports required to trigger a match
* `recent_matches` implements a counter for recent matches

To prevent matching of an item before the specified threshold is reached, the script handles the `extend_match` hook of the intelligence framework and checks the number of recent hits.
For further details on the intel framework see the corresponding [blog post](https://blog.zeek.org/2016/12/the-intelligence-framework-update.html).

The script `heaver-hitter.zeek` implements heavy hitter suppression simply by tracking hits per indicator in a table. Note that item removal and reporting a warning is a very simple strategy. In more complex environments one would want to report heavy hitters using a dedicated feedback channel, e.g. implemented with broker.

## Acknowledgments

Thanks to @mavam (Tenzir), who brought up the idea for heavy hitter suppression during Zeek Workshop Europe 2019.
