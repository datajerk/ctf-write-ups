### FlagConverter Part 1

_On the campground of the CCCamp, someone is trying to troll us by encrypting our flags. Sadly, we only got the memory dump of the PC which encrypted our flags._

_Please provide us with the flag which is not yet encrypted._

[flagconverter.7z](https://static.allesctf.net/flagconverter-725b6d252230016c8126c5d972760e08b824f8a86071e87aa52e6f069a2e18f3.7z)

**Tags:** _forensics_

#### Solution

`ALLES{` was the prefix for the _Sanity Check_ challenge.  It pays to do the simple opening challenges to get the flag format.

```
$ 7z x flagconverter-725b6d252230016c8126c5d972760e08b824f8a86071e87aa52e6f069a2e18f3.7z

$ strings flagconverter.dmp | grep ALLES{

ALLES{f0r3n51k_15_50m3t1m35_t00_345y}
```
