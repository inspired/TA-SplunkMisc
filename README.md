# TA-SplunkMisc
Miscellaneous tips and tricks for Splunk

## Use Case 1 - Create Enterprise Security notables in separate indexes
Date: 2021-02-14
Splunk version: 8.1
Enterprise Security version: 6.4

See local/savedsearches.conf: [Access - Custom arbitrary index - Test - Rule]

The important parts you need in order to make this work:

	alert.digest_mode = 0
	action.notable.param.index = $result.arbitrary_notable_index$

This assumes that your each of your events contain a field called **arbitrary_notable_index**

Bear in mind that editing a correlation search with these settings from the GUI will set digest_mode back to TRUE, so please stick to the CLI

If you want your correlation searches to show up in Incident Review, also edit the **get_notable_index** macro in SA-ThreatIntelligence/local/macros.conf

