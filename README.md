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

## Use Case 2 - Get Analytic Story Response Tasks for Notable Events
Date: 2021-02-18
Splunk Version: 8.1
Enterprise Security version: 6.4
ESCU Version: 3.14.0

This search will look up notable events from ES, join in Analytic Story from ESCU and get the search (Response Task) used to Investigate this
The use case is for forwarding to Phantom or other IR platforms in order to drill down to an investigative search.

	`notable`
	| eval analytic_story=spath(annotations,"analytic_story{}")
	| join type=left max=0 analytic_story
	[
	|rest /services/saved/searches splunk_server=local count=0
	| search title="*Response Task"
	| eval analytic_story=spath('action.escu.analytic_story',"{}")
	| table title, description, search, analytic_story
	| mvexpand analytic_story
	| rename * AS response_task.*
	| rename response_task.analytic_story AS analytic_story
	]
	| expandtoken
