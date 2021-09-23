# TA-SplunkMisc
Miscellaneous tips and tricks for Splunk

## Use Case 1 - Create Enterprise Security notables in separate indexes
Date: 2021-02-14.  
Splunk version: 8.1.  
Enterprise Security version: 6.4

See local/savedsearches.conf: [Access - Custom arbitrary index - Test - Rule]

The important parts you need in order to make this work:

	alert.digest_mode = 0
	action.notable.param.index = $result.arbitrary_notable_index$

This assumes that your each of your events contain a field called **arbitrary_notable_index**

Bear in mind that editing a correlation search with these settings from the GUI will set digest_mode back to TRUE, so please stick to the CLI

If you want your correlation searches to show up in Incident Review, also edit the **get_notable_index** macro in SA-ThreatIntelligence/local/macros.conf

## Use Case 2 - Get Analytic Story Response Tasks for Notable Events
Date: 2021-03-17.  
Splunk Version: 8.1.  
Enterprise Security version: 6.4.  
ESCU Version: 3.14.0.  

This search will look up notable events from ES, join in Analytic Story from ESCU and get the search (Response Task) used to Investigate this. 
It will add in the earliest and latest time offsets as well as legacy Drilldown Searches from ES.  
The use case is for forwarding to Phantom or other IR platforms in order to drill down to an investigative search.

### SPL:
	``` Get all Notables ```
	`notable`
	``` Extract the Analytic Story (our join key) from annotations ```
	| eval analytic_story=spath(annotations,"analytic_story{}")
	``` Get Response Tasks defined in the Analytic Story saved searches ```
	| join type=left max=0 analytic_story 
	[
	| rest /services/saved/searches splunk_server=local count=0 
	| search title="*Response Task" 
	| eval analytic_story=spath('action.escu.analytic_story',"{}")
	| table title, description, search, analytic_story response_task.action.escu.earliest_time_offset response_task.action.escu.latest_time_offset
	| mvexpand analytic_story 
	| rename * AS response_task.* 
	| rename response_task.analytic_story AS analytic_story 
	| eval response_task.earliest_time_offset=coalesce('response_task.action.escu.earliest_time_offset',"86400"), response_task.latest_time_offset=coalesce('response_task.action.escu.latest_time_offset',"0")
	| makejson response_task.search response_task.earliest_time_offset response_task.latest_time_offset output=response_task
	| stats values(response_task) AS response_task BY analytic_story
	| eval response_task=mvjoin(response_task, "######")
	| fields response_task analytic_story
	] 
	| eval response_tasks=split(response_task, "######")

	| mvexpand response_tasks
	| eval response_task_search = spath(response_tasks, "response_task{}.search")

	| eval response_task_earliest_time_offset = spath(response_tasks, "response_task{}.earliest_time_offset")
	| eval response_task_latest_time_offset = spath(response_tasks, "response_task{}.latest_time_offset")
	| eval time_original = _time, time_earliest=_time - response_task_earliest_time_offset, time_latest = _time + response_task_latest_time_offset
	``` Inject earliest= and latest= to | search based SPL```
	| eval response_task_search = replace(response_task_search, "^(\|\s?search)(.+)", "\1 earliest=" . time_earliest . " latest=" . time_latest . " \2" )
	``` Inject earliest= and latest= to | tstats based SPL. Caveat: Does not yet replace in subsearches ```
	| eval response_task_search = if(match(response_task_search,"^(\|\s?tstats)(.+)((?:FROM|from)\s+\S+\s+)((?:WHERE|where)\s+)"), 
	replace(response_task_search, "^(\|\s?tstats)(.+)((?:FROM|from)\s+\S+\s+)((?:WHERE|where)\s+)(.+)", "\1\2\3\4 earliest=" . time_earliest . " latest=" . time_latest . " \5"), 
	replace(response_task_search, "^(\|\s?tstats[^\|]*)((?:FROM|from)\s+\S+\s+)([^\|]*)(.+)", "\1\2 WHERE earliest=" . time_earliest . " latest=" . time_latest . " \3\4")
	)
	| fields - response_tasks response_task

	| stats values(*) AS * values(_raw) AS _raw BY event_id
	``` Inject Legacy Drilldown searches to Response Task Search. Caveat: Only works with standard SPL, not | from command searches as they don't support adding earliest= and latest= ```
	| eval drilldown_search_with_time = if(match(drilldown_search, "^|\s?from"), drilldown_search, "earliest=" . drilldown_earliest . " latest=" . drilldown_latest . " " . drilldown_search )
	| eval response_task_search=mvappend(response_task_search,drilldown_search_with_time)
	| expandtoken
	``` 
	Next step:
	Forward your events to Phantom and have Phantom execute the searches in response_tasks and document findings (I.e. generic Playbook that iterates over the response_tasks)
	
	| sendalert sendtophantom param.phantom_server="Mortens Phantom-server" param.sensitivity="amber" param.severity="high" param.label="notable"```
	
	
### Phantom Playbook
This is where the Phantom playbook that executes these results will go.  
It's basically just a Playbook with a **run query** that is passed **response_task_search**

### Old fun

#### OLD: Creates duplicates because of the mvexpand
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


#### OLD: Tupled Response Tasks (one Notable, multiple Response Tasks):
The benefit of this one is that 1 Notable is 1 Notable.  
The response tasks are a tupled MV field called *response_tasks* in this format:

> SEARCH TITLE//////THE SPL SEARCH//////SEARCH DESCRIPTION


	``` Get all Notables ```
	`notable`
	``` Extract the Analytic Story (our join key) from annotations ```
	| eval analytic_story=spath(annotations,"analytic_story{}")
	``` Get Response Tasks defined in the Analytic Story saved searches ```
	| join type=left max=0 analytic_story
	[
	|rest /services/saved/searches splunk_server=local count=0
	| search title="*Response Task"
	| eval analytic_story=spath('action.escu.analytic_story',"{}")
	| table title, description, search, analytic_story
	| mvexpand analytic_story
	| rename * AS response_task.*
	| rename response_task.analytic_story AS analytic_story
	| eval response_task.mv1=mvzip(mvzip('response_task.title','response_task.search',"//////"), 'response_task.description', "//////")
	| stats values(response_task.mv1) AS response_task.mv2 BY analytic_story
	| eval response_task.mv3=mvjoin('response_task.mv2',"######")
	]
	| eval response_tasks=split('response_task.mv3',"######")
	| fields - response_task.*
	| expandtoken
	``` 
	Next step:
	Forward your events to Phantom and have Phantom execute the searches in response_tasks and document findings (I.e. generic Playbook that iterates over the response_tasks)
	```
	


#### Test fetching Response Tasks from Analytic Story

	| makeresults 
	| eval analytic_story="Malicious PowerShell", src="8.8.8.8", dest="1.1.1.1" 
	| join type=left max=0 analytic_story 
	[
	| rest /services/saved/searches splunk_server=local count=0 
	| search title="*Response Task" 
	| eval analytic_story=spath('action.escu.analytic_story',"{}")
	| table title, description, search, analytic_story
	| mvexpand analytic_story 
	| rename * AS response_task.* 
	| rename response_task.analytic_story AS analytic_story 
	] 
	| expandtoken
	
## Use Case 3 - Azure Web Application Firewall Logs to Splunk Notable Event (WIP)
Date: 2021-09-123.  
Splunk Version: 8.2.  
Enterprise Security version: 6.4.  

This is just the base search. Add Notable Saved Search when done.

	index=azure_azure sourcetype=mscs:azure:eventhub body.records.category=ApplicationGateway*
	| eval action='body.records.properties.action'
	| eval src='body.records.properties.clientIp'
	| eval description='body.records.properties.message'
	| eval dest=if('body.records.properties.hostname' != "<undefined>",mvindex(split('body.records.properties.hostname',":"),0),null())
	| eval url=if(mvindex(split('body.records.properties.hostname',":"),1) == "80", "http://", "tcp://") . mvindex(split('body.records.properties.hostname',":"),0) . 'body.records.properties.requestUri'
	| eval orig_raw = _raw
