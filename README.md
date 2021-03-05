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
Date: 2021-02-18.  
Splunk Version: 8.1.  
Enterprise Security version: 6.4.  
ESCU Version: 3.14.0.  

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


### Tupled Response Tasks (one Notable, multiple Response Tasks):
The benefit of this one is that 1 Notable is 1 Notable. The response tasks are a tupled MV field called *response_tasks* in this format:

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
	

### Also add in legacy ES Drilldowns
This will add drilldowns as response tasks. Add this at the end of the search before expandtoken.  
TODO: Add the drilldown_latest and drilldown_earliest

	```
	Add legacy drilldowns (ES) to Response Task
	TODO: Include search URL, drilldown_earliest and drilldown_latest
	```
	| eval response_task.title=mvappend('response_task.title',drilldown_name)
	| eval response_task.search=mvappend('response_task.search',drilldown_search)


### Test fetching Response Tasks from Analytic Story

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
