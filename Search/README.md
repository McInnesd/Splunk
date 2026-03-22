## Get list of avalaible fields and template tstats search
```
| rest splunk_server=local count=0 /services/data/models 
| search acceleration=1 
| rename title as model,eai:data as data 
| spath input=data output=objects path=objects{} 
| mvexpand objects 
| spath input=objects output=object_name path=objectName 
| spath input=objects output=object_parent_name path=parentName 
| spath input=objects output=fields path=fields{} 
| appendpipe 
    [ spath input=objects output=fields path=calculations{}.outputFields{}] 
| mvexpand fields 
| spath input=fields output=field_name path=fieldName 
| spath input=fields output=recommended path=comment.recommended 
| spath input=fields output=description path=comment.description 
| search field_name!=_time NOT object_name IN(Datamodel_Acceleration, Scheduler_Activity, Web_Service_Errors, *_Intelligence) NOT model IN(Incident_Management, Risk, Splunk_Audit) 
| sort model,object_name,field_name 
| eval datamodel = case(object_parent_name=="BaseSearch", model + "." + object_name, object_parent_name=="BaseEvent", model + "." + object_name, true(), model) 
| eval dataset_name = if(object_parent_name=="BaseEvent" OR object_parent_name=="BaseSearch", object_name, object_parent_name + "." + object_name) 
| eval tstats_field_name = dataset_name + "." + field_name 
| eval tstats_search = "| tstats summariesonly=true count from datamodel=" + datamodel + " where nodename=" + dataset_name + " by " + tstats_field_name 
| table model,dataset_name,field_name,recommended,description tstats_field_name tstats_search
```


## Use subsearch to get fields from a data model and format for the fields command
```
`wineventlog_security`
| fields index source sourcetype host
    [| rest splunk_server=local count=0 /services/data/models/Authentication 
    | search acceleration=1 
    | rename title as model,eai:data as data 
    | spath input=data output=objects path=objects{} 
    | mvexpand objects 
    | spath input=objects output=object_name path=objectName 
    | spath input=objects output=object_parent_name path=parentName 
    | spath input=objects output=fields path=fields{} 
    | appendpipe 
        [ spath input=objects output=fields path=calculations{}.outputFields{}] 
    | mvexpand fields 
    | spath input=fields output=search path=fieldName 
    | stats values(search) as search 
    | eval search = mvjoin(search, " ") ]
```