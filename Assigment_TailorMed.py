#!/usr/bin/env python
# coding: utf-8

# ### API

# In[880]:


import pandas as pd
import requests
from datetime import datetime
url_nys = "https://www.virustotal.com/api/v3/urls/10b6b18f32d34529f830e2e70839c4b13297ed2f6515beb809dd7a3708250295"
headers = {
    "Accept": "application/json",
    "x-apikey": "b7450871b75dcfc4c4f9e9ac964e7b3a17ce08cb449d35a1d53f7fababe75a1d"
}
response_nys = requests.request("GET", url_nys, headers=headers)
response_vote_nys= requests.request("GET", url_votes_nys, headers=headers)
#-------------------------------------------------------------------
url_academy = "https://www.virustotal.com/api/v3/urls/b1c4bc75a23097fdd397cef83c912065c40b0e97944331ee017d852be17c5076"
response_academy = requests.request("GET", url_academy, headers=headers)
#----------------------------------------------------------------------------
url_gate = "https://www.virustotal.com/api/v3/urls/f443cb661a3ce88d135d802d062527cb67e23304468de8206706518a7e50b18d"
response_gate = requests.request("GET", url_gate, headers=headers)

#-----------------------------------------------------
url_vegweb= "https://www.virustotal.com/api/v3/urls/1d5b2bb2857527f45a2eb2121ea19b381b8b51e99a1edb53f4c1194a502a915d"
response_vegweb = requests.request("GET", url_vegweb, headers=headers)
#--------------------------------------------------------------
url_tailor= "https://www.virustotal.com/api/v3/urls/ad8a7e1bfaf884b28cec0418411d79ec0e7c95383748eb4eb38fc190c5bfa683"
response_tailor = requests.request("GET", url_tailor, headers=headers)


# ### Site’s risk

# In[641]:


list_of_all_dict=[response_gate.json(),response_nys.json(),response_academy.json(),response_vegweb.json(),response_tailor.json()]
def paramtetrs_for_risk(res_dict):
    malware=res_dict["data"]["attributes"]["last_analysis_results"]["Malwared"]["result"]
    phishing=res_dict["data"]["attributes"]["last_analysis_results"]["Phishing Database"]["result"]
    num_malicious=res_dict["data"]["attributes"]["last_analysis_stats"]['malicious']
    return malware,phishing,num_malicious


# In[861]:

#creatinf at_risky_dictiory: key= website, values= 'safe' ,'Not Safe'

dict_at_risky={}
for dic in list_of_all_dict:
    for res in  paramtetrs_for_risk(dic):
        if(paramtetrs_for_risk(dic)[0]!='clean' or paramtetrs_for_risk(dic)[1]!='clean'  or paramtetrs_for_risk(dic)[2]>0):
                dict_at_risky[dic["data"]["attributes"]["url"]]='Not Safe'
        else:
                dict_at_risky[dic["data"]["attributes"]["url"]]='safe'


# ### Total (#) voting

# creating total voting for eache website : key - website name , values -  Total Value
all_voting={} 

for item in list_of_all_dict:
    all_voting[item["data"]["attributes"]["url"]]=sum(item["data"]["attributes"]["total_votes"].values())

# ### Categories

categories={}
for item in list_of_all_dict:
    categories[item["data"]["attributes"]["url"]]=item["data"]["attributes"]["categories"]["Comodo Valkyrie Verdict"]


# ### Query only websites which were not queried for at least 30 minutes.

# In[726]:


now = datetime.now()
ts = datetime.timestamp(now)
last_time_query={}
for item in list_of_all_dict:
    diffs=ts-item["data"]["attributes"]["last_analysis_date"]
    time_diffs= (datetime.fromtimestamp(diff).hour)*60
    if time_diffs>=30:
        last_time_query[item["data"]["attributes"]["url"]]=time_diffs

#collect all dict to one dict , will be transformed to daframe later on
from collections import defaultdict
list_all_dict=[last_time_query,categories,all_voting,dict_at_risky]
final_data_dict=defaultdict(list)
for dictionery  in list_all_dict:
    for key in dictionery.keys():
        final_data_dict[key].append(dictionery[key])


# transform dict to datframe and transpose to get the final dataframe 
df=pd.DataFrame.from_dict(final_data_dict).transpose().reset_index()
df
# nameing the columns :
table_df=df.rename(columns={'index':"website", 0: "time_from_last_query_hours",1:"Category",2:"total_vot",3:"at_risk"})

# creating xls file to our PC (the data came from our last daframe :
csv_file=table_df.to_csv(r'./assigmnet_tailormed.xls',sep='\t',index=False,columns=table_df.columns)


# ### SQL


#The top earning employee and his salary+ Salary difference between The top and the second earning employees.

select 
first_name ,
last_name ,
Departments_name,
salary,
slaray-following_salary as salary diff 
        from(select 
             first_name,
             last_name,
             Departments.name as Departments_name,
             slaray,
             rank() over(partition by Departments_id ,first_name,last_name order by salary desc) as rnk,
             lead(salary) over (partition by Departments_id ,first_name,last_name order by Departments_id ) as following_salary
             from employees join Departments on 
                  employees.Departments_id=Departments.id) as data_table
where rnk=1
 
#Calculate the percent of employees working in the company for more than 3 years.

select 
count(hire_date)/(select count(*) from employees) as percantage
from employees
where date(year,current_date())-hire_date >3 

