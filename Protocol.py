import json
import time

import requests
import pandas as pd
import csv
import os
from datetime import datetime, timedelta
# importing timezone from pytz module
from pytz import timezone
from dateutil.relativedelta import relativedelta

# giving the format of datetime g., '2023-07-07T23:59:59Z'): ")
format = "%Y-%m-%d %H:%M:%S"

# getting the current time in UTC timezone
now_utc = datetime.now(timezone('UTC'))

# Format the above DateTime using the strftime()
print('Current Time in UTC TimeZone:',now_utc.strftime(format))

# Converting to Asia/Kolkata time zone
now_asia = now_utc.astimezone(timezone('Asia/Kolkata'))

# Format the above datetime using the strftime()
print('Current Time in Asia/Kolkata TimeZone:',now_asia.strftime(format))
temp_list =[]

def get_custom_time_range():
    s_yeard = input("Enter the Starting  Date in format(YYYY-MM-DD):Ex{2023-09-01}")
    s_yeart = input("Enter the Starting  Time in format(HH:MM:SS)Ex{02:15:15}")
    start_time = f"{s_yeard}T{s_yeart}Z"
    print(start_time)
    # kk = dastart_timestrftime(format)
    print(start_time)
    # print(kk)
    e_yeard = input("Enter the Ending Date in format(YYYY-MM-DD):Ex{2023-09-01}")
    e_yeart = input("Enter the Ending Time in format(HH:MM:SS)Ex{02:15:15}")
    end_time =  f"{e_yeard}T{e_yeart}Z"
    print(end_time)
    return start_time, end_time


def get_last_24_hours():


    hour =int(input("{enter the Hour in digit from 0-24}"))
    start_time = (now_asia - timedelta(hours=hour))
    end_time = now_asia
    print(start_time.isoformat(),end_time.isoformat())
    return start_time.isoformat(), end_time.isoformat()


def get_last_7_days():
    # now = datetime.utcnow()
    day =int(input("Enter the No of Days {example: 7 means 7 Days from now}"))
    start_time = (now_asia - timedelta(days=day))
    end_time = now_asia
    return start_time.isoformat(), end_time.isoformat()

def get_last_minute():
    min =int(input("Enter the No of Minutes{example 15 means 15 from now}"))
    start_time =(now_asia - timedelta(minutes=min))
    end_time =(now_asia)
    return start_time.isoformat(),end_time.isoformat()
# utc_datetime = datetime.now(tzutc())
# local_timezone = pytz.timezone('Asia/Kolkata')

def get_last_month():
    month = int(input("Enter the No of Months {example 5 means 5 months from now} "))
    start_time =(now_asia - relativedelta(months=month))
    end_time =(now_asia)
    return start_time.isoformat(),end_time.isoformat()

def get_last_year():
    year =int(input("Enter the No of Year"))
    start_time =(now_asia - relativedelta(years=year))
    end_time =(now_asia)
    return start_time.isoformat(), end_time.isoformat()

def main():
    print("Choose a time period:")
    print("1. Custom Time Range")
    print("2. Last N Hours")
    print("3. Last N Days")
    print("4. Last N Minutes")
    print("5. Last N Months")
    print("6. Last N Years")
    choice = input("Enter your choice: ")

    if choice == "1":
        start_time, end_time = get_custom_time_range()
    elif choice == "2":
        start_time, end_time = get_last_24_hours()
    elif choice == "3":
        start_time, end_time = get_last_7_days()
    elif choice == "4":
        start_time, end_time = get_last_minute()
    elif choice == "5":
        start_time, end_time = get_last_month()
    elif choice == "6":
        start_time, end_time =get_last_year()
    else:
        print("Invalid choice")

    url = 'http://192.168.1.141:9200/rule_ms_windows-2024.08.31/_search'
    query = {
        "query": {
            "bool": {
                "must": [
                    {"match": {"event.module": "sysmon"}},
                    {"match": {"winlog.event_id": "1"}}
                ],
                "filter": {
                    "range": {
                        "@timestamp": {
                            "gte": start_time,
                            "lte": end_time
                        }
                    }
                }
            }
        },
        "size": 10000
    }
    # Send the search request
    response = requests.post(url, json=query)
    # Process the search results
    if response.status_code == 200:
        result = response.json()
        with open("../log2.json", "a") as file:
            json.dump(result, file, indent=4)
        # print(result)
        fi_name =input("Please Give A Name to File  {ex week1/day2/my_file}:")
        with open(f"{fi_name}.csv", "a") as f:
                column_name =["Process_name","Hostname","Hash","Timestamp","MAC_Address","Ip_Address"]
                wr = csv.writer(f)
                wr.writerow(column_name)
                try:
                    for hit in result['hits']['hits']:
                        # proc = hit['_source'].get('process', {}).get('parent',{}).get('executable')
                        # des = hit['_source'].get('process', {}).get('pe', {}).get('description')
                        real = hit['_source'].get('process', {}).get('name')
                        has = hit['_source'].get('process', {}).get('hash', {}).get('sha256')
                        timey = hit['_source'].get('@timestamp')
                        user = hit['_source'].get('host', {}).get('name')
                        ip_address = hit['_source'].get('host').get('ip')
                        mac_address = hit['_source'].get('host').get('mac')

                        # des = hit['_source']['process']['pe']['product.keyword']
                        # process = hit['_source'].get('winlog', {}).get('event_data', {}).get('OriginalFileName')
                        # User = hit['_source'].get('winlog', {}).get('event_data', {}).get('User')
                        # ['winlog']['event_data'].get('ParentUser')OriginalFileName
                        # print([real, has, user,timey, mac_address])
                        # f_name = input("Enter the file name with extension csv {example: week1.csv}")

                        wr.writerow([real, user, has,timey,mac_address,ip_address])
                        temp_list.append([real,has,user])
                        # print(hit['_source']['process']['parent']['executable'])
                except Exception as e:
                    print(e)

    else:
        print(f"Request failed with status code: {response.status_code}")
    # from duplicate import dupdel as rm

    # file_name = input("Enter the file name to be open")

    print("Filtering the Data...")
    # print(temp_list)
    time.sleep(15)

    # rm(fi_name)

    return temp_list
# if __name__ == "__main__":
#     main()
#     vh = temp_list
#     from newsand3 import get_new_processes as gnp
#     print(vh)
# else:
#     print("Have a Good Day")