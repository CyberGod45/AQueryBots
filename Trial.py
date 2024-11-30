import requests
from requests.auth import HTTPBasicAuth
import json

# Elasticsearch connection details
url = 'http://192.168.1.141:9200/rule_ms_windows-2024.09.39/_search'
username = 'elastic'
password = 'Ztp4ssw0rd@2019'

# Define your query
query = {
    "size" : 10 ,
    "query" : {
        "bool" : {
            "must" : [
                {
                    "term" : {
                        "vendorEId" : "4625"
                        }
                    } ,
                {
                    "range" : {
                        "@timestamp" : {
                            "gte" : "now-90d/d",
                            "lte" : "now"
                            }
                        }
                    }
                ]
            }
        } ,
    "aggs" : {
        "failed_logins" : {
            "terms" : {
                "field" : "destUser.keyword" ,
                "size" : 20
                } ,
            "aggs" : {
                "failed_count" : {
                    "value_count" : {
                        "field" : "destUser.keyword"
                        }
                    } ,
                "source_ips" : {
                    "terms" : {
                        "field" : "srcIp.keyword" ,
                        "size" : 10
                        }
                    } ,
                "failure_reasons" : {
                    "terms" : {
                        "field" : "cs1.keyword" ,
                        "size" : 10
                        }
                    } ,
                "deviceHost" : {
                                    "terms" : {
                                        "field" : "deviceHost.keyword" ,
                                        "size" : 10
                                        }
                                    } ,
                "first_attempt" : {
                    "top_hits" : {
                        "sort" : [
                            {
                                "@timestamp" : {
                                    "order" : "asc"
                                    }
                                }
                            ] ,
                        "_source" : [ "@timestamp" ] ,
                        "size" : 1
                        }
                    } ,
                "last_attempt" : {
                    "top_hits" : {
                        "sort" : [
                            {
                                "@timestamp" : {
                                    "order" : "desc"
                                    }
                                }
                            ] ,
                        "_source" : [ "@timestamp" ] ,
                        "size" : 1
                        }
                    }
                }
            }
        }
    }

# Send the request
try :
    response = requests.post(
        url ,
        auth = HTTPBasicAuth( username , password ) ,
        json = query ,
        timeout = 10
        )
    response.raise_for_status()

    # Parse the response
    data = response.json()
    print(data)
    # with open( "querydata.json" , "a" ) as file :
    #     json.dump( data , file , indent = 4 )
    # Process and print aggregations
    if 'aggregations' in data and 'failed_logins' in data [ 'aggregations' ] :
        failed_logins = data [ 'aggregations' ] [ 'failed_logins' ] [ 'buckets' ]

        print( "Failed Login Details:" )
        for bucket in failed_logins :
            print( "\nUser:" , bucket [ 'key' ] )
            print( "Total Failed Attempts:" , bucket [ 'doc_count' ] )

            # Source IPs
            if 'source_ips' in bucket :
                print( "Source IPs:" )
                for ip in bucket [ 'source_ips' ] [ 'buckets' ] :
                    print( f"- {ip [ 'key' ]} (Count: {ip [ 'doc_count' ]})" )

            # Failure Reasons
            if 'failure_reasons' in bucket :
                print( "Failure Reasons:" )
                for reason in bucket [ 'failure_reasons' ] [ 'buckets' ] :
                    print( f"- {reason [ 'key' ]} (Count: {reason [ 'doc_count' ]})" )

            if 'deviceHost' in bucket :
                print( "deviceHost:" )
                for Machine in bucket [ 'deviceHost' ] [ 'buckets' ] :
                    print( f"- {Machine [ 'key' ]} (Count: {Machine [ 'doc_count' ]})" )

            # First and Last Attempt Timestamps
            if 'first_attempt' in bucket and bucket [ 'first_attempt' ] [ 'hits' ] [ 'total' ] [ 'value' ] > 0 :
                first_timestamp = bucket [ 'first_attempt' ] [ 'hits' ] [ 'hits' ] [ 0 ] [ '_source' ] [ '@timestamp' ]
                print( "First Attempt:" , first_timestamp )

            if 'last_attempt' in bucket and bucket [ 'last_attempt' ] [ 'hits' ] [ 'total' ] [ 'value' ] > 0 :
                last_timestamp = bucket [ 'last_attempt' ] [ 'hits' ] [ 'hits' ] [ 0 ] [ '_source' ] [ '@timestamp' ]
                print( "Last Attempt:" , last_timestamp )

    else :
        print( "No aggregations found in the response." )

except requests.exceptions.RequestException as e :
    print( f"Request Error: {e}" )
except Exception as e :
    print( f"Error processing response: {e}" )