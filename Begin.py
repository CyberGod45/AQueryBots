import requests
from requests.auth import HTTPBasicAuth
import json
# Elasticsearch connection details
url = 'http://192.168.1.141:9200/rule_ms_windows-2024.08.31/_search'
username = 'elastic'  # Replace with your username
password = 'Ztp4ssw0rd@2019'  # Replace with your password

# Define your query
query = {
    "query": {
        "match_all": {}  # Replace with your actual query
    }
}

# Send the request
try:
    response = requests.get(url, auth=HTTPBasicAuth(username, password), json=query)
    response.raise_for_status()  # Raise an error for HTTP codes >= 400
    if response.status_code == 200:
        result = response.json()
        with open("ty45.json", "a") as file:
            json.dump(result, file, indent=4)
        # print(result)
    data = response.json()
    print("Query Results:")
    print(data)
except requests.exceptions.RequestException as e:
    print(f"An error occurred: {e}")
