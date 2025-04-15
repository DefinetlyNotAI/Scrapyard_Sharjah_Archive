import requests

url = "URL HERE"  # Place the url needed here
headers = {
    "Content-Type": "application/json",  # Specify the content you are passing
    "Accept": "application/json"  # Specify that you expect JSON response
}
data = {
    "api-key": "API VALUE",  # Only if the API requires a value, also any needed json data her
}

response = requests.get(url, json=data, headers=headers)  # Modify as needed
print(response.text)
