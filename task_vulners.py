import requests
from urllib.parse import urlsplit
from urllib.parse import urlunsplit
import json
import pandas as pd
import numpy as np
import csv

url1 = 'https://vulners.com/api/v3/search/lucene/'
url2 = 'https://vulners.com/api/v3/burp/softwareapi/'
api_key = 'qweqwr' # Replace <Your-API-Key-Here> with actual API key
Soft_api = [
  {"Program": "LibreOffice", "Version": "6.0.7"},
  {"Program": "7-Zip", "Version": "18.03"},
  {"Program": "Adobe Reader", "Version": "18.009.20050"},
  {"Program": "nginx", "Version": "1.14.0"},
  {"Program": "Apache HTTP Server", "Version": "2.4.29"},
  {"Program": "DjVu Reader", "Version": "2.0.0.27"},
  {"Program": "Wireshark", "Version": "2.6.1"},
  {"Program": "Notepad++", "Version": "8.0"},
  {"Program": "Google Chrome", "Version": "68.0.3440.106"},
  {"Program": "Mozilla Firefox", "Version": "61.0.1"}
]
# работа с cve
print("List cve:")
for i in Soft_api:
  soft_vuln = dict(i)
  data = {
    "query": f"{i["Program"]}",
    "version": f"{i["Version"]}",
    "type": "software",
    "maxVulnerabilities": 100,
    "apiKey": f"{api_key}"
  }
  response = requests.post(url1, json=data)
  assert response.status_code == 200, f"Unexpected status code: {response.status_code}"
  vuln_cve = response.json()

  cve = []
  if "data" in vuln_cve:
    if vuln_cve["result"] == "error":
      print(f'cve not found {soft_vuln["Program"]} {soft_vuln["Version"]}')
    if vuln_cve["data"].get("search"):
      for value in vuln_cve["data"].get("search"):
        cve.append(value["_source"]["cvelist"])
      print(f'{soft_vuln["Program"]} {soft_vuln["Version"]} : {cve[1:3]}')

#Работа с exploit
Soft_api2 = [
  {"Program": "LibreOffice", "Version": "6.0.7"},
  {"Program": "7-Zip", "Version": "18.03"},
  {"Program": "Adobe Reader", "Version": "18.009.20050"},
  {"Program": "nginx", "Version": "1.14.0"},
  {"Program": "Apache HTTP Server", "Version": "2.4.29"},
  {"Program": "DjVu Reader", "Version": "2.0.0.27"},
  {"Program": "Wireshark", "Version": "2.6.1"},
  {"Program": "Notepad++", "Version": "8.0"},
  {"Program": "Google Chrome", "Version": "68.0.3440.106"},
  {"Program": "Mozilla Firefox", "Version": "61.0.1"} ]

print("List exploit:")
for i_2 in Soft_api2:
  soft_vuln2 = dict(i_2)

  data = {
    "software": f"{soft_vuln2["Program"]}",
    "version": f"{soft_vuln2["Version"]}",
    "type": "software",
    "maxVulnerabilities": 500,
    "only_ids": False,
    "apiKey": f"{api_key}"
  }
  response2 = requests.post(url2, json=data)
  assert response2.status_code == 200, f"Unexpected status code: {response2.status_code}"

  vuln_resp = response2.json()
  Exp = []

  if "data" in vuln_resp:
    if vuln_resp["result"] == "error":
      print(f'Exploit not found {soft_vuln2["Program"]} {soft_vuln2["Version"]}')
    if vuln_resp["data"].get("search"):
      for value in vuln_resp["data"].get("search"):
        if not value["id"].startswith("CVE"):
          Exp.append({"id": value["id"], "title":value["_source"]["title"]})
      print(f'{soft_vuln2["Program"]} {soft_vuln2["Version"]} : {Exp[1:3]}')
