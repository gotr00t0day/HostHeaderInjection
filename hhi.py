from colorama import Fore
import requests
import argparse
import urllib3

requests.packages.urllib3.disable_warnings()

parser = argparse.ArgumentParser()

parser.add_argument('-hhi', '--hostheaderinjection',
                    type=str, help='scan a file for injection',
                    metavar='domains.txt')

args = parser.parse_args()

banner = """

 ██░ ██  ██░ ██     ██▓ ███▄    █  ▄▄▄██▀▀▀▓█████  ▄████▄  ▄▄▄█████▓ ██▓ ▒█████   ███▄    █ 
▓██░ ██▒▓██░ ██▒   ▓██▒ ██ ▀█   █    ▒██   ▓█   ▀ ▒██▀ ▀█  ▓  ██▒ ▓▒▓██▒▒██▒  ██▒ ██ ▀█   █ 
▒██▀▀██░▒██▀▀██░   ▒██▒▓██  ▀█ ██▒   ░██   ▒███   ▒▓█    ▄ ▒ ▓██░ ▒░▒██▒▒██░  ██▒▓██  ▀█ ██▒
░▓█ ░██ ░▓█ ░██    ░██░▓██▒  ▐▌██▒▓██▄██▓  ▒▓█  ▄ ▒▓▓▄ ▄██▒░ ▓██▓ ░ ░██░▒██   ██░▓██▒  ▐▌██▒
░▓█▒░██▓░▓█▒░██▓   ░██░▒██░   ▓██░ ▓███▒   ░▒████▒▒ ▓███▀ ░  ▒██▒ ░ ░██░░ ████▓▒░▒██░   ▓██░
 ▒ ░░▒░▒ ▒ ░░▒░▒   ░▓  ░ ▒░   ▒ ▒  ▒▓▒▒░   ░░ ▒░ ░░ ░▒ ▒  ░  ▒ ░░   ░▓  ░ ▒░▒░▒░ ░ ▒░   ▒ ▒ 
 ▒ ░▒░ ░ ▒ ░▒░ ░    ▒ ░░ ░░   ░ ▒░ ▒ ░▒░    ░ ░  ░  ░  ▒       ░     ▒ ░  ░ ▒ ▒░ ░ ░░   ░ ▒░
 ░  ░░ ░ ░  ░░ ░    ▒ ░   ░   ░ ░  ░ ░ ░      ░   ░          ░       ▒ ░░ ░ ░ ▒     ░   ░ ░ 
 ░  ░  ░ ░  ░  ░    ░           ░  ░   ░      ░  ░░ ░                ░      ░ ░           ░ 
                                                  ░                           Version: 1.0
                                                  By: c0deNinja              



"""

print(f"{Fore.CYAN}{banner}")

if args.hostheaderinjection:
    print(f"{Fore.MAGENTA}\t\t Host Header Injection \n")
    redirect = ["301", "302", "303", "307", "308"]
    with open(f"{args.hostheaderinjection}") as f:
        domains = [x.strip() for x in f.readlines()]
        payload = b"google.com" 
        print(f"{Fore.WHITE} Checking For {Fore.CYAN}X-Forwarded-Host {Fore.WHITE}and {Fore.CYAN}Host {Fore.WHITE}injections.....\n")
        try:
            for domainlist in domains:
                session = requests.Session()
                header = {"X-Forwarded-Host": "google.com"}
                header2 = {"Host": "google.com"}
                resp = session.get(f"{domainlist}", verify=False, headers=header)
                resp2 = session.get(f"{domainlist}", verify=False, headers=header2)
                resp_content = resp.content
                resp_status = resp.status_code
                resp2_content = resp2.content
                for value, key in resp.headers.items():
                    for pos, web in enumerate(domainlist):
                        if pos == 0:
                            vuln_domain = []
                            duplicates_none = []  
                            if value == "Location" and key == payload and resp.status_code in redirect:
                                vuln_domain.append(domainlist)
                            if payload in resp_content or key == payload:
                                vuln_domain.append(domainlist)
                        else:
                            pass
                for value2, key2 in resp2.headers.items():
                    for pos, web in enumerate(domainlist):
                        if pos == 0:
                            if payload in resp2_content or key == payload:
                                vuln_domain.append(domainlist)
                        else:
                            pass
                if vuln_domain:
                    [duplicates_none.append(x) for x in vuln_domain if x not in duplicates_none]
                    duplicates_none = ", ".join(duplicates_none)
                    print(f"{Fore.RED} POSSIBLE {Fore.YELLOW} Host Header Injection Detected {Fore.MAGENTA}- {Fore.GREEN} {duplicates_none}")
                print(f"{Fore.CYAN} No Detection {Fore.MAGENTA}- {Fore.GREEN} {(domainlist)}{Fore.BLUE} ({resp_status})")
        except requests.exceptions.TooManyRedirects:
            pass