#!/usr/bin/env python

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from Crawler import Crawler
from XssInjection import XssInjection
from SqlInjection import SqlInjection
import argparse
import os

    
    
def print_banner():
    banner = """
    		    ░██╗░░░░░░░██╗███████╗██████╗░
		    ░██║░░██╗░░██║██╔════╝██╔══██╗
		    ░╚██╗████╗██╔╝█████╗░░██████╦╝
		    ░░████╔═████║░██╔══╝░░██╔══██╗
		    ░░╚██╔╝░╚██╔╝░███████╗██████╦╝
		    ░░░╚═╝░░░╚═╝░░╚══════╝╚═════╝░

██╗░░░██╗██╗░░░██╗██╗░░░░░███╗░░██╗███████╗██████╗░░█████╗░██████╗░██╗██╗░░░░░██╗████████╗██╗░░░██╗
██║░░░██║██║░░░██║██║░░░░░████╗░██║██╔════╝██╔══██╗██╔══██╗██╔══██╗██║██║░░░░░██║╚══██╔══╝╚██╗░██╔╝
╚██╗░██╔╝██║░░░██║██║░░░░░██╔██╗██║█████╗░░██████╔╝███████║██████╦╝██║██║░░░░░██║░░░██║░░░░╚████╔╝░
░╚████╔╝░██║░░░██║██║░░░░░██║╚████║██╔══╝░░██╔══██╗██╔══██║██╔══██╗██║██║░░░░░██║░░░██║░░░░░╚██╔╝░░
░░╚██╔╝░░╚██████╔╝███████╗██║░╚███║███████╗██║░░██║██║░░██║██████╦╝██║███████╗██║░░░██║░░░░░░██║░░░
░░░╚═╝░░░░╚═════╝░╚══════╝╚═╝░░╚══╝╚══════╝╚═╝░░╚═╝╚═╝░░╚═╝╚═════╝░╚═╝╚══════╝╚═╝░░░╚═╝░░░░░░╚═╝░░░

	░██████╗░█████╗░░█████╗░███╗░░██╗███╗░░██╗███████╗██████╗░
	██╔════╝██╔══██╗██╔══██╗████╗░██║████╗░██║██╔════╝██╔══██╗
	╚█████╗░██║░░╚═╝███████║██╔██╗██║██╔██╗██║█████╗░░██████╔╝
	░╚═══██╗██║░░██╗██╔══██║██║╚████║██║╚████║██╔══╝░░██╔══██╗
	██████╔╝╚█████╔╝██║░░██║██║░╚███║██║░╚███║███████╗██║░░██║
	╚═════╝░░╚════╝░╚═╝░░╚═╝╚═╝░░╚══╝╚═╝░░╚══╝╚══════╝╚═╝░░╚═╝
    """
    print(banner)


def Login(session, login_url, payload, isDVWA = False):
    r = session.get(login_url)

    if isDVWA:
        print('DVWA Setting')
        session.cookies.set('security', 'low', domain=urlparse(login_url).netloc, path='')
    
    signin = BeautifulSoup(r.content, "html5lib")
    loginforms = signin.find('form')
    try:
        hiddenInput = loginforms.find_all('input', attrs={"type": "hidden"})
        for hr in hiddenInput:
            payload[hr['name']] = hr['value']
    except:
        pass
 
    p = session.post(login_url, data=payload)
    return p.url

def Session_Creator(login_url, payload={}, isDVWA=False):
    s = requests.session()
    protected_url = Login(s, login_url, payload, isDVWA)
    return (s, protected_url)

def main():
    os.system('clear')
    print_banner()
    
    parser = argparse.ArgumentParser(description="")
    parser.add_argument("--login", help="login page url")
    parser.add_argument('--avoid', nargs='*', help='avoid urls')
    parser.add_argument("-u", "--username", help="username")
    parser.add_argument("-p", "--password", help="password")
    parser.add_argument("-t", "--thread", help="Number of thread", default=1, type=int)
    parser.add_argument("-mu", "--maxUrl", help="Number of max URLs to crawl, default is 30.", default=30, type=int)
    parser.add_argument('-x', '--XSSi', help="XSS injection attack", action='store_true', default=False)
    parser.add_argument('-xp', '--XSSpayload', help="XSS injection payload path")
    parser.add_argument('-s', '--SQLi', help="SQL injection attack", action='store_true', default=False)
    parser.add_argument('-sp', '--SQLpayload', help="SQL injection payload path")
    parser.add_argument('--test', help="test on DVWA", action='store_true', default=False)
    args = parser.parse_args()

    loginURL = args.login
    avoidURL = args.avoid
    thread = args.thread
    max_urls = args.maxUrl 

    if args.test:
        loginURL = "http://localhost/DVWA/login.php"
        avoidURL = ["http://localhost/DVWA/logout.php", "http://localhost/DVWA/security.php",
                    "http://localhost/DVWA/setup.php", "http://localhost/DVWA/vulnerabilities/csrf/","http://localhost/DVWA/vulnerabilities/captcha/"
                   ]

    username = args.username if args.username else 'admin'
    password = args.password if args.password else 'password'

    payload = { 
        'username': username,
        'password': password,
        'Login': 'Login'
    }

    Session, protectedURL = Session_Creator(loginURL, payload, args.test)
    internal_urls = Crawler(Session, protectedURL, loginURL, avoidURL).crawl(max_urls, DynamicSite=0, verbose=False)

    if args.XSSi:
        XssInjection(Session, args.XSSpayload, internal_urls).Fuzzer()
    if args.SQLi:
        SqlInjection(Session, args.SQLpayload, internal_urls).Fuzzer()


if __name__ == '__main__':
    main()
