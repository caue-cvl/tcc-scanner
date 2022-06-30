import requests
#from bs4 import BeautifulSoup
import re
try:
    from googlesearch import search
except ImportError:
    print("Baixa a porra do google usando o comando 'pip3 install google'")
 
# to search
query = "springboot vulnerabilities"

def search_in_google(param):
    url_availables = []
    for j in search(param, tld="co.in", num=10, stop=10, pause=2):
        url_availables.append(j)
    return url_availables


def get_content_page(sites_available_option):
    url_link_available = search_in_google(query)[sites_available_option]
    request_page = requests.get(url_link_available)
    filter_content_page(request_page.text)


def filter_content_page(page_content):
    cve_id = re.search('CVE.*-\d{4}-\d{1,}', page_content)
    print(cve_id_formatter(cve_id.group(0)))

def cve_id_formatter(cve_id):
    current_cve_unformatted = cve_id.split('-')
    current_cve_unformatted[0] = "CVE"
    cve_formatted_value = '-'.join(current_cve_unformatted)
    return cve_formatted_value

for site in range(0, 10):
    try:
        get_content_page(site)
    except:
        pass