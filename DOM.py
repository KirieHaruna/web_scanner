import requests
from lxml import etree

HEADER = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0'
}


def check(url):
    html = requests.get(url, headers=HEADER).text
    htm = etree.HTML(html)
    htree = etree.ElementTree(htm)

    count = 0
    for t in htm.iter():
        str = htree.getpath(t)
        if str.count("/") > count:
            count = str.count("/")
    return count
