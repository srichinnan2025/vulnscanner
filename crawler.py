import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

def crawl(start_url, max_pages=30):
    visited = set()
    queue = [start_url]
    domain = urlparse(start_url).netloc

    while queue and len(visited) < max_pages:
        url = queue.pop(0)
        if url in visited:
            continue

        visited.add(url)

        try:
            r = requests.get(url, timeout=5)
            soup = BeautifulSoup(r.text, "html.parser")

            for a in soup.find_all("a", href=True):
                link = urljoin(url, a["href"])
                if urlparse(link).netloc == domain:
                    queue.append(link)
        except:
            pass

    return list(visited)
