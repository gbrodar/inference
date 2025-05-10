import requests
import re
from openai import OpenAI
from bs4 import BeautifulSoup
from datetime import datetime, timedelta

OPENAI_API_KEY = "sk-proj-fXjUU0bazogOV-SUjBxg2VuXpdUxA1uNZPuJZUGi50ONAOrmMhKd0QR5YiK_EZpBdegQx5UgOpT3BlbkFJvQS4jXDE"\
                 "DmlBcvUvzu-okdiyMjHANsFBTecUhPGnIMOKDfficGy4wXrFQ2ms6r2GXXRY9J8PMA"

def extract_from_malpedia():
    # Fetch Malpedia Library page
    url = "https://malpedia.caad.fkie.fraunhofer.de/library"
    headers = {"User-Agent": "Mozilla/5.0"}
    response = requests.get(url, headers=headers)
    soup = BeautifulSoup(response.content, "html.parser")

    # Time range for last week
    today = datetime.today()
    last_week = today - timedelta(days=7)

    # Locate all BibTeX entries
    entries = soup.find_all("a", class_="bibtex_modal")

    # Regex patterns to extract fields
    date_pattern = re.compile(r'date\s*=\s*{([\d-]+)}')
    url_pattern = re.compile(r'url\s*=\s*{(.+?)}')
    title_pattern = re.compile(r'title\s*=\s*{{(.+?)}}')

    recent_articles = []

    for entry in entries:
        mbody = entry.get("mbody", "")
        match_date = date_pattern.search(mbody)
        match_url = url_pattern.search(mbody)
        match_title = title_pattern.search(mbody)

        if match_date and match_url:
            pub_date = datetime.strptime(match_date.group(1), "%Y-%m-%d")
            if last_week.date() <= pub_date.date() <= today.date():
                article_url = match_url.group(1)
                article_title = match_title.group(1) if match_title else "No title"
                recent_articles.append({
                    "date": pub_date.date(),
                    "title": article_title,
                    "url": article_url
                })

    # Output results
    for article in recent_articles:
        print(f"{article['date']} - {article['title']}")
        print(f"  ↳ {article['url']}")

    return recent_articles

def extract_from_linked_articles(artciles):
    texts = []
    for article in articles:
        url = article['url']
        headers = {"User-Agent": "Mozilla/5.0"}
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()

        # Strip HTML
        soup = BeautifulSoup(response.content, "html.parser")
        text = soup.get_text()
        extract_iocs_with_openai(text)

def extract_iocs_with_openai(text):
    prompt = f"""
You are a cybersecurity analyst. From the text below, extract:

- All IP addresses (including obfuscated like 8[.]8[.]8[.]8)
- All domain names (even if obfuscated with [.] instead of .)
- All file hashes (MD5, SHA-1, SHA-256)
- All MITRE ATT&CK technique IDs (e.g., T1059, T1566.001)

Respond with a JSON object like:
{{
  "ip_addresses": [],
  "domain_names": [],
  "file_hashes": [],
  "ttps": []
}}

Text:
\"\"\"
{text}
\"\"\"
"""

    client = OpenAI(api_key=OPENAI_API_KEY)
    completion = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {
                "role": "user",
                "content": prompt
            }
        ]
    )

    print(completion.choices[0].message.content)
    exit()



if __name__ == "__main__":
    articles = extract_from_malpedia()
    extract_from_linked_articles(articles)