import requests
import time
import smtplib
from email.mime.text import MIMEText

# Configuration for email notifications
EMAIL_SENDER = 'your-email@gmail.com'
EMAIL_PASSWORD = 'your-email-password'
EMAIL_RECEIVER = 'receiver-email@gmail.com'

# Function to send email notification
def send_email_notification(url, details):
    subject = f"Phishing Alert: URL flagged as malicious - {url}"
    body = f"URL: {url}\n\nDetails:\n{details}"
    
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = EMAIL_SENDER
    msg['To'] = EMAIL_RECEIVER
    
    # Send the email
    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
        server.login(EMAIL_SENDER, EMAIL_PASSWORD)
        server.sendmail(EMAIL_SENDER, EMAIL_RECEIVER, msg.as_string())

# Function to check if a URL is flagged by VirusTotal
def check_virustotal(url, api_key):
    base_url = "https://www.virustotal.com/vtapi/v2/url/report"
    params = {'apikey': api_key, 'resource': url}
    response = requests.get(base_url, params=params)
    
    if response.status_code == 200:
        result = response.json()
        if result['response_code'] == 1:
            positives, total = result['positives'], result['total']
            return positives, total
        else:
            return None
    else:
        print(f"Error fetching data from VirusTotal: {response.status_code}")
        return None

# Function to check if a URL is flagged by Google Safe Browsing
def check_google_safebrowsing(url, api_key):
    base_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    headers = {'Content-Type': 'application/json'}
    body = {
        "client": {
            "clientId": "yourcompanyname",
            "clientVersion": "1.5.2"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": url}
            ]
        }
    }
    response = requests.post(base_url, headers=headers, json=body, params={'key': api_key})
    
    if response.status_code == 200:
        result = response.json()
        if 'matches' in result:
            return True
        else:
            return False
    else:
        print(f"Error fetching data from Google Safe Browsing: {response.status_code}")
        return False

# Function to check PhishTank
def check_phishtank(url, api_key):
    base_url = f"https://checkurl.phishtank.com/checkurl/"
    headers = {'Content-Type': 'application/json'}
    params = {
        'format': 'json',
        'url': url,
        'app_key': api_key
    }
    response = requests.post(base_url, headers=headers, params=params)
    
    if response.status_code == 200:
        result = response.json()
        if result['results']['in_database']:
            if result['results']['valid']:
                return True
        return False
    else:
        print(f"Error fetching data from PhishTank: {response.status_code}")
        return False

# Function to check Web of Trust (WOT)
def check_wot(url, api_key):
    base_url = f"https://api.mywot.com/0.4/public_link_json2"
    params = {
        'hosts': f"{url}/",
        'key': api_key
    }
    response = requests.get(base_url, params=params)
    
    if response.status_code == 200:
        result = response.json()
        if url in result:
            # Assuming we flag URLs with a WOT reputation score below 60
            reputation = result[url]['0'][0]  # Trustworthiness score
            if reputation < 60:
                return True
        return False
    else:
        print(f"Error fetching data from Web of Trust: {response.status_code}")
        return False

# Monitor and detect phishing URLs
def monitor_urls(url_list, virustotal_api_key, google_api_key, phishtank_api_key, wot_api_key, interval=300):
    log_file = "phishing_scan_log.txt"

    while True:
        with open(log_file, 'a') as log:
            for url in url_list:
                details = f"Checking URL: {url}\n"
                print(details)
                log.write(details)

                # Check VirusTotal
                virustotal_result = check_virustotal(url, virustotal_api_key)
                if virustotal_result:
                    positives, total = virustotal_result
                    result = f"VirusTotal: {positives}/{total} detections for {url}\n"
                    print(result)
                    log.write(result)
                    if positives > 0:
                        send_email_notification(url, result)

                # Check Google Safe Browsing
                safebrowsing_result = check_google_safebrowsing(url, google_api_key)
                if safebrowsing_result:
                    result = f"Google Safe Browsing: {url} flagged as malicious.\n"
                    print(result)
                    log.write(result)
                    send_email_notification(url, result)

                # Check PhishTank
                phishtank_result = check_phishtank(url, phishtank_api_key)
                if phishtank_result:
                    result = f"PhishTank: {url} flagged as a phishing site.\n"
                    print(result)
                    log.write(result)
                    send_email_notification(url, result)

                # Check Web of Trust
                wot_result = check_wot(url, wot_api_key)
                if wot_result:
                    result = f"Web of Trust: {url} has a low trustworthiness score.\n"
                    print(result)
                    log.write(result)
                    send_email_notification(url, result)

            print(f"Sleeping for {interval} seconds...\n")
            log.write(f"Sleeping for {interval} seconds...\n")
            time.sleep(interval)

# Example usage
url_list = [
    "http://example.com", 
    "http://suspicious-site.com"
]

virustotal_api_key = "YOUR_VIRUSTOTAL_API_KEY"
google_api_key = "YOUR_GOOGLE_SAFE_BROWSING_API_KEY"
phishtank_api_key = "YOUR_PHISHTANK_API_KEY"
wot_api_key = "YOUR_WOT_API_KEY"

monitor_urls(url_list, virustotal_api_key, google_api_key, phishtank_api_key, wot_api_key)
