import ipaddress
import re
from bs4 import BeautifulSoup
import socket
import requests
import whois
from datetime import date
from urllib.parse import urlparse
import pandas as pd
from pathlib import Path

# Baca file top domain dan simpan dalam set
csv_path = Path(__file__).resolve().parent.parent / "assets" / "top-1m_new.csv"
tranco_df = pd.read_csv(csv_path, header=None, names=["rank", "domain"])
top_domains = set(tranco_df["domain"].str.strip().str.lower())

class FeatureExtraction:
    def __init__(self, url):
        self.url = url
        self.features = []
        self.domain = ""
        self.response = ""
        self.soup = ""
        self.whois_response = ""

        # Ambil halaman website
        try:
            # headers = {'User-Agent': 'Mozilla/5.0'}
            # self.response = requests.get(url, headers=headers, timeout=10)
            # self.soup = BeautifulSoup(self.response.text, 'html.parser')
            self.soup, self.response = safe_fetch(url)
            if not self.soup or not self.response:
                print("[INFO] Halaman gagal diambil, fitur mungkin tidak lengkap.")  
        except Exception as e:
            print("[ERROR saat mengambil halaman]:", e)

        # Ambil domain dari URL
        try:
            parsed = urlparse(url)
            self.domain = parsed.netloc
            self.scheme = parsed.scheme
        except Exception as e:
            print("[ERROR saat parsing URL]:", e)

        # Ambil data WHOIS
        try:
            self.whois_response = whois.whois(self.domain)
        except Exception as e:
            print("[ERROR saat WHOIS]:", e)

        # Jalankan semua fungsi fitur
        self.features = [
            self.using_ip(),
            self.long_url(),
            self.short_url(), 
            self.symbol(), 
            self.redirecting(), 
            self.prefix_suffix(),
            self.sub_domains(),
            self.uses_https(),
            self.domain_reg_len(), 
            self.valid_favicon(), 
            self.non_std_port(), 
            self.https_domain_url(), 
           
            self.request_url(),
            self.anchor_url(),
            self.links_in_script_tags(),
            self.server_form_handler(),
            self.info_email(), 
            self.abnormal_url(),
           
            self.website_forwading(),
            self.status_bar_cust(), 
            self.disables_right_click(), 
            self.uses_popup_window(), 
            self.iframe_redirection(), 
           
            self.age_of_domain(),
            self.dns_recording(), 
            self.website_traffic(),
            self.google_index(),
            self.link_pointing_to_page(),
            self.stats_report(),
        ]

        print(f"[INFO] Jumlah fitur mencurigakan (-1): {self.features.count(-1)} dari {len(self.features)} fitur")

    def using_ip(self): 
        try:
            ipaddress.ip_address(self.url)
            return -1
        except:
            return 1

    def long_url(self): 
        if len(self.url) < 54:
            return 1
        elif len(self.url) <= 75:
            return 0
        return -1

    def short_url(self): 
        return -1 if re.search(r"(bit\.ly|goo\.gl|tinyurl\.com|t\.co|ow\.ly|is\.gd|adf\.ly)", self.url) else 1

    def symbol(self): 
        return -1 if "@" in self.url else 1

    def redirecting(self): 
        return -1 if self.url.rfind('//') > 6 else 1

    def prefix_suffix(self):
        return -1 if '-' in self.domain else 1

    def sub_domains(self): 
        dots = self.domain.count('.')
        return 1 if dots == 1 else 0 if dots == 2 else -1

    def uses_https(self):
        if self.scheme == 'https':
            return 1
        elif self.scheme == 'http':
            return -1
        return 0

    def domain_reg_len(self):
        try:
            exp, cre = self.whois_response.expiration_date, self.whois_response.creation_date
            if isinstance(exp, list): exp = exp[0]
            if isinstance(cre, list): cre = cre[0]
            age = (exp.year - cre.year) * 12 + (exp.month - cre.month)
            return 1 if age >= 12 else 0 if age >= 6 else -1
        except:
            return -1

    def valid_favicon(self):
        try:
            for link in self.soup.find_all('link', href=True):
                if self.domain in link['href'] or self.url in link['href']:
                    return 1
            return -1
        except:
            return -1

    def non_std_port(self):
        return -1 if ':' in self.domain else 1

    def https_domain_url(self):
        return -1 if 'https' in self.domain else 1

    def request_url(self):
        try:
            total, valid = 0, 0
            for tag in ['img', 'audio', 'embed', 'iframe']:
                for el in self.soup.find_all(tag, src=True):
                    total += 1
                    if self.domain in el['src'] or self.url in el['src']:
                        valid += 1
            percentage = valid / total * 100 if total else 0
            return 1 if percentage < 22 else 0 if percentage < 61 else -1
        except:
            return -1

    def anchor_url(self):
        try:
            total, unsafe = 0, 0
            for a in self.soup.find_all('a', href=True):
                href = a['href'].lower()
                if '#' in href or 'javascript' in href or 'mailto' in href or self.domain not in href:
                    unsafe += 1
                total += 1
            percentage = unsafe / total * 100 if total else 0
            return 1 if percentage < 31 else 0 if percentage < 67 else -1
        except:
            return -1

    def links_in_script_tags(self):
        try:
            total, valid = 0, 0
            for tag, attr in [('link', 'href'), ('script', 'src')]:
                for el in self.soup.find_all(tag, **{attr: True}):
                    total += 1
                    if self.domain in el[attr] or self.url in el[attr]:
                        valid += 1
            percentage = valid / total * 100 if total else 0
            return 1 if percentage < 17 else 0 if percentage < 81 else -1
        except:
            return -1

    def server_form_handler(self):
        try:
            forms = self.soup.find_all('form', action=True)
            if not forms:
                return 1
            for form in forms:
                action = form['action']
                if action in ["", "about:blank"]:
                    return -1
                elif self.domain not in action:
                    return 0
            return 1
        except:
            return -1

    def info_email(self):
        try:
            return -1 if re.search(r"mailto:|mail\(", self.response.text) else 1
        except:
            return -1
        
    def abnormal_url(self):
        try:
            whois_data = str(self.whois_response)
            if not self.domain.split('.')[0].lower() in whois_data.lower():
                return -1
            return 1
        except:
            return -1

    def website_forwading(self):
        try:
            hops = len(self.response.history)
            return 1 if hops <= 1 else 0 if hops <= 4 else -1
        except:
            return -1

    def status_bar_cust(self):
        try:
            return -1 if re.search("onmouseover", self.response.text) else 1
        except:
            return -1

    def disables_right_click(self):
        try:
            return -1 if re.search("event.button ?== ?2", self.response.text) else 1
        except:
            return -1

    def uses_popup_window(self):
        try:
            return -1 if re.search("alert\\(", self.response.text) else 1
        except:
            return -1

    def iframe_redirection(self):
        try:
            return -1 if re.search("<iframe|frameborder", self.response.text, re.IGNORECASE) else 1
        except:
            return -1

    def age_of_domain(self):
        try:
            creation = self.whois_response.creation_date
            if isinstance(creation, list): creation = creation[0]
            age = (date.today().year - creation.year) * 12 + (date.today().month - creation.month)
            return 1 if age >= 6 else 0 if age >= 3 else -1
        except:
            return -1


    def dns_recording(self):
        try:
            return 1 if self.whois_response else -1
        except:
            return -1
   
    # def is_in_top_domains(self):
    #     try:
    #         root = get_root_domain(self.domain)
    #         rank_row = tranco_df[tranco_df['domain'] == root]
    #         if not rank_row.empty:
    #             rank_val = rank_row.iloc[0]['rank']
    #             if rank_val <= 10000:
    #                 return 1
    #             elif rank_val <= 100000:
    #                 return 0
    #             else:
    #                 return -1
    #         return -1
    #     except:
    #         return -1
    def website_traffic(self):
        try:
            domain_parts = self.domain.lower().split('.')
            if len(domain_parts) > 2:
                root_domain = '.'.join(domain_parts[-2:])
            else:
                root_domain = self.domain.lower()

            if root_domain in top_domains:
                return 1
            else:
                return -1
        except:
            return -1


    # def is_indexed_by_google(self):
    #     try:
    #         site = search(self.url, 5)
    #         if site:
    #             return 1
    #         else:
    #             return -1
    #     except:
    #         return 1
    def google_index(self):
        try:
            # Fokus ke root domain
            root = '.'.join(self.domain.split('.')[-2:])

            # Cari di list Tranco
            rank_row = tranco_df[tranco_df['domain'] == root]
            if not rank_row.empty:
                rank_val = rank_row.iloc[0]['rank']
                if rank_val <= 100000:  # Masuk Top 100k
                    return 1
            return -1
        except:
            return -1

    def link_pointing_to_page(self):
        try:
            count = len(re.findall(r"<a href=", self.response.text))
            return 1 if count == 0 else 0 if count <= 2 else -1
        except:
            return -1

    def stats_report(self):
        try:
            # 1. Cek domain mencurigakan lewat pola nama
            blacklist_domain = re.search(r'(at\.ua|usa\.cc|pe\.hu|esy\.es|hol\.es|ow\.ly|ml|cf|gq|ga|tk|xyz|top|online|site|club|cn|ru)', self.url)
            
            # 2. Resolve IP domain
            ip = socket.gethostbyname(self.domain)
            blacklist_ip = re.search(r'(146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88)', ip)

            # 3. Cek apakah domain ini masuk Tranco Top 100k
            root = '.'.join(self.domain.split('.')[-2:])
            rank_row = tranco_df[tranco_df['domain'] == root]
            is_low_traffic = True
            if not rank_row.empty:
                rank_val = rank_row.iloc[0]['rank']
                if rank_val <= 100000:
                    is_low_traffic = False

            # 4. Gabungan keputusan
            if blacklist_domain or blacklist_ip or is_low_traffic:
                return -1
            return 1
        except:
            return -1

    def get_features(self):
        return self.features
    

def safe_fetch(url):
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                   (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
        }
        response = requests.get(
            url,
            headers=headers,
            timeout=10,
            allow_redirects=True,
            verify=True
        )
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            return soup, response
        else:
            print(f"[SKIP] {url} - status code:", response.status_code)
            return None, None
    except requests.exceptions.RequestException as e:
        print(f"[ERROR FETCH] {url} → {e}")
        return None, None
    