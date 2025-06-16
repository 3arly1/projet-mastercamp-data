# Projet Mastercamp 2025 - Analyse des Avis et Alertes ANSSI avec Enrichissement des CVE
# Auteur: Équipe Mastercamp
# Fichier principal: project_mastercamp.py

import time
import re
import feedparser
import requests
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.cluster import KMeans
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import smtplib
from email.mime.text import MIMEText

# Configuration
gmail_user = "votre_email@gmail.com"
gmail_password = "mot_de_passe_application"

# Étape 1: Extraction des flux RSS ANSSI
def fetch_rss_entries(url: str):
    feed = feedparser.parse(url)
    entries = []
    for entry in getattr(feed, 'entries', []):
        # Normaliser link en str
        raw_link = entry.get('link', '') if isinstance(entry, dict) else getattr(entry, 'link', '')
        if isinstance(raw_link, list):
            link = raw_link[0] if raw_link else ''
        else:
            link = str(raw_link)

        # Extraire l’ID bulletin
        m = re.search(r"CERTFR-[\d-]+", link)
        bulletin_id = m.group(0) if m else None

        entries.append({
            'bulletin_id': bulletin_id,
            'title': str(entry.get('title', '')),
            'description': str(entry.get('description', '')),
            'link': link,
            'published': str(entry.get('published', ''))
        })
    return pd.DataFrame(entries)

# Étape 2: Extraction des CVE depuis JSON
cve_pattern = r"CVE-\d{4}-\d{4,7}"
def extract_cves_from_entry(entry_link: str):
    json_url = entry_link.rstrip('/') + '/json/'
    resp = requests.get(json_url)
    if resp.status_code != 200:
        return []
    data = resp.json()
    # extraction via liste data["cves"] or regex fallback
    cves = []
    if 'cves' in data:
        cves = [c['name'] for c in data['cves']]
    else:
        cves = list(set(re.findall(cve_pattern, str(data))))
    return cves

# Étape 3: Enrichissement des CVE via MITRE et FIRST

def enrich_cve_mitre(cve_id: str):
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    resp = requests.get(url)
    if resp.status_code != 200:
        return {}
    data = resp.json()
    # extraire description et métriques
    info = {}
    cna = data.get('containers', {}).get('cna', {})
    info['description'] = cna.get('descriptions', [{}])[0].get('value', '')
    metrics = data.get('containers', {}).get('cna', {}).get('metrics', [])
    # cvssV3_1 ou cvssV3_0
    for m in metrics:
        for key in ('cvssV3_1', 'cvssV3_0'):
            if key in m:
                info['cvss_score'] = m[key].get('baseScore')
                info['base_severity'] = m[key].get('baseSeverity')
                break
    problem = cna.get('problemTypes', [{}])[0].get('descriptions', [{}])[0]
    info['cwe_id'] = problem.get('cweId')
    info['cwe_desc'] = problem.get('description')
    # affected products
    affected = []
    for prod in cna.get('affected', []):
        vendor = prod.get('vendor')
        name = prod.get('product')
        versions = [v['version'] for v in prod.get('versions', []) if v.get('status')=='affected']
        affected.append({'vendor': vendor, 'product': name, 'versions': versions})
    info['affected'] = affected
    return info


def enrich_cve_epss(cve_id: str):
    url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    resp = requests.get(url)
    if resp.status_code != 200:
        return None
    data = resp.json().get('data', [])
    if data:
        return data[0].get('epss')
    return None

# Étape 4: Consolidation des données

def build_consolidated_df(rss_df: pd.DataFrame):
    rows = []
    for idx, row in rss_df.iterrows():
        cve_list = extract_cves_from_entry(row['link'])
        for cve in cve_list:
            info = enrich_cve_mitre(cve)
            epss = enrich_cve_epss(cve)
            rows.append({
                'bulletin_id': row['bulletin_id'],
                'title': row['title'],
                'type': 'Alerte' if 'ALERTE' in row['link'].upper() else 'Avis',
                'published': row['published'],
                'cve_id': cve,
                'cvss_score': info.get('cvss_score'),
                'base_severity': info.get('base_severity'),
                'cwe_id': info.get('cwe_id'),
                'cwe_desc': info.get('cwe_desc'),
                'epss_score': epss,
                'link': row['link'],
                'description': info.get('description'),
                'affected': info.get('affected', [])
            })
            print("Traitement CVE:", cve, "Bulletin:", row['bulletin_id'])
            time.sleep(2)  # rate limiting
    df = pd.DataFrame(rows)
    # normaliser liste affected
    df_exp = df.explode('affected')
    df_exp['vendor'] = df_exp['affected'].apply(lambda x: x['vendor'] if isinstance(x, dict) else None)
    df_exp['product'] = df_exp['affected'].apply(lambda x: x['product'] if isinstance(x, dict) else None)
    df_exp['versions'] = df_exp['affected'].apply(lambda x: ','.join(x['versions']) if isinstance(x, dict) else None)
    df_exp = df_exp.drop(columns=['affected'])
    return df_exp

# Étape 5: Visualisation

def visualize_data(df: pd.DataFrame):
    # Histogramme CVSS
    plt.figure()
    df['cvss_score'].dropna().astype(float).hist()
    plt.title('Distribution des scores CVSS')
    plt.xlabel('CVSS')
    plt.ylabel('Nombre')
    plt.show()
    # ... autres visualisations ...

# Étape 6: ML Models

def train_ml_models(df: pd.DataFrame):
    # Préparation: classification supervised: severity critique (>7) vs non
    df_ml = df.dropna(subset=['cvss_score', 'epss_score'])
    df_ml['label'] = (df_ml['cvss_score'] >= 7).astype(int)
    X = df_ml[['cvss_score', 'epss_score']]
    y = df_ml['label']
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
    clf = RandomForestClassifier()
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)
    print(classification_report(y_test, y_pred))
    # Unsupervised: clustering
    km = KMeans(n_clusters=3)
    df_ml['cluster'] = km.fit_predict(X)
    return clf, km

# Étape 7: Génération d'alertes et notifications email

def send_email(to_email: str, subject: str, body: str):
    msg = MIMEText(body)
    msg['From'] = gmail_user
    msg['To'] = to_email
    msg['Subject'] = subject
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(gmail_user, gmail_password)
    server.sendmail(gmail_user, to_email, msg.as_string())
    server.quit()

if __name__ == '__main__':
    # Extraction
    rss_url_avis = 'https://www.cert.ssi.gouv.fr/avis/feed'
    rss_url_alertes = 'https://www.cert.ssi.gouv.fr/alerte/feed'
    df_avis = fetch_rss_entries(rss_url_avis)
    df_alertes = fetch_rss_entries(rss_url_alertes)
    rss_df = pd.concat([df_avis, df_alertes], ignore_index=True)
    # Consolidation
    consolidated_df = build_consolidated_df(rss_df)
    consolidated_df.to_csv('consolide_cve.csv', index=False)
    print('CSV consolidé généré: consolide_cve.csv')
    # Visualisation
    visualize_data(consolidated_df)
    # ML
    train_ml_models(consolidated_df)
    # Exemple d'alerte
    criticals = consolidated_df[consolidated_df['base_severity'].isin(['Critical', 'Critique'])]
    for _, row in criticals.iterrows():
        body = f"Alerte critique: {row['cve_id']} - {row['description']}"
        send_email('destinataire@email.com', 'Alerte CVE critique', body)
