import feedparser
import requests
import re
import pandas as pd
import time
import smtplib
from email.mime.text import MIMEText
from typing import List, Dict, Any
import os
import json

# --- CONFIGURATION ---
ANSSI_FEEDS = [
    ("Avis", "https://www.cert.ssi.gouv.fr/avis/feed/"),
    ("Alerte", "https://www.cert.ssi.gouv.fr/alerte/feed/")
]
RATE_LIMIT_SECONDS = 2
CSV_OUTPUT = "consolidated_anssi_cve.csv"

# --- STEP 1: Extract ANSSI RSS Feeds ---
def extract_anssi_feeds() -> List[Dict[str, Any]]:
    bulletins = []
    for bulletin_type, url in ANSSI_FEEDS:
        print(f"Extraction du flux RSS pour {bulletin_type} depuis {url}...")
        feed = feedparser.parse(url)
        for entry in feed.entries:
            # Robust extraction of ANSSI ID from link or id
            link = str(getattr(entry, 'link', ''))
            id_anssi = ''
            if link:
                parts = link.rstrip('/').split('/')
                if len(parts) > 1:
                    id_anssi = parts[-1] if parts[-1] else parts[-2]
            if not id_anssi and hasattr(entry, 'id'):
                id_anssi = str(entry.id)
            bulletins.append({
                "id_anssi": id_anssi,
                "titre_anssi": entry.title,
                "type": bulletin_type,
                "date": entry.published,
                "link": link
            })
    print(f"Nombre total de bulletins extraits : {len(bulletins)}")
    return bulletins

# --- STEP 2: Extract CVEs from ANSSI bulletin web page ---
def extract_cves_from_bulletin(bulletin: Dict[str, Any]) -> List[Dict[str, Any]]:
    print(f"Extraction des CVE depuis le bulletin : {bulletin['id_anssi']} ({bulletin['titre_anssi']})")
    cve_list = []
    try:
        # Download the bulletin web page
        response = requests.get(bulletin["link"], timeout=10)
        html = response.text
        # Extract CVE identifiers using regex
        cve_pattern = r"CVE-\d{4}-\d{4,7}"  # FIXED: single backslash for regex
        cve_list = list(set(re.findall(cve_pattern, html)))
        print(f"Nombre de CVE trouvés : {len(cve_list)}")
        return [{"cve": cve, "html": html} for cve in cve_list]
    except Exception as e:
        print(f"Erreur lors de l'extraction des CVE depuis la page web: {e}")
        return []

# --- STEP 3: Enrich CVE with MITRE and EPSS APIs ---
def enrich_cve(cve_id: str) -> Dict[str, Any]:
    print(f"Enrichissement des données pour la CVE : {cve_id}")
    # MITRE CVE API
    mitre_url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    cve_info = {
        "cvss": None, "base_severity": None, "cwe": None, "cwe_desc": None,
        "description": None, "vendor": None, "product": None, "versions": ""
    }
    try:
        r = requests.get(mitre_url, timeout=10)
        data = r.json()
        cna = data["containers"]["cna"]
        cve_info["description"] = cna["descriptions"][0]["value"] if cna.get("descriptions") else None
        # CVSS
        metrics = cna.get("metrics", [])
        if metrics:
            for metric in metrics:
                for key in metric:
                    if key.startswith("cvssV3"):
                        cve_info["cvss"] = metric[key].get("baseScore")
                        cve_info["base_severity"] = metric[key].get("baseSeverity")
        # CWE
        problemtype = cna.get("problemTypes", [])
        if problemtype and "descriptions" in problemtype[0]:
            cve_info["cwe"] = problemtype[0]["descriptions"][0].get("cweId", "Non disponible")
            cve_info["cwe_desc"] = problemtype[0]["descriptions"][0].get("description", "Non disponible")
        # Vendor/Product/Versions
        affected = cna.get("affected", [])
        if affected:
            cve_info["vendor"] = affected[0].get("vendor")
            cve_info["product"] = affected[0].get("product")
            versions = [v["version"] for v in affected[0].get("versions", []) if v.get("status") == "affected"]
            cve_info["versions"] = ", ".join(versions) if versions else ""
    except Exception as e:
        print(f"Erreur enrichissement MITRE pour {cve_id}: {e}")
    # EPSS API
    epss_url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    try:
        r = requests.get(epss_url, timeout=10)
        data = r.json()
        epss_data = data.get("data", [])
        cve_info["epss"] = epss_data[0]["epss"] if epss_data else None
    except Exception as e:
        print(f"Erreur enrichissement EPSS pour {cve_id}: {e}")
        cve_info["epss"] = None
    print(f"Enrichissement terminé pour {cve_id}")
    return cve_info

# --- STEP 4: Consolidate Data ---
def consolidate_data():
    print("Consolidation des données dans le DataFrame...")
    bulletins = extract_anssi_feeds()
    all_rows = []
    for i, bulletin in enumerate(bulletins, 1):
        print(f"Traitement du bulletin {i}/{len(bulletins)} : {bulletin['id_anssi']}")
        cves = extract_cves_from_bulletin(bulletin)
        for j, cve_entry in enumerate(cves, 1):
            print(f"  Traitement de la CVE {j}/{len(cves)} pour ce bulletin...")
            cve_id = cve_entry["cve"]
            cve_info = enrich_cve(cve_id)
            row = {
                "ID ANSSI": bulletin["id_anssi"],
                "Titre ANSSI": bulletin["titre_anssi"],
                "Type": bulletin["type"],
                "Date": bulletin["date"],
                "CVE": cve_id,
                "CVSS": cve_info["cvss"],
                "Base Severity": cve_info["base_severity"],
                "CWE": cve_info["cwe"],
                "CWE Description": cve_info["cwe_desc"],
                "EPSS": cve_info["epss"],
                "Lien": bulletin["link"],
                "Description": cve_info["description"],
                "Éditeur": cve_info["vendor"],
                "Produit": cve_info["product"],
                "Versions affectées": cve_info["versions"]
            }
            all_rows.append(row)
            time.sleep(RATE_LIMIT_SECONDS)
    print(f"Nombre total de lignes consolidées : {len(all_rows)}")
    df = pd.DataFrame(all_rows)
    df.to_csv(CSV_OUTPUT, index=False)
    print(f"CSV consolidé écrit dans {CSV_OUTPUT}")
    return df

# --- STEP 6: Alert Generation and Email Notification ---
def send_email(to_email, subject, body):
    from_email = "votre_email@gmail.com"
    password = "mot_de_passe_application"
    msg = MIMEText(body)
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(from_email, password)
    server.sendmail(from_email, to_email, msg.as_string())
    server.quit()

def generate_alerts_and_notify(df: pd.DataFrame, product_filter: str, email: str):
    critical = df[(df['Base Severity'] == 'Critical') & (df['Produit'].str.contains(product_filter, na=False))]
    if not critical.empty:
        for _, row in critical.iterrows():
            subject = f"Alerte CVE critique: {row['Produit']}"
            body = f"CVE: {row['CVE']}\nDescription: {row['Description']}\nScore CVSS: {row['CVSS']}\nLien: {row['Lien']}"
            send_email(email, subject, body)
            print(f"Envoi d'une alerte pour {row['Produit']} à {email}")


# --- STEP X: Extract CVEs from local 'first' folder ---
def extract_first_local(folder_path: str) -> pd.DataFrame:
    print(f"Extraction des CVE depuis le dossier 'first' : {folder_path}")
    records = []
    for fname in os.listdir(folder_path):
        fpath = os.path.join(folder_path, fname)
        if os.path.isfile(fpath):
            with open(fpath, 'r') as f:
                try:
                    data = json.load(f)
                    for entry in data.get('data', []):
                        entry['source'] = 'first'
                        records.append(entry)
                except Exception as e:
                    print(f"Erreur lecture {fpath}: {e}")
    print(f"Nombre de CVE extraits depuis 'first': {len(records)}")
    return pd.DataFrame(records)

# --- STEP X: Extract CVEs from local 'mitre' folder ---
def extract_mitre_local(folder_path: str) -> pd.DataFrame:
    print(f"Extraction des CVE depuis le dossier 'mitre' : {folder_path}")
    records = []
    for fname in os.listdir(folder_path):
        fpath = os.path.join(folder_path, fname)
        if os.path.isfile(fpath):
            with open(fpath, 'r') as f:
                try:
                    data = json.load(f)
                    meta = data.get('cveMetadata', {})
                    cna = data.get('containers', {}).get('cna', {})
                    record = {
                        'cve': meta.get('cveId'),
                        'state': meta.get('state'),
                        'datePublished': meta.get('datePublished'),
                        'description': cna.get('descriptions', [{}])[0].get('value'),
                        'vendor': cna.get('affected', [{}])[0].get('vendor'),
                        'product': cna.get('affected', [{}])[0].get('product'),
                        'source': 'mitre'
                    }
                    records.append(record)
                except Exception as e:
                    print(f"Erreur lecture {fpath}: {e}")
    print(f"Nombre de CVE extraits depuis 'mitre': {len(records)}")
    return pd.DataFrame(records)

# --- STEP X: Consolidate local enriched data (merge by CVE, keep all info) ---
def consolidate_local_enriched_data(df1: pd.DataFrame, df2: pd.DataFrame) -> pd.DataFrame:
    print("Fusion des données locales enrichies par CVE (structure complète)...")
    columns = [
        "ID ANSSI", "Titre ANSSI", "Type", "Date", "CVE", "CVSS", "Base Severity", "CWE", "CWE Description", "EPSS", "Lien", "Description", "Éditeur", "Produit", "Versions affectées"
    ]
    df = pd.concat([df1, df2], ignore_index=True)
    if 'cve' in df.columns:
        df['CVE'] = df['cve']
    all_rows = []
    for cve_id, group in df.groupby('CVE'):
        row = {col: '' for col in columns}
        row['CVE'] = str(cve_id) if cve_id is not None else ''
        for col in columns:
            values = group.get(col, pd.Series()).dropna().astype(str).replace('nan', '').replace('None', '').replace('', pd.NA).dropna().unique()
            if len(values) == 0:
                values = group.get(col.lower(), pd.Series()).dropna().astype(str).replace('nan', '').replace('None', '').replace('', pd.NA).dropna().unique()
            if len(values) > 0:
                row[col] = str(values[0]) if len(values) == 1 else ' | '.join([str(v) for v in values])
        if not row['EPSS']:
            values = group.get('epss', pd.Series()).dropna().astype(str).replace('nan', '').replace('None', '').replace('', pd.NA).dropna().unique()
            if len(values) > 0:
                row['EPSS'] = str(values[0]) if len(values) == 1 else ' | '.join([str(v) for v in values])
        if not row['Description']:
            values = group.get('description', pd.Series()).dropna().astype(str).replace('nan', '').replace('None', '').replace('', pd.NA).dropna().unique()
            if len(values) > 0:
                row['Description'] = str(values[0]) if len(values) == 1 else ' | '.join([str(v) for v in values])
        if not row['Éditeur']:
            values = group.get('vendor', pd.Series()).dropna().astype(str).replace('nan', '').replace('None', '').replace('', pd.NA).dropna().unique()
            if len(values) > 0:
                row['Éditeur'] = str(values[0]) if len(values) == 1 else ' | '.join([str(v) for v in values])
        if not row['Produit']:
            values = group.get('product', pd.Series()).dropna().astype(str).replace('nan', '').replace('None', '').replace('', pd.NA).dropna().unique()
            if len(values) > 0:
                row['Produit'] = str(values[0]) if len(values) == 1 else ' | '.join([str(v) for v in values])
        if not row['Versions affectées']:
            values = group.get('versions', pd.Series()).dropna().astype(str).replace('nan', '').replace('None', '').replace('', pd.NA).dropna().unique()
            if len(values) > 0:
                row['Versions affectées'] = str(values[0]) if len(values) == 1 else ' | '.join([str(v) for v in values])
        all_rows.append(row)
    print(f"Nombre total de CVE consolidés : {len(all_rows)}")
    df_final = pd.DataFrame(all_rows, columns=columns)
    return df_final

# --- STEP X: Main function to process local enriched data ---
def process_local_enriched_data(mitre_path: str, first_path: str) -> pd.DataFrame:
    print("--- Début du traitement des données CVE locales déjà enrichies ---")
    df_first = extract_first_local(first_path)
    df_mitre = extract_mitre_local(mitre_path)
    df = consolidate_local_enriched_data(df_first, df_mitre)
    print(f"Total CVEs consolidés: {len(df)}")
    print("--- Fin du traitement des données CVE locales déjà enrichies ---")
    return df


if __name__ == "__main__":
    # Utiliser la consolidation locale des données déjà enrichies à partir des dossiers mitre et first
    mitre_path = "./data_pour_TD_final/mitre"
    first_path = "./data_pour_TD_final/first"
    df = process_local_enriched_data(mitre_path, first_path)
    # Exemple d'alerte: notifier pour Apache
    # generate_alerts_and_notify(df, "Apache", "destinataire@email.com")
    print("Traitement terminé. Passez à l'analyse et la visualisation dans le notebook.")
