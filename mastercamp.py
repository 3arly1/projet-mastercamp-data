import feedparser
import requests
import re
import pandas as pd
import time
import smtplib
from email.mime.text import MIMEText
from typing import List, Dict, Any

# --- CONFIGURATION ---
ANSSI_FEEDS = [
    ("Avis", "https://www.cert.ssi.gouv.fr/avis/feed/"),
    ("Alerte", "https://www.cert.ssi.gouv.fr/alerte/feed/")
]
RATE_LIMIT_SECONDS = 2
CSV_OUTPUT = "consolidated_anssi_cve.csv"

def extract_anssi_feeds() -> List[Dict[str, Any]]:
    bulletins = []
    for bulletin_type, url in ANSSI_FEEDS:
        print(f"Extraction du flux RSS pour {bulletin_type} depuis {url}...")
        feed = feedparser.parse(url)
        for entry in feed.entries:
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

def extract_cves_from_bulletin(bulletin: Dict[str, Any]) -> List[Dict[str, Any]]:
    print(f"Extraction des CVE depuis le bulletin : {bulletin['id_anssi']} ({bulletin['titre_anssi']})")
    json_url = bulletin["link"].rstrip("/") + "/json/"
    try:
        response = requests.get(json_url, timeout=10)
        data = response.json()
        cves = data.get("cves", [])
        cve_list = [cve["name"] for cve in cves if "name" in cve]
        # Fallback: regex extraction
        if not cve_list:
            cve_pattern = r"CVE-\\d{4}-\\d{4,7}"
            cve_list = list(set(re.findall(cve_pattern, str(data))))
        print(f"Nombre de CVE trouvés : {len(cve_list)}")
        return [{"cve": cve, "json_data": data} for cve in cve_list]
    except Exception as e:
        print(f"Erreur lors de l'extraction du JSON: {json_url} - {e}")
        return []

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

if __name__ == "__main__":
    df = consolidate_data()
    print("Traitement terminé. Passez à l'analyse et la visualisation dans le notebook.")
