import os
import feedparser
import requests
import re
import pandas as pd
import time
import smtplib
from email.mime.text import MIMEText
from typing import List, Dict, Any
from dateutil import parser as dateparser
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


def consolidate_data(seen_cves=None):
    print("Consolidation des données dans le DataFrame...")
    bulletins = extract_anssi_feeds()

    # Conversion des dates texte en objets datetime
    for b in bulletins:
        try:
            b["parsed_date"] = dateparser.parse(b["date"])
        except Exception as e:
            print(f"Erreur lors du parsing de la date pour le bulletin {b['id_anssi']}: {e}")
            b["parsed_date"] = None

    # Filtrage et tri chronologique (plus récent d'abord)
    valid_bulletins = [b for b in bulletins if b["parsed_date"] is not None]
    valid_bulletins.sort(key=lambda b: b["parsed_date"], reverse=True)

    all_rows = []
    stop_avis = False
    stop_alerte = False

    for i, bulletin in enumerate(valid_bulletins, 1):
        btype = bulletin['type']
        # Skip if this category is already completed
        if btype == 'Avis' and stop_avis:
            continue
        if btype == 'Alerte' and stop_alerte:
            continue

        print(f"Traitement du bulletin {i}/{len(valid_bulletins)} : {bulletin['id_anssi']} ({btype})")
        cves = extract_cves_from_bulletin(bulletin)

        for j, cve_entry in enumerate(cves, 1):
            cve_id = cve_entry["cve"]
            if seen_cves is not None and cve_id in seen_cves:
                print(f"  CVE déjà présente dans {btype}, arrêt des {btype.lower()}...")
                # Mark stop for this category and break inner loop
                if btype == 'Avis':
                    stop_avis = True
                else:
                    stop_alerte = True
                break
            print(f"  Traitement de la CVE {j}/{len(cves)} pour ce bulletin...")
            cve_info = enrich_cve(cve_id)
            row = {
                "ID ANSSI": bulletin["id_anssi"],
                "Titre ANSSI": bulletin["titre_anssi"],
                "Type": btype,
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

        # Si les deux catégories sont terminées, on peut sortir complètement
        if stop_avis and stop_alerte:
            break

    print(f"\033[91mNombre total de lignes consolidées : {len(all_rows)}\033[0m")
    df = pd.DataFrame(all_rows)

    if os.path.exists(CSV_OUTPUT):
        df_old = pd.read_csv(CSV_OUTPUT)
        df = pd.concat([df_old, df], ignore_index=True).drop_duplicates(subset=["CVE"])

    df.to_csv(CSV_OUTPUT, index=False)
    print(f"CSV consolidé écrit dans {CSV_OUTPUT}")
    return df


def send_email(to_email, subject, body):
    from_email = "laerec.agency@gmail.com"
    password = "lgdy gwxl eyvr zlzc"
    msg = MIMEText(body)
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(from_email, password)
        server.send_message(msg)
        server.quit()
    except smtplib.SMTPAuthenticationError as e:
        print(f"Erreur d'authentification SMTP : {e}. Vérifiez l'adresse email et le mot de passe (utilisez un App Password si 2FA est activée).")
    except Exception as e:
        print(f"Erreur lors de l'envoi de l'email : {e}")

def generate_alerts_and_notify(df: pd.DataFrame, user_email: str, keywords: list):
    """
    For each new CVE, check if any keyword appears in the bulletin title, description, or product.
    If yes, send an alert to the user's email with all useful information.
    """
    if df.empty or not keywords:
        return
    keywords_lower = [k.lower() for k in keywords]
    for _, row in df.iterrows():
        text_to_search = f"{row.get('Titre ANSSI','')} {row.get('Description','')} {row.get('Produit','')}".lower()
        if any(kw in text_to_search for kw in keywords_lower):
            subject = f"Alerte ANSSI: {row.get('Titre ANSSI','')}"
            body = (
                f"Type: {row.get('Type','')}\n"
                f"Date: {row.get('Date','')}\n"
                f"ID ANSSI: {row.get('ID ANSSI','')}\n"
                f"CVE: {row.get('CVE','')}\n"
                f"Score CVSS: {row.get('CVSS','')}\n"
                f"Base Severity: {row.get('Base Severity','')}\n"
                f"CWE: {row.get('CWE','')}\n"
                f"CWE Description: {row.get('CWE Description','')}\n"
                f"EPSS: {row.get('EPSS','')}\n"
                f"Éditeur: {row.get('Éditeur','')}\n"
                f"Produit: {row.get('Produit','')}\n"
                f"Versions affectées: {row.get('Versions affectées','')}\n"
                f"Lien: {row.get('Lien','')}\n"
                f"Description: {row.get('Description','')}\n"
            )
            send_email(user_email, subject, body)
            print(f"Envoi d'une alerte à {user_email} pour {row.get('ID ANSSI','')}")


if __name__ == "__main__":
    print("Démarrage de la surveillance continue des flux ANSSI...")
    while True:
        print("\033[94miteration on the loop\033[0m")
        try:
            if os.path.exists(CSV_OUTPUT):
                print(f"Fichier CSV existant trouvé : {CSV_OUTPUT}")
                df_existing = pd.read_csv(CSV_OUTPUT)
                seen_cves = set(df_existing['CVE'].unique())
            else:
                seen_cves = set()
            df = consolidate_data(seen_cves=seen_cves)
            new_cves = set(df['CVE'].unique())
            if seen_cves:
                new_entries = new_cves - seen_cves
                if new_entries:
                    print(f"Nouvelles CVE détectées : {new_entries}")
                    generate_alerts_and_notify(df[df['CVE'].isin(new_entries)], "maxime.musquin@efrei.net", ["vulnérabilité", "sécurité", "exploit", "attaque", "faille", "CVE", "vulnerability", "security", "exploit", "attack", "flaw"])
        except Exception as e:
            print(f"Erreur lors de la consolidation des données : {e}")
        print("Attente de 60 secondes avant la prochaine itération...")
        time.sleep(60)
