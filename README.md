# Projet Mastercamp 2025 – Analyse des Avis et Alertes ANSSI avec Enrichissement des CVE

## Objectif du projet

Ce projet vise à :
- Extraire automatiquement les bulletins de sécurité (avis et alertes) publiés par l’ANSSI via leur flux RSS.
- Identifier les vulnérabilités mentionnées (CVE) dans ces bulletins.
- Enrichir ces CVE avec des données supplémentaires issues des API MITRE (CVSS, CWE) et FIRST (EPSS).
- Consolider les informations dans un fichier CSV.
- Réaliser une analyse exploratoire et des visualisations pertinentes.
- Implémenter des modèles de Machine Learning (supervisé et non supervisé).
- Générer des alertes personnalisées et envoyer des notifications email.

---

## Structure du projet
projet/
├── data_pour_TD_final/
│   └── fichiers_json/        # Données statiques ANSSI/API si fournies
├── mastercamp.ipynb  # Notebook principal
├── mastercamp.py
├── consolidated_anssi_cve.csv          # Données finales consolidées
├── demo_video.mp4        # Démonstration vidéo (sans voix)
├── README.md                 # Ce fichier
└── contributions.txt          # Participations