# Agent IA Génératif pour l'Analyse de Vulnérabilités et la Gestion des Risques

## ESILV PI2 Project

---

## Description

Ce projet développe un agent intelligent basé sur l'IA générative capable d'assister les analystes en cybersécurité dans:
- La compréhension des vulnérabilités (nature, criticité, impact métier)
- La priorisation selon le contexte
- La proposition de mesures de remédiation
- La génération automatique de rapports adaptés (exécutif et technique)

## Architecture

```
PI2/
├── src/
│   ├── parsers/        # Parseurs Nmap et Nessus
│   ├── enrichment/     # Enrichissement CVE/NVD et mapping MITRE ATT&CK
│   ├── dispatcher/     # Routage intelligent vers les modèles IA
│   ├── agent/          # Agent IA pour l'analyse
│   ├── reports/        # Générateurs de rapports
│   ├── models/         # Modèles de données
│   └── pipeline.py     # Pipeline principal
├── api/                # API REST (FastAPI)
│   └── main.py         # Endpoints API
├── frontend/           # Interface Web
│   ├── index.html      # Dashboard principal
│   ├── styles.css      # Styles (dark theme)
│   └── app.js          # Application JavaScript
├── config/             # Configuration
├── data/
│   ├── scans/         # Fichiers de scans (Nmap, Nessus)
│   └── reports/       # Rapports générés
├── tests/             # Tests unitaires
├── main.py            # Point d'entrée CLI
├── run_web.py         # Point d'entrée Web Interface
└── requirements.txt   # Dépendances
```

## Dispatcher (Routage Intelligent)

Le module de routage analyse la complexité de la tâche pour sélectionner le modèle le plus efficient:

| Type de Tâche | Complexité | Modèle Sélectionné | Raison |
|---------------|------------|-------------------|--------|
| Parsing Logs / Nmap | Simple | Phi-4 | Rapidité (~13 sec) |
| Analyse Nessus | Moyenne | Phi-4 | Bonne capacité de synthèse |
| Corrélation MITRE | Complexe | Mistral Small | Raisonnement contextuel fort |
| Génération Exploit/Script | Très Complexe | gpt-oss-20b | Spécialisation Code & Syntaxe |

## Installation

```bash
# Cloner le projet
cd PI2

# Installer les dépendances
pip install -r requirements.txt

# Installer Ollama (pour les modèles IA)
# https://ollama.ai/download

# Télécharger le modèle par défaut
ollama pull gpt-oss-20b
```

## Utilisation

### Interface Web (Recommandé)

L'interface web moderne permet de visualiser et gérer les vulnérabilités de manière interactive.

```bash
# Installer les dépendances web
pip install fastapi uvicorn[standard] python-multipart

# Lancer l'interface web
python run_web.py

# Ou sur Windows, double-cliquer sur:
run_web.bat
```

**Accès:**
- Interface Web: http://localhost:8000
- Documentation API: http://localhost:8000/docs

**Fonctionnalités de l'interface:**
- **Dashboard:** Vue d'ensemble avec score de risque, statistiques de sévérité
- **Vulnérabilités:** Liste filtrable et triable avec détails complets
- **Hosts:** Vue par hôte affecté
- **Scans:** Upload de fichiers Nmap/Nessus et lancement d'analyses
- **Rapports:** Génération de rapports exécutifs et techniques
- **MITRE ATT&CK:** Mapping visuel des tactiques et techniques

### Mode CLI - Démonstration

```bash
python main.py --demo
```

### Analyse Complète

```bash
# Analyse avec fichiers de scan
python main.py --nmap data/scans/scan.xml --nessus data/scans/scan.nessus --org "Nom Organisation"

# Avec analyse IA activée
python main.py --nmap scan.xml --ai --model mistral-small
```

### Utilisation en Python

```python
from src.pipeline import VulnerabilityAnalysisPipeline

# Initialiser le pipeline
pipeline = VulnerabilityAnalysisPipeline(
    llm_model="gpt-oss-20b",
    enable_ai=True
)

# Charger les scans
pipeline.load_nmap_scan("data/scans/scan.xml")
pipeline.load_nessus_scan("data/scans/scan.nessus")

# Enrichir les vulnérabilités
pipeline.enrich_vulnerabilities()

# Analyse IA
pipeline.analyze_with_ai()

# Prioriser
pipeline.prioritize()

# Générer les rapports
reports = pipeline.generate_reports(organization="Mon Organisation")
```

## Rapports Générés

### Rapport Exécutif
- Synthétique et orienté décisionnel
- Pour le management
- Focus sur l'impact business et les recommandations stratégiques

### Rapport Technique
- Détaillé et complet
- Pour les administrateurs sécurité
- Inclut les détails techniques, CVE, CVSS, MITRE ATT&CK

## Configuration

Les paramètres sont configurables dans `config/settings.py`:

```python
# Température à 0 pour reproductibilité
temperature = 0.0

# Routage des modèles
model_routing = {
    "simple": "phi-4",
    "medium": "phi-4",
    "complex": "mistral-small",
    "very_complex": "gpt-oss-20b"
}
```

## Métriques d'Évaluation

- **Accuracy (Justesse):** Taux global de bonnes réponses
- **Precision (Fiabilité):** Proportion de vraies vulnérabilités parmi les alertes (évite les Faux Positifs)
- **Recall (Exhaustivité):** Proportion de vulnérabilités réelles détectées (évite les Faux Négatifs)

## Hyperparamètres

**Température fixée à 0:**
- Référence théorique: Dans l'échantillonnage de tokens, une valeur proche de 0 (Argmax) rend le modèle déterministe
- Intérêt Métier: En cybersécurité, la créativité est un risque (hallucination). Nous cherchons la reproductibilité et la précision factuelle

## Outils de Scan Supportés

- **Nmap:** Cartographie réseau (XML output)
- **Nessus Essential:** Analyse de vulnérabilités (.nessus, JSON)

## Architecture de Test

Environnement de laboratoire isolé avec:
- Machine attaquante (Kali Linux)
- Cibles volontairement vulnérables:
  - Metasploitable 2
  - Windows Server
  - DVWA

## Contraintes

- Respect du cadre pédagogique (pas d'attaques réelles)
- Outils open-source privilégiés
- Tests uniquement sur environnements simulés
- Documentation claire et traçabilité des choix techniques

---

**Équipe projet ESILV - PI2**
