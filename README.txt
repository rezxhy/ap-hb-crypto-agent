=====================================================
AP-HB AI Crypto Agent
Agent IA de chiffrement automatique de fichiers
=====================================================

Agent IA développé pour l'AP-HB (Assistance Publique - Hopitaux et Biotechnologies).
Il garantit qu'AUCUNE donnée de santé ne sorte sous forme lisible.

  Modèle IA   : Groq / LLaMA 3.3 70B (gratuit)
  Chiffrement : AES-256-GCM
  Conformité  : RGPD, HIPAA, Loi chinoise sur la cybersécurité (CSL)

=====================================================
STRUCTURE DU PROJET
=====================================================

  ap-hb-crypto-agent/
  |
  |-- ai_agent.py          --> Agent IA principal (Groq + outils de chiffrement)
  |-- crypto_agent.py      --> Moteur de chiffrement AES-256-GCM
  |-- setup.sh             --> Script d'installation automatique
  |-- requirements.txt     --> Dépendances Python
  |-- .env.example         --> Modèle de configuration (à copier en .env)
  |-- LICENSE              --> Licence MIT
  |-- README.txt        
  |
  |-- keys/
  |     master.key         --> Clé maître chiffrée (créée au premier lancement)
  |
  |-- demo/
        patients_test/     --> Faux dossiers patients pour tester

=====================================================
INSTALLATION (à faire une seule fois)
=====================================================

Étape 1 : Lancer le script de setup

    bash setup.sh

  Ce script fait automatiquement :
    - Installation de Python et des outils système
    - Création d'un environnement virtuel (venv)
    - Installation des dépendances (cryptography, watchdog, groq)
    - Création du fichier .env à remplir

Étape 2 : Obtenir une clé API Groq (gratuit)

  1. Aller sur : https://console.groq.com
  2. Créer un compte (gratuit, pas de carte bancaire)
  3. Aller dans "API Keys" -> "Create API Key"
  4. Copier la clé (commence par "gsk_...")

Étape 3 : Ajouter la clé dans le fichier .en

    nano .env

  Modifier la ligne :
    GROQ_API_KEY=gsk_votre_cle_ici

  Sauvegarder : Ctrl+O puis Entrée, quitter : Ctrl+X

Étape 4 : Activer le venv (à faire à chaque nouveau terminal)

    source venv/bin/activate

  Vous verrez (venv) apparaître au début de la ligne.


=====================================================
UTILISATION DE L'AGENT IA
=====================================================

Mode automatique — scan et chiffrement d'un dossier

    python3 ai_agent.py --scan demo/patients_test

  L'agent analyse le dossier, chiffre tous les fichiers en clair,
  puis génère un rapport de conformité. Aucune interaction requise.

Mode instruction directe

    python3 ai_agent.py --prompt "Chiffre le dossier demo/patients_test"
    python3 ai_agent.py --prompt "Génère un rapport d'audit sur demo/"

Mode interactif — conversation avec l'agent

    python3 ai_agent.py

  Exemples de commandes en langage naturel :
    "Scanne et chiffre le dossier demo/patients_test"
    "Quels fichiers ne sont pas encore protégés ?"
    "Génère un rapport d'audit sur demo/"
    "Restaure demo/patients_test vers demo/restauration"

  Taper "quitter" pour sortir.

Premier lancement — génération de la clé maître : 

  Au premier lancement, l'agent vous demande de créer une clé maître :

    Mot de passe pour la clé maître : [tapez votre mot de passe]
    Confirmer le mot de passe       : [confirmez]

  Pour le test de démonstration, vous pouvez utiliser : DemoAPHB2026!

=====================================================
CE QUE FAIT L'AGENT IA (fonctionnement interne)
=====================================================

  L'agent raisonne en plusieurs étapes automatiques :

    1. Il ANALYSE le dossier
       --> Identifie les fichiers en clair et les fichiers chiffrés

    2. Il DÉCIDE quoi faire
       --> Si des fichiers ne sont pas protégés, il les chiffre

    3. Il AGIT avec ses outils :
       - scanner_dossier    : liste fichiers en clair vs chiffrés
       - chiffrer_dossier   : chiffre un dossier (AES-256-GCM)
       - dechiffrer_dossier : restaure vers une destination sûre
       - rapport_audit      : rapport de conformité RGPD
       - lister_fichiers    : liste le contenu d'un dossier

    4. Il VÉRIFIE que tout est protégé

    5. Il RAPPORTE le résultat en français

=====================================================
CONFORMITÉ RÉGLEMENTAIRE
=====================================================

  RGPD Article 32
    --> Chiffrement des données personnelles de santé

  HIPAA Section 164.312(a)(2)(iv) - Etats-Unis
    --> Chiffrement des données au repos

  CSL Article 21 - Loi chinoise sur la cybersécurité
    --> Protection des données d'infrastructure critique

  HDS - Hébergement de Données de Santé (France)
    --> Traçabilité et intégrité des données de santé


=====================================================
LICENCE
=====================================================

  MIT License (open source, utilisation libre)
  Voir le fichier LICENSE pour le texte complet.


=====================================================
AUTEURS
=====================================================

  Atelier AP-HB - Conformité et Cyber-résilience en Finance Agentique
  Date de soumission : 5 avril 2026
