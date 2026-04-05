#!/bin/bash

# ============================================================
# Script de setup — AP-HB AI Crypto Agent (Ubuntu)
# ============================================================

set -e  # Arrêt immédiat en cas d'erreur

echo ""
echo "============================================================"
echo "  AP-HB AI Crypto Agent — Setup Ubuntu"
echo "  Chiffrement AES-256-GCM propulsé par Groq"
echo "============================================================"
echo ""

# --- Étape 1 : Paquets système ---
echo "📦 [1/5] Installation des paquets système..."
sudo apt update -qq
sudo apt install -y python3 python3-pip python3-venv
echo "    ✅ Paquets système installés"

# --- Étape 2 : Environnement virtuel ---
echo ""
echo "🐍 [2/5] Création de l'environnement virtuel..."
python3 -m venv venv
echo "    ✅ Environnement virtuel créé dans ./venv"

# --- Étape 3 : Activation du venv ---
echo ""
echo "⚡ [3/5] Activation de l'environnement virtuel..."
source venv/bin/activate
echo "    ✅ Environnement virtuel activé"

# --- Étape 4 : Dépendances Python ---
echo ""
echo "📥 [4/5] Installation des dépendances Python..."
pip install --upgrade pip -q
pip install -r requirements.txt -q
echo "    ✅ Dépendances installées (cryptography, watchdog, groq)"

# --- Étape 5 : Fichier .env ---
echo ""
echo "🔑 [5/5] Configuration de l'environnement..."
if [ ! -f ".env" ]; then
    cp .env.example .env
    echo "    ⚠️  Fichier .env créé. Tu dois y ajouter ta clé API Groq :"
    echo "       nano .env"
else
    echo "    ✅ Fichier .env déjà existant"
fi

# --- Génération de la clé maître ---
echo ""
echo "🔐 [+] Génération de la clé maître de chiffrement..."
if [ ! -f "keys/master.key" ]; then
    echo "    La clé maître n'existe pas encore."
    echo "    Elle sera générée au premier lancement de l'agent."
    echo "    ⚠️  Retenez bien votre mot de passe — sans lui, les données sont irrécupérables."
else
    echo "    ✅ Clé maître déjà existante dans keys/master.key"
fi

# --- Résumé ---
echo ""
echo "============================================================"
echo "  ✅ Setup terminé avec succès !"
echo "============================================================"
echo ""
echo "  👉 Étapes suivantes :"
echo ""
echo "  1. Ajoute ta clé API Groq dans .env :"
echo "     nano .env"
echo "     (clé disponible gratuitement sur https://console.groq.com)"
echo ""
echo "  2. Active le venv (à chaque nouveau terminal) :"
echo "     source venv/bin/activate"
echo ""
echo "  3. Lance l'agent IA :"
echo ""
echo "     Mode automatique (scan + chiffrement d'un dossier) :"
echo "     python3 ai_agent.py --scan demo/patients_test"
echo ""
echo "     Mode instruction directe :"
echo "     python3 ai_agent.py --prompt 'Chiffre le dossier demo/patients_test'"
echo ""
echo "     Mode interactif (conversation avec l'agent) :"
echo "     python3 ai_agent.py"
echo ""
