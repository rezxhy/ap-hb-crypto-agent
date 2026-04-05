#!/usr/bin/env python3
"""
AP-HB AI Crypto Agent — Agent IA de chiffrement automatique
Propulsé par Groq (LLM) + AES-256-GCM (chiffrement)

Usage:
    python3 ai_agent.py                        # Mode interactif
    python3 ai_agent.py --scan /dossier        # Scan et chiffrement automatique
    python3 ai_agent.py --prompt "chiffre demo/patients_test"
"""

import os
import sys
import json
import shutil
import argparse
from pathlib import Path

# Chargement automatique du fichier .env
if os.path.exists(".env"):
    with open(".env") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                os.environ[key.strip()] = value.strip()

from groq import Groq
from crypto_agent import (
    encrypt_directory, decrypt_directory,
    decrypt_file, load_master_key, generate_master_key,
    ENCRYPTED_EXT,
)

# ─── Configuration ─────────────────────────────────────────────────────────────

MODEL     = "llama-3.3-70b-versatile"
KEY_FILE  = "keys/master.key"
MAX_TURNS = 15

SYSTEM_PROMPT = """Tu es l'Agent IA de Cyber-Sécurité de l'AP-HB (Assistance Publique - Hôpitaux et Biotechnologies).

Ta mission est de gérer les fichiers de santé sensibles : créer des dossiers, copier des fichiers, chiffrer et déchiffrer de manière autonome.

Tu disposes des outils suivants :
- lister_fichiers    : liste le contenu d'un dossier avec statut chiffré/en clair
- creer_dossier      : crée un nouveau dossier
- copier_fichier     : copie un fichier vers un dossier de destination
- chiffrer_dossier   : chiffre tous les fichiers d'un dossier (AES-256-GCM)
- dechiffrer_dossier : déchiffre tous les fichiers .aphb d'un dossier vers une destination
- dechiffrer_fichier : déchiffre un seul fichier .aphb vers un dossier de destination
- scanner_dossier    : analyse un dossier et identifie les fichiers non protégés
- rapport_audit      : génère un rapport de conformité RGPD

Règles absolues :
1. Utilise toujours lister_fichiers en premier pour connaître l'état du dossier
2. Tu peux créer des dossiers et copier des fichiers de manière autonome
3. Après chaque action, confirme ce qui a été fait
4. Réponds toujours en français

Quand on te demande de copier des fichiers chiffrés (.aphb), copie les .aphb directement."""

# ─── Définition des outils ─────────────────────────────────────────────────────

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "lister_fichiers",
            "description": "Liste tous les fichiers d'un dossier avec leur statut (chiffré .aphb ou en clair) et leur taille.",
            "parameters": {
                "type": "object",
                "properties": {
                    "chemin": {"type": "string", "description": "Dossier à lister"}
                },
                "required": ["chemin"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "creer_dossier",
            "description": "Crée un nouveau dossier (et les dossiers parents si nécessaire).",
            "parameters": {
                "type": "object",
                "properties": {
                    "chemin": {"type": "string", "description": "Chemin du dossier à créer"}
                },
                "required": ["chemin"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "copier_fichier",
            "description": "Copie un fichier (en clair ou chiffré) vers un dossier de destination. Fonctionne avec tous les types de fichiers.",
            "parameters": {
                "type": "object",
                "properties": {
                    "fichier_source": {"type": "string", "description": "Chemin complet du fichier à copier"},
                    "dossier_destination": {"type": "string", "description": "Dossier de destination"}
                },
                "required": ["fichier_source", "dossier_destination"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "chiffrer_dossier",
            "description": "Chiffre tous les fichiers en clair d'un dossier avec AES-256-GCM.",
            "parameters": {
                "type": "object",
                "properties": {
                    "chemin": {"type": "string", "description": "Dossier à chiffrer"}
                },
                "required": ["chemin"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "dechiffrer_dossier",
            "description": "Déchiffre tous les fichiers .aphb d'un dossier vers une destination.",
            "parameters": {
                "type": "object",
                "properties": {
                    "chemin_source": {"type": "string", "description": "Dossier contenant les .aphb"},
                    "chemin_destination": {"type": "string", "description": "Dossier de destination"}
                },
                "required": ["chemin_source", "chemin_destination"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "dechiffrer_fichier",
            "description": "Déchiffre un seul fichier .aphb vers un dossier de destination.",
            "parameters": {
                "type": "object",
                "properties": {
                    "fichier_source": {"type": "string", "description": "Chemin du fichier .aphb à déchiffrer"},
                    "dossier_destination": {"type": "string", "description": "Dossier de destination"}
                },
                "required": ["fichier_source", "dossier_destination"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "scanner_dossier",
            "description": "Analyse un dossier et retourne les fichiers en clair vs chiffrés.",
            "parameters": {
                "type": "object",
                "properties": {
                    "chemin": {"type": "string", "description": "Dossier à analyser"}
                },
                "required": ["chemin"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "rapport_audit",
            "description": "Génère un rapport de conformité RGPD sur l'état de protection d'un dossier.",
            "parameters": {
                "type": "object",
                "properties": {
                    "chemin": {"type": "string", "description": "Dossier à auditer"}
                },
                "required": ["chemin"]
            }
        }
    }
]

# ─── Implémentation des outils ─────────────────────────────────────────────────

def lister_fichiers(chemin: str) -> dict:
    path = Path(chemin)
    if not path.exists():
        return {"erreur": f"Dossier introuvable : {chemin}"}
    fichiers = []
    for f in sorted(path.rglob("*")):
        if f.is_file():
            statut = "chiffre" if str(f).endswith(ENCRYPTED_EXT) else "en_clair"
            fichiers.append({
                "nom"   : str(f.relative_to(path)),
                "statut": statut,
                "taille": f"{f.stat().st_size} octets"
            })
    return {"dossier": chemin, "fichiers": fichiers, "total": len(fichiers)}


def creer_dossier(chemin: str) -> dict:
    try:
        Path(chemin).mkdir(parents=True, exist_ok=True)
        return {"succes": True, "message": f"Dossier créé : {chemin}"}
    except Exception as e:
        return {"succes": False, "erreur": str(e)}


def copier_fichier(fichier_source: str, dossier_destination: str) -> dict:
    src = Path(fichier_source)
    dst = Path(dossier_destination)
    if not src.exists():
        return {"erreur": f"Fichier introuvable : {fichier_source}"}
    try:
        dst.mkdir(parents=True, exist_ok=True)
        dest_path = dst / src.name
        shutil.copy2(src, dest_path)
        return {"succes": True, "message": f"Copié : {src.name} → {dossier_destination}"}
    except Exception as e:
        return {"succes": False, "erreur": str(e)}


def chiffrer_dossier(chemin: str, key: bytes) -> dict:
    if not Path(chemin).exists():
        return {"erreur": f"Dossier introuvable : {chemin}"}
    try:
        stats = encrypt_directory(chemin, key)
        return {
            "succes"  : True,
            "chiffres": stats["encrypted"],
            "erreurs" : stats["errors"],
            "message" : f"{stats['encrypted']} fichier(s) chiffré(s)."
        }
    except Exception as e:
        return {"succes": False, "erreur": str(e)}


def dechiffrer_dossier(chemin_source: str, chemin_destination: str, key: bytes) -> dict:
    try:
        stats = decrypt_directory(chemin_source, chemin_destination, key)
        return {
            "succes"    : True,
            "dechiffres": stats["decrypted"],
            "erreurs"   : stats["errors"],
            "message"   : f"{stats['decrypted']} fichier(s) restauré(s) dans {chemin_destination}."
        }
    except Exception as e:
        return {"succes": False, "erreur": str(e)}


def dechiffrer_fichier_unique(fichier_source: str, dossier_destination: str, key: bytes) -> dict:
    src = Path(fichier_source)
    if not src.exists():
        return {"erreur": f"Fichier introuvable : {fichier_source}"}
    if not str(fichier_source).endswith(ENCRYPTED_EXT):
        return {"erreur": f"Ce fichier n'est pas un fichier chiffré .aphb : {fichier_source}"}
    try:
        Path(dossier_destination).mkdir(parents=True, exist_ok=True)
        dest = decrypt_file(fichier_source, key, dossier_destination)
        return {"succes": True, "message": f"Déchiffré : {src.name} → {dossier_destination}"}
    except Exception as e:
        return {"succes": False, "erreur": str(e)}


def scanner_dossier(chemin: str) -> dict:
    path = Path(chemin)
    if not path.exists():
        return {"erreur": f"Dossier introuvable : {chemin}"}
    clairs, chiffres = [], []
    for f in path.rglob("*"):
        if not f.is_file() or f.suffix in {".py", ".key", ".log", ".md"}:
            continue
        if str(f).endswith(ENCRYPTED_EXT):
            chiffres.append(str(f.relative_to(path)))
        else:
            clairs.append(str(f.relative_to(path)))
    return {
        "dossier": chemin,
        "fichiers_en_clair": clairs,
        "fichiers_chiffres": chiffres,
        "total_en_clair": len(clairs),
        "total_chiffres": len(chiffres),
        "message": f"{len(clairs)} fichier(s) non protégé(s) !" if clairs else "Tout est chiffré."
    }


def rapport_audit(chemin: str) -> dict:
    path = Path(chemin)
    if not path.exists():
        return {"erreur": f"Dossier introuvable : {chemin}"}
    chiffres = list(path.rglob(f"*{ENCRYPTED_EXT}"))
    clairs = [f for f in path.rglob("*") if f.is_file()
              and not str(f).endswith(ENCRYPTED_EXT)
              and f.suffix not in {".py", ".key", ".log", ".md", ".txt", ".gitignore"}]
    volume_mb = sum(f.stat().st_size for f in chiffres) / (1024 * 1024)
    return {
        "dossier": chemin,
        "conformite_rgpd": "CONFORME" if not clairs else "NON CONFORME",
        "fichiers_chiffres": len(chiffres),
        "fichiers_en_clair": len(clairs),
        "liste_non_proteges": [str(f.relative_to(path)) for f in clairs[:10]],
        "volume_chiffre_mb": round(volume_mb, 2),
        "message": (
            f"NON CONFORME — {len(clairs)} fichier(s) exposé(s) !"
            if clairs else
            f"CONFORME RGPD — {len(chiffres)} fichier(s) protégé(s)"
        )
    }


# ─── Exécuteur d'outils ────────────────────────────────────────────────────────

def executer_outil(nom: str, arguments: dict, key: bytes) -> str:
    print(f"\n  {nom}({', '.join(f'{k}={v}' for k,v in arguments.items())})")

    if nom == "lister_fichiers":
        result = lister_fichiers(arguments["chemin"])
    elif nom == "creer_dossier":
        result = creer_dossier(arguments["chemin"])
    elif nom == "copier_fichier":
        result = copier_fichier(arguments["fichier_source"], arguments["dossier_destination"])
    elif nom == "chiffrer_dossier":
        result = chiffrer_dossier(arguments["chemin"], key)
    elif nom == "dechiffrer_dossier":
        result = dechiffrer_dossier(arguments["chemin_source"], arguments["chemin_destination"], key)
    elif nom == "dechiffrer_fichier":
        result = dechiffrer_fichier_unique(arguments["fichier_source"], arguments["dossier_destination"], key)
    elif nom == "scanner_dossier":
        result = scanner_dossier(arguments["chemin"])
    elif nom == "rapport_audit":
        result = rapport_audit(arguments["chemin"])
    else:
        result = {"erreur": f"Outil inconnu : {nom}"}

    print(f"  {json.dumps(result, ensure_ascii=False)[:200]}")
    return json.dumps(result, ensure_ascii=False)


# ─── Boucle agent ──────────────────────────────────────────────────────────────

def run_agent(client: Groq, messages: list, key: bytes) -> str:
    turns = 0
    while turns < MAX_TURNS:
        turns += 1
        response = client.chat.completions.create(
            model=MODEL,
            messages=messages,
            tools=TOOLS,
            tool_choice="auto",
            max_tokens=2048,
        )
        message = response.choices[0].message
        if not message.tool_calls:
            return message.content

        messages.append({
            "role"      : "assistant",
            "content"   : message.content or "",
            "tool_calls": [
                {"id": tc.id, "type": "function",
                 "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
                for tc in message.tool_calls
            ]
        })
        for tool_call in message.tool_calls:
            arguments = json.loads(tool_call.function.arguments)
            result    = executer_outil(tool_call.function.name, arguments, key)
            messages.append({
                "role": "tool", "tool_call_id": tool_call.id, "content": result
            })
    return "Nombre maximum de tours atteint."


# ─── Interface principale ──────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="AP-HB AI Crypto Agent")
    parser.add_argument("--scan",   metavar="DOSSIER")
    parser.add_argument("--prompt", metavar="TEXTE")
    args = parser.parse_args()

    print("\n")
    print("AP-HB AI Crypto Agent  •  Groq + AES-256-GCM  ")
    print("Agent IA de chiffrement automatique            ")
    print("\n")

    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        print("Clé API Groq non trouvée.")
        api_key = input("   Entrez votre clé API Groq : ").strip()

    client = Groq(api_key=api_key)

    if not os.path.exists(KEY_FILE):
        print("Aucune clé maître trouvée. Génération en cours...")
        generate_master_key(KEY_FILE)

    key = load_master_key(KEY_FILE)
    print()

    if args.scan:
        prompt = (f"Liste d'abord les fichiers de '{args.scan}', puis analyse, "
                  f"chiffre tous les fichiers en clair, et génère un rapport de conformité final.")
        messages = [{"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user",   "content": prompt}]
        print(f"Analyse automatique de '{args.scan}'...\n")
        print(f"\n{'─'*55}")
        print(f"Agent IA :\n{run_agent(client, messages, key)}")
        return

    if args.prompt:
        messages = [{"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user",   "content": args.prompt}]
        print(f"Traitement en cours...\n")
        print(f"\n{'─'*55}")
        print(f"Agent IA :\n{run_agent(client, messages, key)}")
        return

    # Mode interactif
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    print("Mode interactif — tapez votre instruction (ou 'quitter' pour sortir)")
    print("   Exemples :")
    print("   • 'Mets dupont_jean et martin_marie dans un dossier confidentiel chiffré'")
    print("   • 'Déchiffre ordonnance_dupont dans le dossier recuperation'")
    print("   • 'Génère un rapport d'audit sur demo/'")
    print(f"{'─'*55}\n")

    while True:
        try:
            user_input = input("Vous : ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nAu revoir !")
            break
        if not user_input:
            continue
        if user_input.lower() in {"quitter", "exit", "quit"}:
            print("Au revoir !")
            break
        messages.append({"role": "user", "content": user_input})
        print("\nRéflexion en cours...")
        reponse = run_agent(client, messages, key)
        messages.append({"role": "assistant", "content": reponse})
        print(f"\nAgent IA :\n{reponse}\n{'─'*55}\n")


if __name__ == "__main__":
    main()
