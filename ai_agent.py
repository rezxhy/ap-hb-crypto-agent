#!/usr/bin/env python3
"""
AP-HB AI Crypto Agent — Agent IA de chiffrement automatique
Propulsé par Groq (LLM) + AES-256-GCM (chiffrement)

L'agent IA analyse la situation, raisonne, et décide quelles actions
de chiffrement effectuer pour garantir qu'aucune donnée sensible
ne sorte sous forme lisible.

Usage:
    python3 ai_agent.py                        # Mode interactif
    python3 ai_agent.py --scan /dossier        # Scan et chiffrement automatique
    python3 ai_agent.py --prompt "chiffre demo/patients_test"
"""

import os
import sys
import json
import argparse
import getpass
from pathlib import Path
from typing import Any

from groq import Groq
from crypto_agent import (
    encrypt_directory, decrypt_directory,
    load_master_key, generate_master_key,
    audit_directory, watch_directory,
    ENCRYPTED_EXT,
)

# ─── Configuration ────────────────────────────────────────────────────────────

MODEL        = "llama-3.3-70b-versatile"   # Modèle Groq (rapide et puissant)
KEY_FILE     = "keys/master.key"
MAX_TURNS    = 10                           # Sécurité : max 10 appels d'outils par session

SYSTEM_PROMPT = """Tu es l'Agent IA de Cyber-Sécurité de l'AP-HB (Assistance Publique - Hôpitaux et Biotechnologies).

Ta mission principale est de garantir qu'AUCUNE donnée de santé ne sorte sous forme lisible.
Tu es responsable du chiffrement automatique et robuste des fichiers sensibles.

Tu disposes des outils suivants :
- scanner_dossier : analyse un dossier et identifie les fichiers non protégés
- chiffrer_dossier : chiffre tous les fichiers d'un dossier (AES-256-GCM)
- dechiffrer_dossier : déchiffre un dossier vers une destination sûre
- rapport_audit : génère un rapport de conformité sur l'état de protection
- lister_fichiers : liste le contenu d'un dossier

Tes règles de sécurité absolues :
1. Tout fichier contenant des données de santé DOIT être chiffré
2. Tu dois toujours vérifier l'état AVANT et APRÈS chiffrement
3. Tu rapportes toujours le résultat de tes actions
4. En cas de doute, tu chiffres (principe de précaution)
5. Tu ne déchiffres que si explicitement demandé avec une destination sûre

Réponds toujours en français. Sois précis et professionnel.
Après chaque action, confirme ce qui a été fait et l'état de sécurité actuel."""

# ─── Définition des outils pour Groq ─────────────────────────────────────────

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "scanner_dossier",
            "description": "Analyse un dossier et retourne la liste des fichiers en clair (non chiffrés) et des fichiers déjà chiffrés. Permet d'évaluer l'état de sécurité avant d'agir.",
            "parameters": {
                "type": "object",
                "properties": {
                    "chemin": {
                        "type": "string",
                        "description": "Chemin absolu ou relatif du dossier à analyser"
                    }
                },
                "required": ["chemin"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "chiffrer_dossier",
            "description": "Chiffre tous les fichiers en clair d'un dossier avec AES-256-GCM. Les fichiers originaux sont effacés de manière sécurisée. À utiliser pour protéger des données de santé sensibles.",
            "parameters": {
                "type": "object",
                "properties": {
                    "chemin": {
                        "type": "string",
                        "description": "Chemin du dossier à chiffrer"
                    }
                },
                "required": ["chemin"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "dechiffrer_dossier",
            "description": "Déchiffre les fichiers .aphb d'un dossier vers une destination sûre. À utiliser uniquement pour la restauration après incident.",
            "parameters": {
                "type": "object",
                "properties": {
                    "chemin_source": {
                        "type": "string",
                        "description": "Dossier contenant les fichiers chiffrés (.aphb)"
                    },
                    "chemin_destination": {
                        "type": "string",
                        "description": "Dossier de destination pour les fichiers restaurés"
                    }
                },
                "required": ["chemin_source", "chemin_destination"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "rapport_audit",
            "description": "Génère un rapport détaillé de conformité : nombre de fichiers chiffrés vs en clair, volume total, liste des fichiers non protégés.",
            "parameters": {
                "type": "object",
                "properties": {
                    "chemin": {
                        "type": "string",
                        "description": "Dossier à auditer"
                    }
                },
                "required": ["chemin"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "lister_fichiers",
            "description": "Liste les fichiers présents dans un dossier avec leur statut (chiffré ou en clair).",
            "parameters": {
                "type": "object",
                "properties": {
                    "chemin": {
                        "type": "string",
                        "description": "Dossier à lister"
                    }
                },
                "required": ["chemin"]
            }
        }
    }
]

# ─── Implémentation des outils ────────────────────────────────────────────────

def scanner_dossier(chemin: str) -> dict:
    path = Path(chemin)
    if not path.exists():
        return {"erreur": f"Dossier introuvable : {chemin}"}

    fichiers_clairs   = []
    fichiers_chiffres = []

    for f in path.rglob("*"):
        if not f.is_file():
            continue
        if f.suffix in {".py", ".key", ".log", ".gitignore", ".txt"} and f.name == "README.txt":
            continue
        if str(f).endswith(ENCRYPTED_EXT):
            fichiers_chiffres.append(str(f.relative_to(path)))
        elif f.suffix not in {".py", ".key", ".log", ".md"}:
            fichiers_clairs.append(str(f.relative_to(path)))

    return {
        "dossier"          : chemin,
        "fichiers_en_clair": fichiers_clairs,
        "fichiers_chiffres": fichiers_chiffres,
        "total_en_clair"   : len(fichiers_clairs),
        "total_chiffres"   : len(fichiers_chiffres),
        "alerte"           : len(fichiers_clairs) > 0,
        "message"          : (
            f"{len(fichiers_clairs)} fichier(s) non protégé(s) détecté(s) !"
            if fichiers_clairs else
            "Tous les fichiers sont chiffrés."
        )
    }


def chiffrer_dossier(chemin: str, key: bytes) -> dict:
    path = Path(chemin)
    if not path.exists():
        return {"erreur": f"Dossier introuvable : {chemin}"}
    try:
        stats = encrypt_directory(chemin, key)
        return {
            "succes"    : True,
            "chiffres"  : stats["encrypted"],
            "ignores"   : stats["skipped"],
            "erreurs"   : stats["errors"],
            "message"   : f"{stats['encrypted']} fichier(s) chiffré(s) avec succès. {stats['errors']} erreur(s)."
        }
    except Exception as e:
        return {"succes": False, "erreur": str(e)}


def dechiffrer_dossier(chemin_source: str, chemin_destination: str, key: bytes) -> dict:
    try:
        stats = decrypt_directory(chemin_source, chemin_destination, key)
        return {
            "succes"     : True,
            "dechiffres" : stats["decrypted"],
            "erreurs"    : stats["errors"],
            "destination": chemin_destination,
            "message"    : f"{stats['decrypted']} fichier(s) restauré(s) dans {chemin_destination}."
        }
    except Exception as e:
        return {"succes": False, "erreur": str(e)}


def rapport_audit(chemin: str) -> dict:
    path = Path(chemin)
    if not path.exists():
        return {"erreur": f"Dossier introuvable : {chemin}"}

    chiffres = list(path.rglob(f"*{ENCRYPTED_EXT}"))
    clairs   = [
        f for f in path.rglob("*")
        if f.is_file()
        and not str(f).endswith(ENCRYPTED_EXT)
        and f.suffix not in {".py", ".key", ".log", ".md", ".txt", ".gitignore"}
    ]

    volume_mb = sum(f.stat().st_size for f in chiffres) / (1024 * 1024)
    conformite = "CONFORME" if not clairs else "NON CONFORME"

    return {
        "dossier"          : chemin,
        "conformite_rgpd"  : conformite,
        "fichiers_chiffres": len(chiffres),
        "fichiers_en_clair": len(clairs),
        "liste_non_proteges": [str(f.relative_to(path)) for f in clairs[:10]],
        "volume_chiffre_mb": round(volume_mb, 2),
        "message"          : (
            f"NON CONFORME — {len(clairs)} fichier(s) exposé(s) en clair !"
            if clairs else
            f"CONFORME RGPD — {len(chiffres)} fichier(s) protégé(s), volume {volume_mb:.2f} MB"
        )
    }


def lister_fichiers(chemin: str) -> dict:
    path = Path(chemin)
    if not path.exists():
        return {"erreur": f"Dossier introuvable : {chemin}"}

    fichiers = []
    for f in sorted(path.rglob("*")):
        if f.is_file():
            statut = "chiffré" if str(f).endswith(ENCRYPTED_EXT) else "📄 en clair"
            fichiers.append({
                "nom"   : str(f.relative_to(path)),
                "statut": statut,
                "taille": f"{f.stat().st_size} octets"
            })
    return {"dossier": chemin, "fichiers": fichiers, "total": len(fichiers)}


# ─── Exécuteur d'outils ───────────────────────────────────────────────────────

def executer_outil(nom: str, arguments: dict, key: bytes) -> str:
    """Exécute un outil et retourne le résultat en JSON."""
    print(f"\n  Outil appelé : {nom}({', '.join(f'{k}={v}' for k,v in arguments.items())})")

    if nom == "scanner_dossier":
        result = scanner_dossier(arguments["chemin"])
    elif nom == "chiffrer_dossier":
        result = chiffrer_dossier(arguments["chemin"], key)
    elif nom == "dechiffrer_dossier":
        result = dechiffrer_dossier(arguments["chemin_source"], arguments["chemin_destination"], key)
    elif nom == "rapport_audit":
        result = rapport_audit(arguments["chemin"])
    elif nom == "lister_fichiers":
        result = lister_fichiers(arguments["chemin"])
    else:
        result = {"erreur": f"Outil inconnu : {nom}"}

    print(f"  Résultat : {json.dumps(result, ensure_ascii=False)[:200]}...")
    return json.dumps(result, ensure_ascii=False)


# ─── Boucle agent ─────────────────────────────────────────────────────────────

def run_agent(client: Groq, messages: list, key: bytes) -> str:
    """Boucle ReAct : l'agent raisonne, appelle des outils, observe, répète."""
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

        # Si l'agent a fini (pas d'appel d'outil)
        if not message.tool_calls:
            return message.content

        # L'agent appelle un ou plusieurs outils
        messages.append({
            "role"      : "assistant",
            "content"   : message.content or "",
            "tool_calls": [
                {
                    "id"      : tc.id,
                    "type"    : "function",
                    "function": {"name": tc.function.name, "arguments": tc.function.arguments}
                }
                for tc in message.tool_calls
            ]
        })

        # Exécuter chaque outil et ajouter les résultats
        for tool_call in message.tool_calls:
            arguments = json.loads(tool_call.function.arguments)
            result    = executer_outil(tool_call.function.name, arguments, key)
            messages.append({
                "role"        : "tool",
                "tool_call_id": tool_call.id,
                "content"     : result
            })

    return "Nombre maximum de tours atteint."


# ─── Interface principale ─────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="AP-HB AI Crypto Agent — Agent IA de chiffrement (Groq + AES-256-GCM)"
    )
    parser.add_argument("--scan",   metavar="DOSSIER", help="Scanner et chiffrer automatiquement un dossier")
    parser.add_argument("--prompt", metavar="TEXTE",   help="Envoyer une instruction directe à l'agent")
    args = parser.parse_args()

    print("\n")
    print("AP-HB AI Crypto Agent  •  Groq + AES-256-GCM    ")
    print("Agent IA de chiffrement automatique             ")
    print("\n")

    # Clé API Groq
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        print("Clé API Groq non trouvée dans les variables d'environnement.")
        api_key = input("   Entrez votre clé API Groq : ").strip()

    client = Groq(api_key=api_key)

    # Clé de chiffrement
    if not os.path.exists(KEY_FILE):
        print("\nAucune clé maître trouvée. Génération en cours...")
        generate_master_key(KEY_FILE)

    key = load_master_key(KEY_FILE)
    print()

    # Mode --scan : l'agent scanne et chiffre automatiquement
    if args.scan:
        prompt_initial = (
            f"Analyse le dossier '{args.scan}', identifie tous les fichiers non protégés, "
            f"chiffre-les immédiatement, puis génère un rapport de conformité final."
        )
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": prompt_initial}
        ]
        print(f"Agent IA : analyse automatique de '{args.scan}'...\n")
        reponse = run_agent(client, messages, key)
        print(f"\n{'─'*55}")
        print(f"Agent IA :\n{reponse}")
        return

    # Mode --prompt : instruction directe
    if args.prompt:
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": args.prompt}
        ]
        print(f"Agent IA : traitement de votre demande...\n")
        reponse = run_agent(client, messages, key)
        print(f"\n{'─'*55}")
        print(f"Agent IA :\n{reponse}")
        return

    # Mode interactif (chat)
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    print("Mode interactif — tapez votre instruction (ou 'quitter' pour sortir)")
    print("   Exemples :")
    print("   • 'Scanne et chiffre le dossier demo/patients_test'")
    print("   • 'Génère un rapport d'audit sur demo/'")
    print("   • 'Restaure demo/patients_test vers demo/restauration'")
    print(f"{'─'*55}\n")

    while True:
        try:
            user_input = input("Vous : ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n\nAu revoir !")
            break

        if not user_input:
            continue
        if user_input.lower() in {"quitter", "exit", "quit"}:
            print("Au revoir !")
            break

        messages.append({"role": "user", "content": user_input})
        print("\nAgent IA : réflexion en cours...")

        reponse = run_agent(client, messages, key)
        messages.append({"role": "assistant", "content": reponse})

        print(f"\nAgent IA :\n{reponse}\n")
        print(f"{'─'*55}\n")


if __name__ == "__main__":
    main()
