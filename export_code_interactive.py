#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import datetime
from pathlib import Path

# Dossiers par défaut à ignorer si l'utilisateur ne précise rien
DEFAULT_IGNORE_DIRS = {
    '.git', 'node_modules', 'target', '.idea', 'out', 'build', 'dist',
    '__pycache__', '.venv', 'env', 'venv', '.env', 'docker-data',
    '.next', '.nuxt', '.vscode', '.gradle', 'logs', '.mvn'
}

def get_user_input(prompt, default=None):
    """Récupère la saisie utilisateur avec une valeur par défaut affichée."""
    if default:
        user_input = input(f"{prompt} (par défaut: {default}) : ").strip()
        return user_input if user_input else default
    else:
        return input(f"{prompt} : ").strip()

def export_code_to_txt(root_dir, ignore_set, output_file):
    root_path = Path(root_dir).resolve()
    output_path = Path(output_file).resolve()

    if not root_path.exists() or not root_path.is_dir():
        print(f"\n❌ Erreur : Le dossier '{root_path}' n'existe pas ou n'est pas un répertoire.")
        return

    print(f"\n🔍 Dossier racine : {root_path}")
    print(f"⏭️  Dossiers ignorés : {', '.join(sorted(ignore_set)) if ignore_set else 'Aucun'}")
    print(f"📄 Fichier de sortie : {output_path}")
    print("\n🚀 Démarrage de l'export... (veuillez patienter)\n")

    try:
        with open(output_path, 'w', encoding='utf-8') as out_f:
            out_f.write(f"# EXPORT DE CODE - DOSSIER RACINE : {root_path}\n")
            out_f.write(f"# Date de l'export : {datetime.datetime.now()}\n\n")

            total_files = 0
            ignored_files = 0

            # Parcours récursif via rglob
            for file_path in root_path.rglob('*'):
                if file_path.is_dir():
                    continue

                # Vérifier si le chemin contient un dossier à ignorer
                should_ignore = False
                for part in file_path.parts:
                    if part in ignore_set:
                        should_ignore = True
                        break

                if should_ignore:
                    ignored_files += 1
                    continue

                # Lecture du fichier
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()

                    # Écriture du fichier dans l'export
                    rel_path = file_path.relative_to(root_path)
                    out_f.write(f"\n{'=' * 80}\n")
                    out_f.write(f"FICHIER : {rel_path}\n")
                    out_f.write(f"{'=' * 80}\n")
                    out_f.write(content)
                    out_f.write("\n")

                    total_files += 1
                    if total_files % 50 == 0:
                        print(f"✅ {total_files} fichiers traités...")

                except UnicodeDecodeError:
                    ignored_files += 1
                    continue
                except PermissionError:
                    print(f"⚠️ Permission refusée pour : {file_path}")
                    ignored_files += 1
                    continue
                except Exception as e:
                    print(f"⚠️ Erreur inattendue pour {file_path} : {e}")
                    ignored_files += 1
                    continue

        print(f"\n🎉 Export terminé avec succès !")
        print(f"📊 Fichiers exportés : {total_files}")
        print(f"⏭️  Fichiers ignorés (exclus ou binaires) : {ignored_files}")

    except Exception as e:
        print(f"\n❌ Erreur fatale lors de l'export : {e}")

def main():
    print("\n" + "=" * 60)
    print("           EXPORTEUR DE CODE INTERACTIF")
    print("=" * 60 + "\n")

    # 1. Dossier racine à analyser
    root_dir = get_user_input("Entrez le dossier racine à analyser", ".")

    # 2. Dossiers à ignorer
    default_ignore_str = ",".join(sorted(DEFAULT_IGNORE_DIRS))
    ignore_input = get_user_input(
        "Entrez les dossiers à ignorer (séparés par des virgules)",
        default_ignore_str
    )
    ignore_set = set([d.strip() for d in ignore_input.split(',') if d.strip()])

    # 3. Nom du fichier de sortie
    output_file = get_user_input("Entrez le nom du fichier de sortie", "code_export.txt")

    # 4. Lancer l'export
    export_code_to_txt(root_dir, ignore_set, output_file)

if __name__ == "__main__":
    main()
