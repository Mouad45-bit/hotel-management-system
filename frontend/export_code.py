#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import datetime  # <-- L'importation est déplacée ici !
from pathlib import Path

# Liste des dossiers à ignorer
IGNORED_DIRS = {
    '.git', 'node_modules', 'target', '.idea', 'out', 'build', 'dist',
    '__pycache__', '.venv', 'env', 'venv', '.env', 'docker-data',
    '.next', '.nuxt', '.vscode', '.gradle', 'logs'
}

# Extensions de fichiers textes
TEXT_EXTENSIONS = {
    '.java', '.py', '.js', '.ts', '.jsx', '.tsx', '.c', '.cpp', '.h', '.hpp',
    '.html', '.css', '.scss', '.xml', '.json', '.yaml', '.yml', '.properties',
    '.md', '.txt', '.csv', '.conf', '.cfg', '.ini', '.sql', '.sh', '.bat',
    '.ps1', '.dockerfile', '.gradle', '.mvn', '.xml', '.groovy', '.kt', '.kts'
}

def export_code_to_txt(root_dir, output_file="code_export.txt"):
    root_path = Path(root_dir).resolve()
    output_path = Path(output_file).resolve()

    if not root_path.exists():
        print(f"❌ Erreur : Le dossier '{root_dir}' n'existe pas.")
        return

    print(f"🔍 Analyse du dossier : {root_path}")
    print(f"📄 Les résultats seront exportés vers : {output_path}")

    with open(output_path, 'w', encoding='utf-8') as out_f:
        out_f.write(f"# EXPORT DE CODE - DOSSIER RACINE : {root_path}\n")
        out_f.write(f"# Date de l'export : {datetime.datetime.now()}\n\n")  # <-- Plus d'erreur ici

        total_files = 0
        ignored_files = 0

        # Parcours récursif de tous les fichiers
        for file_path in root_path.rglob('*'):
            if file_path.is_dir():
                continue

            # Vérifier si le chemin contient un dossier à ignorer
            should_ignore = False
            for part in file_path.parts:
                if part in IGNORED_DIRS:
                    should_ignore = True
                    break

            if should_ignore:
                ignored_files += 1
                continue

            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()

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
            except Exception as e:
                print(f"⚠️ Impossible de lire le fichier {file_path} : {e}")
                ignored_files += 1
                continue

    print(f"\n🎉 Export terminé !")
    print(f"📊 Fichiers exportés : {total_files}")
    print(f"⏭️  Fichiers ignorés (binaires ou dossier exclus) : {ignored_files}")
    print(f"📍 Fichier créé : {output_path}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target_dir = sys.argv[1]
    else:
        target_dir = "."
    export_code_to_txt(target_dir)
