#!/usr/bin/env python3
"""fortigate-policy-parser — extrait les politiques d'une sauvegarde FortiOS.

Lit un fichier de configuration FortiGate (`.conf`), reconstruit les VDOM,
objets et politiques, puis exporte la table des règles en CSV et affiche un
bilan. Bibliothèque standard uniquement.

Exemples :
  python fgt_parser.py samples/fortigate-exemple.conf
  python fgt_parser.py backup.conf --csv politiques.csv
  python fgt_parser.py backup.conf --vdom root --objects
  python fgt_parser.py backup.conf --resolve --csv politiques.csv   # puis fw-audit
"""

import argparse
import csv
import io
import sys

from fgtparser import (
    iter_vdoms,
    load_objects,
    load_policies,
    parse,
    summary,
    to_csv_rows,
)
from fgtparser.policy import CSV_FIELDS, RESOLVED_FIELDS, resolve_policy

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="fgt_parser",
        description="Extrait et cartographie les politiques d'une sauvegarde FortiOS.",
    )
    ap.add_argument("config", help="fichier de configuration FortiGate (.conf)")
    ap.add_argument("--csv", metavar="FICHIER", help="écrire la table des politiques en CSV (défaut : stdout avec --stdout-csv)")
    ap.add_argument("--stdout-csv", action="store_true", help="afficher le CSV sur la sortie standard")
    ap.add_argument("--vdom", help="ne traiter que ce VDOM")
    ap.add_argument("--objects", action="store_true", help="afficher aussi le nombre d'objets par VDOM")
    ap.add_argument(
        "--resolve",
        action="store_true",
        help="ajouter au CSV les adresses (sous-réseaux) et services (proto/ports) résolus, pour fw-audit",
    )
    args = ap.parse_args(argv)

    try:
        with open(args.config, "r", encoding="utf-8", errors="replace") as handle:
            text = handle.read()
    except OSError as err:
        ap.error(f"impossible de lire {args.config} ({err})")

    root = parse(text)
    vdoms = iter_vdoms(root)
    if args.vdom is not None:
        vdoms = [(name, node) for name, node in vdoms if name == args.vdom]
        if not vdoms:
            ap.error(f"VDOM introuvable : {args.vdom}")

    all_rows = []
    print(f"Configuration : {args.config}")
    for name, node in vdoms:
        policies = load_policies(node)
        if args.resolve:
            objects = load_objects(node)
            policies = [resolve_policy(p, objects) for p in policies]
        rows = to_csv_rows(policies, vdom_name=name, resolved=args.resolve)
        all_rows.extend(rows)
        stats = summary(policies)
        label = f"VDOM {name}" if name else "Politiques"
        print(f"\n{label} — {stats['total']} politique(s)")
        print(f"  actives : {stats['enabled']}   désactivées : {stats['disabled']}")
        print(f"  accept : {stats['accept']}   deny : {stats['deny']}")
        if stats["any_any_accept"]:
            print(f"  ⚠ any→any en accept : {stats['any_any_accept']}")
        if stats["accept_sans_log"]:
            print(f"  ⚠ accept sans journalisation : {stats['accept_sans_log']}")
        if stats["sans_nom"]:
            print(f"  ⚠ sans nom : {stats['sans_nom']}")
        if args.objects:
            obj = load_objects(node)
            print(
                f"  objets : {len(obj['addresses'])} adresses, "
                f"{len(obj['addrgrps'])} groupes, {len(obj['services'])} services"
            )

    if args.csv or args.stdout_csv:
        target = io.StringIO() if args.stdout_csv else open(args.csv, "w", newline="", encoding="utf-8")
        try:
            writer = csv.DictWriter(target, fieldnames=CSV_FIELDS + (RESOLVED_FIELDS if args.resolve else []))
            writer.writeheader()
            writer.writerows(all_rows)
            if args.stdout_csv:
                sys.stdout.write("\n" + target.getvalue())
        finally:
            if not args.stdout_csv:
                target.close()
                print(f"\nCSV écrit : {args.csv} ({len(all_rows)} ligne(s))")

    return 0


if __name__ == "__main__":
    sys.exit(main())
