# fortigate-policy-parser

![Python 3.7+](https://img.shields.io/badge/Python-3.7%2B-3776AB?logo=python&logoColor=white) ![Bibliothèque standard](https://img.shields.io/badge/d%C3%A9pendances-aucune-2E7D32) ![Tests](https://img.shields.io/badge/tests-unittest-455A64) ![Licence MIT](https://img.shields.io/badge/licence-MIT-546E7A)

**FR** — Lit une sauvegarde de configuration FortiGate (FortiOS) et en extrait la table des politiques de pare-feu : VDOM, objets, règles, export CSV et bilan de qualification. Outil d'aide à l'audit FortiGate, Python 3, bibliothèque standard uniquement.

**EN** — Parses a FortiGate (FortiOS) configuration backup and extracts the firewall policy table: VDOMs, objects, rules, CSV export and a qualification summary. A FortiGate audit helper, Python 3, standard library only.

---

## Français

### Objectif

Transformer un export de configuration FortiOS — plusieurs milliers de lignes — en une table lisible où chaque règle est une ligne, prête pour un tableur ou un autre outil d'audit, et donner un premier bilan qui **qualifie** les règles sans se substituer au jugement de l'auditeur.

### Contexte cybersécurité

Avant d'auditer un FortiGate, la mise à plat des politiques est la première étape, fastidieuse à faire à la main. Ce projet prolonge une mission réelle : l'audit d'un FortiGate 601E (FortiOS 7.4.9) et la création d'un outil Python de parsing d'exports de configuration pour cartographier et qualifier les règles.

Une sauvegarde FortiGate contient des informations très sensibles (architecture, objets, parfois des secrets VPN et des hachages) : ne jamais publier de configuration réelle dans un dépôt, et traiter le CSV produit comme un livrable d'audit.

### Fonctionnalités

- Analyse générique de la syntaxe FortiOS (`config` / `edit` / `set` / `unset` / `next` / `end`), valeurs entre guillemets et multi-valeurs gérées.
- Gestion des **VDOM** : chaque `config vdom / edit <nom>` est traité séparément ; une configuration sans VDOM fonctionne aussi.
- Reconstruction des objets : adresses, groupes d'adresses, services, groupes de services, avec résolution récursive des groupes (protégée contre les cycles).
- Extraction des politiques (`firewall policy`) avec les valeurs par défaut de FortiOS (action `deny`, status `enable`, log `disable`…).
- Export CSV (fichier ou sortie standard), une ligne par règle.
- Bilan de qualification par VDOM : total, actives / désactivées, accept / deny, et constats — any→any en accept, accept sans journalisation, règles sans nom.
- **`--resolve`** : ajoute trois colonnes résolues au CSV — sous-réseaux et FQDN des adresses (groupes développés, masque converti en /n), et services en `protocole/ports` (services personnalisés, groupes de services et services prédéfinis FortiOS). Un objet inconnu est conservé préfixé de `?`. Ce CSV est lu directement par [fw-audit](https://github.com/Lenu-san/fw-audit).

### Technologies et outils

- Python 3.7+ : `shlex`, `csv`, `argparse`, `io`
- Aucune dépendance externe, aucun accès réseau
- Tests : `unittest`

```
fgt_parser.py         ligne de commande (bilan, export CSV)
fgtparser/
  config.py           analyse de la syntaxe FortiOS en arbre générique
  policy.py           reconstruction des objets, des politiques, bilan, résolution
  services.py         services prédéfinis FortiOS (HTTP, RDP, ALL_TCP…)
tests/
  test_parser.py      tests unitaires
samples/
  fortigate-exemple.conf  configuration fictive (1 VDOM, 4 objets, 5 règles)
```

`config.py` ne fait qu'analyser la syntaxe ; `policy.py` donne du sens. La logique est réutilisable en import : `from fgtparser import load_policies`.

### Compatibilité

Fonctionne sous Windows, Linux et macOS : Python 3.7 ou plus, bibliothèque standard uniquement, aucun paquet à installer. Seul le nom de la commande Python change selon le système.

| Système | Vérifier Python | Lancer l'outil | Lancer les tests |
|---|---|---|---|
| Windows (PowerShell ou Invite de commandes) | `py --version` ou `python --version` | `py fgt_parser.py samples/fortigate-exemple.conf` | `py -m unittest discover -s tests -v` |
| Linux (Debian, Ubuntu…) | `python3 --version` | `python3 fgt_parser.py samples/fortigate-exemple.conf` | `python3 -m unittest discover -s tests -v` |
| macOS | `python3 --version` | `python3 fgt_parser.py samples/fortigate-exemple.conf` | `python3 -m unittest discover -s tests -v` |

Les exemples ci-dessous utilisent `python` : remplacer par `py` ou `python3` si nécessaire. Sous Windows, préférer PowerShell ou Windows Terminal pour l'affichage correct des accents et des couleurs.

### Installation

```bash
git clone https://github.com/Lenu-san/fortigate-policy-parser.git
cd fortigate-policy-parser
python fgt_parser.py samples/fortigate-exemple.conf
```

### Utilisation

```bash
python fgt_parser.py samples/fortigate-exemple.conf
python fgt_parser.py backup.conf --csv politiques.csv
python fgt_parser.py backup.conf --vdom root --objects
python fgt_parser.py backup.conf --stdout-csv
python fgt_parser.py backup.conf --resolve --csv politiques.csv
python -m unittest discover -s tests -v
```

Chaînage avec fw-audit, en deux commandes :

```bash
python fgt_parser.py sauvegarde.conf --resolve --csv politiques.csv   # ici
python fw_audit.py politiques.csv                                     # dans fw-audit
```

Colonnes du CSV : `vdom, id, name, srcintf, dstintf, srcaddr, dstaddr, service, action, status, nat, logtraffic, schedule, comments`, plus `srcaddr_resolved, dstaddr_resolved, service_resolved` avec `--resolve` (par exemple `192.168.10.0/24`, `update.exemple-editeur.com`, `tcp/80 tcp/443`).

### Résultats

Sur la configuration d'exemple :

```
Configuration : samples/fortigate-exemple.conf

VDOM root — 5 politique(s)
  actives : 4   désactivées : 1
  accept : 4   deny : 1
  ⚠ any→any en accept : 1
  ⚠ accept sans journalisation : 1
  ⚠ sans nom : 1
```

La règle 3 (any→any en accept, sans nom, sans journalisation, commentée « regle temporaire debug ») est exactement le genre de règle qu'un audit doit remonter. 12 tests unitaires passants, dont la résolution des objets.

### Limites

- **Politiques IPv4 (`firewall policy`)** uniquement : `firewall policy6`, `firewall proxy-policy` et les politiques NGFW par nom ne sont pas extraites.
- Qualification volontairement simple (any→any, désactivée, sans log, sans nom) : pas d'analyse de politique complète (règles masquées, redondantes ou contradictoires non détectées, ordre non pris en compte).
- Sans `--resolve`, la ligne CSV garde les noms d'objets. Avec `--resolve`, seuls les services prédéfinis présents dans `services.py` (les plus courants) sont traduits ; un service prédéfini absent de la table reste un nom préfixé de `?`. Les adresses dynamiques, géographiques ou de type interface ne sont pas résolues.
- Testé sur des exports FortiOS 7.x ; des sections non gérées sont ignorées sans erreur.
- Pas de gestion des sauvegardes chiffrées.

### Améliorations possibles

- Extraction des sections `policy6` et des politiques NGFW par nom.
- Compléter la table des services prédéfinis FortiOS.
- Tests sur des exports de plusieurs versions de FortiOS.

---

## English

### Objective

Turn a FortiOS configuration export — thousands of lines — into a readable table with one rule per row, ready for a spreadsheet or another audit tool, and print a first summary that **qualifies** the rules without replacing the auditor's judgement.

### Cybersecurity context

Before auditing a FortiGate, flattening the policies is the first step, and a tedious one by hand. This project extends a real assignment: the audit of a FortiGate 601E (FortiOS 7.4.9) and the creation of a Python tool to parse configuration exports in order to map and qualify the rules.

A FortiGate backup contains highly sensitive information (architecture, objects, sometimes VPN secrets and hashes): never publish a real configuration in a repository, and treat the generated CSV as an audit deliverable.

### Features

- Generic parsing of the FortiOS syntax (`config` / `edit` / `set` / `unset` / `next` / `end`), with quoted and multi-value fields.
- **VDOM** support: each `config vdom / edit <name>` is handled separately; configurations without VDOMs work too.
- Object reconstruction: addresses, address groups, services, service groups, with recursive group resolution (cycle-safe).
- Policy extraction (`firewall policy`) with FortiOS defaults (action `deny`, status `enable`, log `disable`…).
- CSV export (file or standard output), one row per rule.
- Per-VDOM qualification summary: total, enabled / disabled, accept / deny, and findings — any→any accept, accept without logging, unnamed rules.
- **`--resolve`**: adds three resolved columns to the CSV — address subnets and FQDNs (groups expanded, netmask converted to /n) and services as `protocol/ports` (custom services, service groups and FortiOS predefined services). Unknown objects are kept with a `?` prefix. That CSV is read directly by [fw-audit](https://github.com/Lenu-san/fw-audit).

### Technologies and tools

- Python 3.7+: `shlex`, `csv`, `argparse`, `io`
- No external dependency, no network access
- Tests: `unittest`

```
fgt_parser.py         command line (summary, CSV export)
fgtparser/
  config.py           FortiOS syntax parsed into a generic tree
  policy.py           objects, policies, summary and resolution
  services.py         FortiOS predefined services (HTTP, RDP, ALL_TCP…)
tests/
  test_parser.py      unit tests
samples/
  fortigate-exemple.conf  fictional configuration (1 VDOM, 4 objects, 5 rules)
```

`config.py` only parses the syntax; `policy.py` gives it meaning. The logic is importable: `from fgtparser import load_policies`.

### Compatibility

Runs on Windows, Linux and macOS: Python 3.7 or later, standard library only, nothing to install. Only the name of the Python command differs between systems.

| System | Check Python | Run the tool | Run the tests |
|---|---|---|---|
| Windows (PowerShell or Command Prompt) | `py --version` or `python --version` | `py fgt_parser.py samples/fortigate-exemple.conf` | `py -m unittest discover -s tests -v` |
| Linux (Debian, Ubuntu…) | `python3 --version` | `python3 fgt_parser.py samples/fortigate-exemple.conf` | `python3 -m unittest discover -s tests -v` |
| macOS | `python3 --version` | `python3 fgt_parser.py samples/fortigate-exemple.conf` | `python3 -m unittest discover -s tests -v` |

The examples below use `python`: replace with `py` or `python3` where needed. On Windows, prefer PowerShell or Windows Terminal so that accented characters and colours display correctly.

### Installation

```bash
git clone https://github.com/Lenu-san/fortigate-policy-parser.git
cd fortigate-policy-parser
python fgt_parser.py samples/fortigate-exemple.conf
```

### Usage

```bash
python fgt_parser.py samples/fortigate-exemple.conf
python fgt_parser.py backup.conf --csv policies.csv
python fgt_parser.py backup.conf --vdom root --objects
python fgt_parser.py backup.conf --stdout-csv
python fgt_parser.py backup.conf --resolve --csv policies.csv
python -m unittest discover -s tests -v
```

Chaining with fw-audit, in two commands:

```bash
python fgt_parser.py backup.conf --resolve --csv policies.csv   # here
python fw_audit.py policies.csv                                 # in fw-audit
```

CSV columns: `vdom, id, name, srcintf, dstintf, srcaddr, dstaddr, service, action, status, nat, logtraffic, schedule, comments`, plus `srcaddr_resolved, dstaddr_resolved, service_resolved` with `--resolve` (for instance `192.168.10.0/24`, `update.exemple-editeur.com`, `tcp/80 tcp/443`). Output messages are in French.

### Results

On the sample configuration: 5 policies in VDOM `root`, 4 enabled / 1 disabled, 4 accept / 1 deny, and three findings — one any→any accept, one accept without logging, one unnamed rule (see the French section for the full output). Rule 3 (any→any accept, unnamed, unlogged, commented “temporary debug rule”) is exactly the kind of rule an audit must surface. 12 passing unit tests, including object resolution.

### Limitations

- **IPv4 policies (`firewall policy`) only**: `firewall policy6`, `firewall proxy-policy` and name-based NGFW policies are not extracted.
- Deliberately simple qualification (any→any, disabled, unlogged, unnamed): not a full policy analysis (shadowed, redundant or contradictory rules are not detected, order is ignored).
- Without `--resolve`, CSV rows keep object names. With `--resolve`, only the predefined services listed in `services.py` (the common ones) are translated; a predefined service missing from the table stays a `?`-prefixed name. Dynamic, geographic or interface-type addresses are not resolved.
- Tested on FortiOS 7.x exports; unhandled sections are ignored without error.
- No support for encrypted backups.

### Possible improvements

- Extraction of `policy6` sections and name-based NGFW policies.
- Complete the FortiOS predefined services table.
- Tests on exports from several FortiOS versions.

---

## Auteur / Author

**Lénusan Gunarajah** — ingénieur cybersécurité junior : audit de sécurité, sécurité des infrastructures et services managés. / Junior cybersecurity engineer: security auditing, infrastructure security and managed services.

- Portfolio : https://lenu-san.github.io
- GitHub : https://github.com/Lenu-san
- LinkedIn : https://www.linkedin.com/in/l%C3%A9nusan-g-0470b6336

## Licence / License

MIT
