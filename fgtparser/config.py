"""Lecture d'une sauvegarde de configuration FortiOS.

Le format est une suite de blocs :

    config firewall policy
        edit 1
            set name "LAN_vers_Internet"
            set srcaddr "LAN_USERS" "POSTES_TECH"
        next
    end

On le transforme en arbre générique (sections / entrées / réglages) sans rien
interpréter : c'est policy.py qui donne un sens aux objets. Les VDOM sont
gérés naturellement, « config vdom / edit root » n'étant qu'une imbrication
de plus.
"""

import shlex


def new_node():
    return {"settings": {}, "sections": {}, "entries": {}}


def _split(line):
    # shlex gère les valeurs entre guillemets et les \" échappés comme FortiOS
    try:
        return shlex.split(line, posix=True)
    except ValueError:
        return line.split()


def parse(text):
    """Renvoie l'arbre racine d'une sauvegarde FortiOS."""
    root = new_node()
    stack = [root]

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        tokens = _split(line)
        if not tokens:
            continue
        cmd, args = tokens[0], tokens[1:]
        current = stack[-1]

        if cmd == "config":
            stack.append(current["sections"].setdefault(" ".join(args), new_node()))
        elif cmd == "edit":
            stack.append(current["entries"].setdefault(" ".join(args), new_node()))
        elif cmd == "set" and args:
            current["settings"][args[0]] = args[1:]
        elif cmd == "unset" and args:
            current["settings"].pop(args[0], None)
        elif cmd in ("next", "end"):
            if len(stack) > 1:
                stack.pop()
        # autres commandes (abort, purge...) : ignorées

    return root


def section(node, name):
    """Section directe d'un nœud, ou une section vide si absente."""
    return node["sections"].get(name, new_node())


def find_sections(node, name, path=()):
    """Toutes les sections portant ce nom, à n'importe quelle profondeur.

    Renvoie une liste de (chemin, section), le chemin étant la suite des
    entrées parentes — par exemple ('root',) pour un VDOM.
    """
    found = []
    for sec_name, sec in node["sections"].items():
        if sec_name == name:
            found.append((path, sec))
        found.extend(find_sections(sec, name, path))
        for entry_name, entry in sec["entries"].items():
            found.extend(find_sections(entry, name, path + (entry_name,)))
    return found


def iter_vdoms(root):
    """Renvoie [(nom_vdom, nœud)] : chaque VDOM, ou ('', racine) sans VDOM."""
    vdom = root["sections"].get("vdom")
    if vdom and vdom["entries"]:
        return [(name, node) for name, node in vdom["entries"].items()]
    return [("", root)]
