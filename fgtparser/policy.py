"""Interprétation des objets et des politiques d'un nœud FortiOS.

À partir de l'arbre produit par config.py, on reconstruit les objets adresses,
groupes d'adresses et services, puis on lit la section « firewall policy ».
Chaque politique est mise à plat en une ligne exploitable (CSV), et un petit
bilan qualifie les règles (any→any, désactivées, sans journalisation…) — le
travail de cartographie et de qualification fait lors d'un audit.
"""

# Valeurs FortiOS qui signifient « tout ».
ANY_ADDR = {"all"}
ANY_SVC = {"ALL"}


def _val(node, key, default=""):
    """Premier jeton d'un réglage, ou une valeur par défaut."""
    tokens = node["settings"].get(key)
    return tokens[0] if tokens else default


def _list(node, key):
    """Tous les jetons d'un réglage (adresses, services multiples)."""
    return list(node["settings"].get(key, []))


def load_objects(vdom):
    """Renvoie un dict des objets définis dans un VDOM (ou la racine)."""
    from .config import section

    addresses = {}
    for name, entry in section(vdom, "firewall address")["entries"].items():
        addresses[name] = {
            "type": _val(entry, "type", "ipmask"),
            "subnet": " ".join(entry["settings"].get("subnet", [])),
            "fqdn": _val(entry, "fqdn"),
        }

    addrgrps = {}
    for name, entry in section(vdom, "firewall addrgrp")["entries"].items():
        addrgrps[name] = _list(entry, "member")

    services = {}
    for name, entry in section(vdom, "firewall service custom")["entries"].items():
        services[name] = {
            "tcp": _list(entry, "tcp-portrange"),
            "udp": _list(entry, "udp-portrange"),
        }

    servicegrps = {}
    for name, entry in section(vdom, "firewall service group")["entries"].items():
        servicegrps[name] = _list(entry, "member")

    return {
        "addresses": addresses,
        "addrgrps": addrgrps,
        "services": services,
        "servicegrps": servicegrps,
    }


def expand_group(name, groups, _seen=None):
    """Résout récursivement les membres d'un groupe en feuilles.

    Protégé contre les cycles (un groupe qui se contient indirectement).
    """
    if _seen is None:
        _seen = set()
    if name in _seen:
        return []
    _seen.add(name)
    if name not in groups:
        return [name]
    leaves = []
    for member in groups[name]:
        leaves.extend(expand_group(member, groups, _seen))
    return leaves


def load_policies(vdom):
    """Liste les politiques de la section « firewall policy » d'un VDOM."""
    from .config import section

    policies = []
    for pid, entry in section(vdom, "firewall policy")["entries"].items():
        policies.append(
            {
                "id": pid,
                "name": _val(entry, "name"),
                "srcintf": _list(entry, "srcintf"),
                "dstintf": _list(entry, "dstintf"),
                "srcaddr": _list(entry, "srcaddr"),
                "dstaddr": _list(entry, "dstaddr"),
                "service": _list(entry, "service"),
                "action": _val(entry, "action", "deny"),  # FortiOS : deny par défaut
                "status": _val(entry, "status", "enable"),  # enable par défaut
                "schedule": _val(entry, "schedule", "always"),
                "logtraffic": _val(entry, "logtraffic", "disable"),
                "nat": _val(entry, "nat", "disable"),
                "comments": _val(entry, "comments"),
            }
        )
    return policies


CSV_FIELDS = [
    "vdom", "id", "name", "srcintf", "dstintf", "srcaddr", "dstaddr",
    "service", "action", "status", "nat", "logtraffic", "schedule", "comments",
]

# Colonnes ajoutées par --resolve : objets et services mis à plat.
RESOLVED_FIELDS = ["srcaddr_resolved", "dstaddr_resolved", "service_resolved"]


def resolve_addresses(names, objects):
    """Remplace des noms d'adresses/groupes par leurs sous-réseaux ou FQDN.

    « all » reste « all ». Un nom inconnu (objet non défini dans le VDOM,
    adresse dynamique, géographie…) est conservé tel quel, préfixé d'un « ? »
    pour signaler qu'il n'a pas été résolu.
    """
    out = []
    for name in names:
        if name in ANY_ADDR:
            out.append("all")
            continue
        for leaf in expand_group(name, objects["addrgrps"]):
            addr = objects["addresses"].get(leaf)
            if addr is None:
                out.append("?" + leaf)
            elif addr["fqdn"]:
                out.append(addr["fqdn"])
            elif addr["subnet"]:
                ip, _, mask = addr["subnet"].partition(" ")
                out.append(_cidr(ip, mask))
            else:
                out.append("?" + leaf)
    return out


def _cidr(ip, mask):
    """« 10.0.0.0 255.255.255.0 » -> « 10.0.0.0/24 » ; masque déjà en /n conservé."""
    if not mask:
        return ip
    if mask.isdigit():
        return f"{ip}/{mask}"
    try:
        bits = sum(bin(int(octet)).count("1") for octet in mask.split("."))
    except ValueError:
        return f"{ip} {mask}"
    return f"{ip}/{bits}"


def resolve_services(names, objects):
    """Remplace des noms de services par « proto/ports » (tcp/8443, udp/53…).

    Ordre de recherche : service personnalisé du VDOM, groupe de services,
    puis service prédéfini FortiOS. Un nom inconnu est conservé avec « ? ».
    """
    from .services import lookup

    out = []
    for name in names:
        if name in ANY_SVC:
            out.append("any")
            continue
        for leaf in expand_group(name, objects["servicegrps"]):
            custom = objects["services"].get(leaf)
            if custom is not None:
                for proto in ("tcp", "udp"):
                    for portrange in custom[proto]:
                        # FortiOS écrit « 8443 » ou « 8443:1024-65535 » (port dst:src) :
                        # seul le port de destination compte pour l'audit.
                        out.append(f"{proto}/{portrange.split(':')[0]}")
                if not custom["tcp"] and not custom["udp"]:
                    out.append("?" + leaf)
                continue
            predefined = lookup(leaf)
            if predefined is None:
                out.append("?" + leaf)
                continue
            for proto, ports in predefined:
                out.append("any" if proto == "any" else f"{proto}/{ports}")
    return out


def resolve_policy(policy, objects):
    """Renvoie une copie de la politique enrichie des champs *_resolved."""
    p = dict(policy)
    p["srcaddr_resolved"] = resolve_addresses(policy["srcaddr"], objects)
    p["dstaddr_resolved"] = resolve_addresses(policy["dstaddr"], objects)
    p["service_resolved"] = resolve_services(policy["service"], objects)
    return p


def to_csv_rows(policies, vdom_name="", resolved=False):
    """Transforme les politiques en lignes de dicts prêtes pour csv.DictWriter."""
    fields = CSV_FIELDS + (RESOLVED_FIELDS if resolved else [])
    rows = []
    for p in policies:
        row = {"vdom": vdom_name}
        for field in fields:
            if field == "vdom":
                continue
            value = p.get(field, "")
            row[field] = " ".join(value) if isinstance(value, list) else value
        rows.append(row)
    return rows


def _is_any_addr(values):
    return any(v in ANY_ADDR for v in values) or not values


def _is_any_svc(values):
    return any(v in ANY_SVC for v in values) or not values


def summary(policies):
    """Bilan chiffré et qualification des politiques (constats non bloquants)."""
    stats = {
        "total": len(policies),
        "enabled": 0,
        "disabled": 0,
        "accept": 0,
        "deny": 0,
        "any_any_accept": 0,
        "accept_sans_log": 0,
        "sans_nom": 0,
    }
    for p in policies:
        enabled = p["status"] == "enable"
        accept = p["action"] == "accept"
        stats["enabled" if enabled else "disabled"] += 1
        stats["accept" if accept else "deny"] += 1
        if not p["name"]:
            stats["sans_nom"] += 1
        if accept and _is_any_addr(p["srcaddr"]) and _is_any_addr(p["dstaddr"]) and _is_any_svc(p["service"]):
            stats["any_any_accept"] += 1
        if accept and enabled and p["logtraffic"] == "disable":
            stats["accept_sans_log"] += 1
    return stats
