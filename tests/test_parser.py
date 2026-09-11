import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fgtparser import iter_vdoms, load_objects, load_policies, parse, summary, to_csv_rows  # noqa: E402
from fgtparser.policy import expand_group  # noqa: E402

HERE = os.path.dirname(__file__)
SAMPLE = os.path.join(HERE, "..", "samples", "fortigate-exemple.conf")


def load_root():
    with open(SAMPLE, encoding="utf-8") as handle:
        return parse(handle.read())


class ParseTests(unittest.TestCase):
    def test_vdom_detected(self):
        vdoms = iter_vdoms(load_root())
        self.assertEqual([name for name, _ in vdoms], ["root"])

    def test_quoted_values_and_multi_token(self):
        root = load_root()
        _, node = iter_vdoms(root)[0]
        policies = load_policies(node)
        p1 = next(p for p in policies if p["id"] == "1")
        self.assertEqual(p1["name"], "LAN_vers_Internet")
        self.assertEqual(p1["srcaddr"], ["LAN_USERS"])
        self.assertEqual(p1["service"], ["WEB"])
        self.assertEqual(p1["nat"], "enable")

    def test_defaults(self):
        # la règle 3 n'a pas de status -> enable ; la règle 5 est disable
        _, node = iter_vdoms(load_root())[0]
        by_id = {p["id"]: p for p in load_policies(node)}
        self.assertEqual(by_id["3"]["status"], "enable")
        self.assertEqual(by_id["3"]["action"], "accept")
        self.assertEqual(by_id["5"]["status"], "disable")
        self.assertEqual(by_id["5"]["action"], "deny")

    def test_objects(self):
        _, node = iter_vdoms(load_root())[0]
        obj = load_objects(node)
        self.assertIn("LAN_USERS", obj["addresses"])
        self.assertEqual(obj["addresses"]["MAJ_EDITEUR"]["type"], "fqdn")
        self.assertEqual(obj["addrgrps"]["SERVEURS_INTERNES"], ["SRV_WEB", "SRV_DB"])
        self.assertEqual(obj["servicegrps"]["WEB"], ["HTTP", "HTTPS"])

    def test_expand_group_and_cycle(self):
        groups = {"A": ["B", "x"], "B": ["A", "y"]}  # cycle volontaire
        self.assertEqual(sorted(set(expand_group("A", groups))), ["x", "y"])

    def test_summary_flags(self):
        _, node = iter_vdoms(load_root())[0]
        stats = summary(load_policies(node))
        self.assertEqual(stats["total"], 5)
        self.assertEqual(stats["enabled"], 4)
        self.assertEqual(stats["disabled"], 1)
        self.assertEqual(stats["any_any_accept"], 1)  # règle 3
        self.assertEqual(stats["accept_sans_log"], 1)  # règle 3
        self.assertEqual(stats["sans_nom"], 1)  # règle 3

    def test_csv_rows(self):
        _, node = iter_vdoms(load_root())[0]
        rows = to_csv_rows(load_policies(node), vdom_name="root")
        self.assertEqual(rows[0]["vdom"], "root")
        self.assertEqual(rows[0]["dstaddr"], "all")
        # les listes multi-valeurs sont jointes par un espace
        self.assertEqual(rows[0]["service"], "WEB")


class NoVdomTests(unittest.TestCase):
    def test_config_without_vdom(self):
        text = """config firewall policy
    edit 1
        set name "test"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "ALL"
    next
end
"""
        root = parse(text)
        vdoms = iter_vdoms(root)
        self.assertEqual(vdoms[0][0], "")
        self.assertEqual(len(load_policies(vdoms[0][1])), 1)


if __name__ == "__main__":
    unittest.main()


class ResolveTests(unittest.TestCase):
    def _resolved(self):
        from fgtparser import resolve_policy

        _, node = iter_vdoms(load_root())[0]
        objects = load_objects(node)
        return {p["id"]: resolve_policy(p, objects) for p in load_policies(node)}

    def test_addresses_groups_and_all(self):
        by_id = self._resolved()
        self.assertEqual(by_id["1"]["srcaddr_resolved"], ["192.168.10.0/24"])
        self.assertEqual(by_id["1"]["dstaddr_resolved"], ["all"])
        # SERVEURS_INTERNES est un groupe : deux sous-réseaux résolus
        self.assertEqual(len(by_id["2"]["dstaddr_resolved"]), 2)
        self.assertTrue(all("/" in a for a in by_id["2"]["dstaddr_resolved"]))

    def test_services_custom_group_and_predefined(self):
        by_id = self._resolved()
        self.assertEqual(by_id["1"]["service_resolved"], ["tcp/80", "tcp/443"])   # groupe WEB
        self.assertEqual(by_id["2"]["service_resolved"], ["tcp/8443"])           # service personnalisé
        self.assertEqual(by_id["3"]["service_resolved"], ["any"])                # ALL
        self.assertEqual(by_id["4"]["service_resolved"], ["tcp/443"])            # prédéfini HTTPS

    def test_unknown_object_is_flagged_not_dropped(self):
        from fgtparser.policy import resolve_addresses, resolve_services

        objects = {"addresses": {}, "addrgrps": {}, "services": {}, "servicegrps": {}}
        self.assertEqual(resolve_addresses(["INCONNU"], objects), ["?INCONNU"])
        self.assertEqual(resolve_services(["APP_X"], objects), ["?APP_X"])

    def test_csv_rows_with_resolved_columns(self):
        from fgtparser import resolve_policy

        _, node = iter_vdoms(load_root())[0]
        objects = load_objects(node)
        rows = to_csv_rows([resolve_policy(p, objects) for p in load_policies(node)], "root", resolved=True)
        self.assertIn("service_resolved", rows[0])
        self.assertEqual(rows[0]["service_resolved"], "tcp/80 tcp/443")
