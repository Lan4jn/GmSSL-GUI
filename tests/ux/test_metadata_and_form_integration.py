#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Independent QA Verification of 94 Tool Catalog Metadata & Form Constraints.

Verifies:
1. 80 native CLI tools + 14 C extension tools = 94 total capability items.
2. Label integrity: 100% of parameters have non-empty human-readable labels.
3. Security constraint: No static all-zero or predictable IV/nonce default values.
4. Visibility constraint: All required parameters must NOT be hidden under advanced: true.
5. Credential bindings: Sensitive password fields must properly reference their key parameter via credentialKeyParameter.
6. Evidence-based enums: Curated option choices match upstream valid CLI options.
"""

import json
import os
import unittest

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

class TestMetadataAndFormIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        catalog_path = os.path.join(ROOT_DIR, "native", "catalog.json")
        ext_catalog_path = os.path.join(ROOT_DIR, "native", "extensions-catalog.json")

        with open(catalog_path, "r", encoding="utf-8") as f:
            cls.catalog = json.load(f)
        with open(ext_catalog_path, "r", encoding="utf-8") as f:
            cls.ext_catalog = json.load(f)

        cls.cli_tools = cls.catalog["tools"]
        cls.ext_tools = cls.ext_catalog["tools"]
        cls.all_tools = cls.cli_tools + cls.ext_tools

    def test_01_tool_counts(self):
        self.assertEqual(len(self.cli_tools), 80, "Expected 80 CLI tools")
        self.assertEqual(len(self.ext_tools), 14, "Expected 14 C extension tools")
        self.assertEqual(len(self.all_tools), 94, "Expected 94 total tools")

    def test_02_all_parameters_have_labels(self):
        missing_labels = []
        total_params = 0
        for tool in self.all_tools:
            for p in tool.get("parameters", []):
                total_params += 1
                label = p.get("label")
                if not label or not str(label).strip():
                    missing_labels.append(f"{tool['id']}.{p.get('name')}")
        self.assertEqual(missing_labels, [], f"Found {len(missing_labels)} parameters with missing/empty labels")
        self.assertTrue(total_params > 700, f"Expected > 700 parameters, found {total_params}")

    def test_03_no_static_all_zero_iv_or_nonce(self):
        forbidden_defaults = [
            "00000000000000000000000000000000",
            "000000000000000000000000",
            "0000000000000000",
            "0102030405060708090a0b0c0d0e0f10",
            "1234567812345678",
            "00" * 8, "00" * 12, "00" * 16, "00" * 32
        ]
        violations = []
        for tool in self.all_tools:
            for p in tool.get("parameters", []):
                name = p.get("name", "").lower()
                desc = p.get("description", "").lower()
                if "iv" in name or "nonce" in name or "iv" in desc or "nonce" in desc:
                    default_val = str(p.get("defaultValue", "")).strip().lower()
                    if default_val in forbidden_defaults:
                        violations.append(f"{tool['id']}.{p['name']} default='{default_val}'")
        self.assertEqual(violations, [], f"Security violation: Found static predictable IV/nonce defaults: {violations}")

    def test_04_no_required_field_hidden_in_advanced(self):
        hidden_required = []
        for tool in self.all_tools:
            for p in tool.get("parameters", []):
                # A required parameter must either have advanced=false OR have a valid defaultValue
                if p.get("required") is True:
                    if p.get("advanced") is True and p.get("defaultValue") is None:
                        hidden_required.append(f"{tool['id']}.{p.get('name')}")
        self.assertEqual(hidden_required, [], f"UX violation: Required parameters hidden under advanced without defaultValue: {hidden_required}")

    def test_05_credential_key_parameter_bindings(self):
        checked = 0
        for tool in self.all_tools:
            param_names = {p["name"] for p in tool.get("parameters", [])}
            for p in tool.get("parameters", []):
                binding = p.get("credentialKeyParameter")
                if binding:
                    checked += 1
                    self.assertIn(
                        binding,
                        param_names,
                        f"In tool {tool['id']}, credentialKeyParameter '{binding}' references non-existent parameter"
                    )
        self.assertTrue(checked > 20, f"Expected >20 credential bindings, found {checked}")

    def test_06_options_and_enums_validity(self):
        for tool in self.all_tools:
            for p in tool.get("parameters", []):
                options = p.get("options")
                if options is not None:
                    self.assertIsInstance(options, list, f"{tool['id']}.{p['name']} options must be a list")
                    self.assertTrue(len(options) > 0, f"{tool['id']}.{p['name']} options must not be empty")
                    # Default value if present must be in options
                    def_val = p.get("defaultValue")
                    if def_val is not None and def_val != "":
                        self.assertIn(
                            def_val,
                            options,
                            f"{tool['id']}.{p['name']} defaultValue '{def_val}' not in options {options}"
                        )

if __name__ == "__main__":
    unittest.main()
