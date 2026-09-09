"""Scrubber, vault, rules-file and dotenv contracts. Self-contained: built-in rules only."""
import json
import os
from pathlib import Path

import pytest

from local_llm_mcp.config import load_env_file
from local_llm_mcp.scrub import PLACEHOLDER_RE, Scrubber, Vault


@pytest.fixture
def terms(tmp_path):
    p = tmp_path / "terms.json"
    p.write_text(json.dumps({"terms": [
        {"kind": "PERSON", "values": ["Jane Q. Example"]},
        {"kind": "ADDRESS", "values": ["12 Example Lane"]},
    ]}))
    return p


@pytest.fixture
def scrubber(terms):
    return Scrubber(None, terms)


@pytest.fixture
def vault(tmp_path):
    return Vault(tmp_path / "vault.json")


def test_email_and_key_get_placeholders(scrubber, vault):
    text = "contact jane.example@example.org, key sk-abcdefghijklmnopqrstuvwxyz0123, again jane.example@example.org"  # gitleaks:allow
    r = scrubber.scrub(text, vault)
    assert "jane.example@example.org" not in r.text
    assert "sk-abcdefghijklmnop" not in r.text
    assert r.text.count("[EMAIL-1]") == 2
    assert "[SECRET-1]" in r.text
    assert r.replaced == 3


def test_placeholders_stable_and_rehydrate(scrubber, vault):
    r1 = scrubber.scrub("mail a@example.org", vault)
    r2 = scrubber.scrub("again a@example.org and b@example.org", vault)
    assert "[EMAIL-1]" in r1.text and "[EMAIL-1]" in r2.text and "[EMAIL-2]" in r2.text
    assert vault.rehydrate("send to [EMAIL-1], cc [EMAIL-2], keep [EMAIL-9]") == \
        "send to a@example.org, cc b@example.org, keep [EMAIL-9]"


def test_material_values_are_scrubbed_from_any_output(scrubber, vault):
    scrubber.register_material("PHONE: (555) 010-2233 belongs to Jane Q. Example", vault)
    r = scrubber.scrub("call (555) 010-2233; Jane Q. Example answered", vault)
    assert "(555) 010-2233" not in r.text and "Jane Q. Example" not in r.text
    assert "[PERSON-1]" in r.text


def test_private_terms_case_insensitive_whole_word(scrubber, vault):
    r = scrubber.scrub("JANE Q. EXAMPLE lives at 12 example lane; examples are fine", vault)
    assert "[PERSON-1]" in r.text and "[ADDRESS-1]" in r.text
    assert "examples are fine" in r.text


def test_env_lines_assignments_and_pem(scrubber, vault):
    text = ("export OPENAI_API_KEY=abcdef1234567890\nPASSWORD='hunter2hunter2'\n"  # gitleaks:allow
            "the password is hunter2\nthe secret is stored in the vault\n"  # gitleaks:allow
            "-----BEGIN RSA PRIVATE KEY-----\nMIIabcMIIabc\n-----END RSA PRIVATE KEY-----\n")  # gitleaks:allow
    r = scrubber.scrub(text, vault, secrets_only=True)
    for leaked in ("abcdef1234567890", "hunter2hunter2", "hunter2\n", "MIIabc"):  # gitleaks:allow
        assert leaked not in r.text, leaked
    assert "the secret is stored in the vault" in r.text
    assert r.kinds.get("SECRET", 0) >= 4


def test_references_and_placeholders_are_not_secrets(scrubber, vault):
    text = "api_key: os.environ/VLLM_KEY\npassword = $PASS\nTOKEN=<redacted>\nsecret: null\nkey: [SECRET-1]"
    r = scrubber.scrub(text, vault, secrets_only=True)
    assert r.replaced == 0, r


def test_secrets_only_keeps_email_but_full_scrub_does_not(scrubber, vault):
    r = scrubber.scrub("maintainer bob@example.org", vault, secrets_only=True)
    assert "bob@example.org" in r.text
    r = scrubber.scrub("maintainer bob@example.org", vault)
    assert "bob@example.org" not in r.text


def test_phone_bare_digits_need_context_unless_strict(tmp_path, terms):
    # Fresh vault per case: a value one scrub registers is exact-matched by the next.
    def fresh(i):
        return Vault(tmp_path / f"v{i}.json")
    sc = Scrubber(None, terms)
    assert sc.scrub("build 1788893464 finished", fresh(1)).replaced == 0
    assert sc.scrub("call me at 5550102233 tomorrow", fresh(2)).replaced == 1
    assert sc.scrub("5550102233", fresh(3)).replaced == 0
    assert sc.scrub("(555) 010-2233", fresh(4)).replaced == 1
    strict = Scrubber(None, terms, strict=True)
    assert strict.scrub("5550102233", fresh(5)).replaced == 1


def test_card_needs_luhn_and_is_not_a_timestamp_id(scrubber, vault):
    assert scrubber.scrub("card 4242 4242 4242 4242 on file", vault).kinds.get("CARD") == 1  # gitleaks:allow
    assert scrubber.scrub("card 4242 4242 4242 4243 on file", vault).replaced == 0
    assert scrubber.scrub("backup 20260908-154500 done", vault).replaced == 0


def test_vault_persists_with_0600(tmp_path, scrubber):
    v = Vault(tmp_path / "v.json")
    scrubber.scrub("x@example.org", v)
    assert oct(os.stat(tmp_path / "v.json").st_mode & 0o777) == "0o600"
    v2 = Vault(tmp_path / "v.json")
    assert v2.rehydrate("[EMAIL-1]") == "x@example.org"
    assert v2.counts() == {"EMAIL": 1}


def test_nothing_detectable_survives(scrubber, vault):
    text = ("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnopqrstuvwxyz\n"  # gitleaks:allow
            "xoxb-123456789012-abcdefghij")  # gitleaks:allow
    r = scrubber.scrub(text, vault)
    assert not [s for s in scrubber.find_spans(r.text) if not PLACEHOLDER_RE.fullmatch(s[3])]


def test_pii_mode_catches_unnamed_long_credentials(scrubber, vault):
    text = "WEIRD_NAME=Zq8pL2mN4vB7xC1kR9tY3wE6uI0oP5aS  path=/opt/x/Zq8pL2mN4vB7xC1kR9tY3wE6uI0oP5aS0"  # gitleaks:allow
    full = scrubber.scrub(text, vault)
    assert "Zq8pL2mN4vB7xC1kR9tY3wE6uI0oP5aS " not in full.text and "[SECRET-1]" in full.text
    assert "/opt/x/Zq8pL2mN4vB7xC1kR9tY3wE6uI0oP5aS0" in full.text  # a path segment is not a credential
    sha = "commit 3f2a9c1d4e5b6a7f8091a2b3c4d5e6f708192a3b4"
    assert scrubber.scrub(sha, vault, secrets_only=True).replaced == 0  # ASSIST mode keeps SHAs


def test_entity_registration_takes_values_not_labels(scrubber, vault):
    material = "DB_PASSWORD=hunter2hunter2\nOwner: Jane Q. Example\n"  # gitleaks:allow
    n = scrubber.register_entities([
        {"kind": "SECRET", "value": "DB_PASSWORD"},          # a label: ignored
        {"kind": "SECRET", "value": "hunter2hunter2"},       # the value: registered  # gitleaks:allow
        {"kind": "PERSON", "value": "Jane Q. Example"},
        {"kind": "PERSON", "value": "Nobody Here"},          # not in the material: ignored
    ], material, vault)
    assert n == 2
    r = scrubber.scrub("DB_PASSWORD is set for Jane Q. Example to hunter2hunter2", vault)  # gitleaks:allow
    assert r.text.startswith("DB_PASSWORD is set for [PERSON-") and "hunter2hunter2" not in r.text  # gitleaks:allow


def test_rules_file_replaces_builtins_and_tolerates_extra_keys(tmp_path, terms, vault):
    rules = tmp_path / "rules.json"
    rules.write_text(json.dumps({
        "enabled": True, "router_name": "unrelated", "phrase_rules": [{"id": "p", "pattern": "my password"}],
        "regex_rules": [
            {"id": "email", "pattern": r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"},
            {"id": "employee_id", "pattern": r"\bEMP-\d{6}\b"},
            {"id": "disabled_one", "pattern": r"never", "enabled": False},
        ]}))
    sc = Scrubber(rules, terms)
    assert sc.rules.source == str(rules) and len(sc.rules.regex) == 2
    r = sc.scrub("EMP-123456 wrote to a@example.org", vault)
    assert "[PII-1]" in r.text and "[EMAIL-1]" in r.text


def test_env_file_seeds_without_overriding(tmp_path, monkeypatch):
    f = tmp_path / "env"
    f.write_text('# comment\nexport LOCAL_LLM_MCP_MODEL="m1"\nLOCAL_LLM_MCP_MODE=pii # trailing\n'
                 'LOCAL_LLM_MCP_STATE_DIR=$HOME/x\nnot a line\n')
    monkeypatch.setenv("LOCAL_LLM_MCP_ENV_FILE", str(f))
    monkeypatch.setenv("LOCAL_LLM_MCP_MODE", "assist")
    monkeypatch.delenv("LOCAL_LLM_MCP_MODEL", raising=False)
    monkeypatch.delenv("LOCAL_LLM_MCP_STATE_DIR", raising=False)
    assert load_env_file() == 2
    assert os.environ["LOCAL_LLM_MCP_MODEL"] == "m1"
    assert os.environ["LOCAL_LLM_MCP_MODE"] == "assist"
    assert os.environ["LOCAL_LLM_MCP_STATE_DIR"] == os.path.expandvars("$HOME/x")


def test_assignment_value_that_is_a_variable_name_is_a_label(scrubber, vault):
    assert scrubber.scrub("SECRET: TELEGRAM_BOT_TOKEN\nCONFIG: OPENAI_BASE_URL", vault, secrets_only=True).replaced == 0
    assert scrubber.scrub("password: HUNTER2X", vault, secrets_only=True).replaced == 1  # gitleaks:allow


# ---------------------------------------------------------------- identity shapes (PII mode)


def test_identity_shapes_addresses(scrubber, vault):
    text = ("Ship to 1234 N Maple Street, Apt 4B, Springfield, IL 62704 and P.O. Box 889, Boston, MA 02134; "
            "office at 10 Downing Street. Meet in Portland, OR 97201.")
    r = scrubber.scrub(text, vault)
    for v in ("1234 N Maple Street, Apt 4B, Springfield, IL 62704", "P.O. Box 889, Boston, MA 02134",
              "10 Downing Street", "Portland, OR 97201"):
        assert v not in r.text, v
    assert r.kinds == {"ADDRESS": 4}
    assert "[ADDRESS-1]" in r.text and "[ADDRESS-4]" in r.text


def test_identity_shapes_names(scrubber, vault):
    text = ("Dr Ada Lovelace-Byron called. patient: Grace Hopper today.\n"
            "From: Alan M. Turing <alan@example.org>\nDear Hedy,\nthanks for the note.\nRegards,\nLinus Torvalds\n"
            '{"name": "Margaret Hamilton"}\nfirst name: Ken')
    r = scrubber.scrub(text, vault)
    for v in ("Ada Lovelace-Byron", "Grace Hopper", "Alan M. Turing", "Hedy", "Linus Torvalds", "Margaret Hamilton", "Ken"):
        assert v not in r.text, v
    assert r.kinds["PERSON"] == 7 and r.kinds["EMAIL"] == 1
    assert "Dr [PERSON-1] called" in r.text and "Regards,\n[PERSON-" in r.text and '"name": "[PERSON-' in r.text


def test_identity_shapes_dob_and_ids(scrubber, vault):
    text = ("DOB: 03/14/1988; born on 14 March 1988; passport no. X1234567; NHS number: 4857773456; "
            "account number: 00012345678; SSN 123 45 6789; driver's license: D1234567")
    r = scrubber.scrub(text, vault)
    for v in ("03/14/1988", "14 March 1988", "X1234567", "4857773456", "00012345678", "123 45 6789", "D1234567"):
        assert v not in r.text, v
    assert r.kinds == {"DOB": 2, "ID": 3, "ACCOUNT": 1, "SSN": 1}
    assert "passport no. [ID-1]" in r.text and "DOB: [DOB-1]" in r.text


def test_identity_shapes_address_beats_honorific(scrubber, vault):
    r = scrubber.scrub("sent to 12 Sample Dr Springfield IL 62704 yesterday", vault)
    assert r.kinds == {"ADDRESS": 1}
    assert r.text == "sent to [ADDRESS-1] yesterday"


def test_identity_shapes_leave_technical_text_alone(scrubber, vault):
    text = ("PR 12345 merged; graphics card: RTX 5090; license: GPL-3.0; Hi there, hello world\n"
            "hostname: Ms-Alpha; name: local-llm-mcp; version 3 of the way forward; Mr-Beta is a host\n"
            "swift: 5.9; policy: ALLOW; Best\npractices apply; Dear Sir, Hello World!")
    r = scrubber.scrub(text, vault)
    assert r.replaced == 0, r


def test_identity_shapes_pii_mode_only_and_switchable(terms, vault):
    text = "Dr Ada Lovelace lives at 12 Sample Drive, Springfield, IL 62704"
    on = Scrubber(None, terms)
    assert on.scrub(text, vault, secrets_only=True).text == text        # ASSIST mode: untouched
    assert on.scrub(text, vault).kinds == {"PERSON": 1, "ADDRESS": 1}   # PII mode
    off = Scrubber(None, terms, shapes=False)
    assert off.scrub(text, Vault(vault.path.parent / "v2.json")).replaced == 0


def test_nested_placeholder_from_a_worker_collapses(scrubber, vault):
    r = scrubber.scrub("card: [CARD-4111 1111 1111 1111] and again [CARD-4111 1111 1111 1111]", vault)
    assert r.text == "card: [CARD-1] and again [CARD-1]" and r.kinds == {"CARD": 2}
    assert scrubber.scrub("[PERSON-[PERSON-3]] said hi", vault).text == "[PERSON-3] said hi"
