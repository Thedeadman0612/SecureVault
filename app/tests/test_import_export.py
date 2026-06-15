"""
app/tests/test_import_export.py

Unit tests for app/services/import_export.py.

All functions in this module are pure (no DB, no session) so tests are fast
and self-contained. Covers:

  parse_keepass_xml  — valid XML with groups, invalid XML, missing Root/Group,
                       entries without titles (should be skipped), nested groups
  parse_lastpass_csv — valid CSV with all columns, rows missing title (skipped),
                       UTF-8-BOM encoded file
  build_keepass_xml  — round-trip structure check, grouping by category, empty list
  build_lastpass_csv — header row present, data rows correct, empty list
"""

from datetime import datetime, timezone

import pytest

from app.schemas.vault import VaultEntryResponse
from app.services.import_export import (
    ImportError,
    build_keepass_xml,
    build_lastpass_csv,
    parse_keepass_xml,
    parse_lastpass_csv,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_response(**kwargs) -> VaultEntryResponse:
    """Build a minimal VaultEntryResponse for export tests."""
    now = datetime.now(timezone.utc)
    defaults = {
        "id": 1,
        "title": "Example",
        "website": None,
        "category": None,
        "username": "user",
        "password": "pass",  # NOSONAR — test fixture value, not a real credential
        "notes": None,
        "created_at": now,
        "updated_at": now,
    }
    defaults.update(kwargs)
    return VaultEntryResponse(**defaults)


def _keepass_xml(groups: str) -> bytes:
    """Wrap group XML in a minimal KeePass file envelope."""
    return f"""<?xml version="1.0" encoding="utf-8"?>
<KeePassFile>
  <Root>
    <Group>
      <Name>NewDatabase</Name>
      {groups}
    </Group>
  </Root>
</KeePassFile>""".encode()


def _entry_xml(title="Gmail", username="user@gmail.com", password="s3cr3t",  # NOSONAR — test fixture
               url="https://gmail.com", notes="my notes") -> str:
    return f"""<Entry>
      <String><Key>Title</Key><Value>{title}</Value></String>
      <String><Key>UserName</Key><Value>{username}</Value></String>
      <String><Key>Password</Key><Value>{password}</Value></String>
      <String><Key>URL</Key><Value>{url}</Value></String>
      <String><Key>Notes</Key><Value>{notes}</Value></String>
    </Entry>"""


# ---------------------------------------------------------------------------
# parse_keepass_xml
# ---------------------------------------------------------------------------

class TestParseKeepassXml:
    def test_valid_entry_parsed(self):
        xml = _keepass_xml(_entry_xml())
        entries = parse_keepass_xml(xml)
        assert len(entries) == 1
        e = entries[0]
        assert e.title == "Gmail"
        assert e.username == "user@gmail.com"
        assert e.password == "s3cr3t"
        assert e.website == "https://gmail.com"
        assert e.notes == "my notes"

    def test_group_name_becomes_category(self):
        inner = f"""<Group>
          <Name>Email</Name>
          {_entry_xml("Inbox")}
        </Group>"""
        xml = _keepass_xml(inner)
        entries = parse_keepass_xml(xml)
        assert len(entries) == 1
        assert entries[0].category == "Email"

    def test_nested_groups_inherit_parent_category(self):
        inner = """<Group>
          <Name>Work</Name>
          <Group>
            <Name>Sub</Name>
            <Entry>
              <String><Key>Title</Key><Value>Tool</Value></String>
              <String><Key>UserName</Key><Value>u</Value></String>
              <String><Key>Password</Key><Value>p</Value></String>
            </Entry>
          </Group>
        </Group>"""
        xml = _keepass_xml(inner)
        entries = parse_keepass_xml(xml)
        assert len(entries) == 1
        assert entries[0].category == "Sub"

    def test_entry_without_title_skipped(self):
        xml = _keepass_xml("""<Entry>
          <String><Key>Title</Key><Value></Value></String>
          <String><Key>Password</Key><Value>x</Value></String>
        </Entry>""")
        entries = parse_keepass_xml(xml)
        assert entries == []

    def test_empty_url_stored_as_none(self):
        xml = _keepass_xml(_entry_xml(url=""))
        entries = parse_keepass_xml(xml)
        assert entries[0].website is None

    def test_empty_notes_stored_as_none(self):
        xml = _keepass_xml(_entry_xml(notes=""))
        entries = parse_keepass_xml(xml)
        assert entries[0].notes is None

    def test_invalid_xml_raises_import_error(self):
        with pytest.raises(ImportError, match="KeePass XML"):
            parse_keepass_xml(b"not xml at all <<>>")

    def test_missing_root_group_raises_import_error(self):
        bad_xml = b"<?xml version='1.0'?><KeePassFile><SomeOtherTag/></KeePassFile>"
        with pytest.raises(ImportError, match="Root/Group"):
            parse_keepass_xml(bad_xml)

    def test_multiple_entries_all_parsed(self):
        inner = f"""<Group>
          <Name>Social</Name>
          {_entry_xml("Twitter")}
          {_entry_xml("Facebook")}
        </Group>"""
        xml = _keepass_xml(inner)
        entries = parse_keepass_xml(xml)
        assert len(entries) == 2
        titles = {e.title for e in entries}
        assert titles == {"Twitter", "Facebook"}


# ---------------------------------------------------------------------------
# parse_lastpass_csv
# ---------------------------------------------------------------------------

def _csv(*rows: str) -> bytes:
    header = "url,username,password,extra,name,grouping,fav"
    body = "\n".join([header, *rows])
    return body.encode("utf-8")


class TestParseLastpassCsv:
    def test_single_valid_row(self):
        csv_bytes = _csv("https://github.com,alice,pass123,some note,GitHub,Dev,0")
        entries = parse_lastpass_csv(csv_bytes)
        assert len(entries) == 1
        e = entries[0]
        assert e.title == "GitHub"
        assert e.username == "alice"
        assert e.password == "pass123"
        assert e.website == "https://github.com"
        assert e.notes == "some note"
        assert e.category == "Dev"

    def test_row_with_empty_title_is_skipped(self):
        csv_bytes = _csv("https://x.com,user,pass,,  ,Group,0")
        entries = parse_lastpass_csv(csv_bytes)
        assert entries == []

    def test_empty_url_stored_as_none(self):
        csv_bytes = _csv(",user,pass,,GitHub,,0")
        entries = parse_lastpass_csv(csv_bytes)
        assert entries[0].website is None

    def test_empty_grouping_stored_as_none(self):
        csv_bytes = _csv("https://x.com,user,pass,,SiteX,,0")
        entries = parse_lastpass_csv(csv_bytes)
        assert entries[0].category is None

    def test_utf8_bom_handled(self):
        bom = b"\xef\xbb\xbf"
        body = b"url,username,password,extra,name,grouping,fav\nhttps://x.com,u,p,,Title,,0"
        entries = parse_lastpass_csv(bom + body)
        assert len(entries) == 1
        assert entries[0].title == "Title"

    def test_multiple_rows_all_parsed(self):
        csv_bytes = _csv(
            "https://a.com,u1,p1,,Site A,Group1,0",
            "https://b.com,u2,p2,,Site B,Group2,0",
        )
        entries = parse_lastpass_csv(csv_bytes)
        assert len(entries) == 2

    def test_empty_extra_notes_stored_as_none(self):
        csv_bytes = _csv("https://x.com,user,pass,,GitHub,,0")
        entries = parse_lastpass_csv(csv_bytes)
        assert entries[0].notes is None


# ---------------------------------------------------------------------------
# build_keepass_xml
# ---------------------------------------------------------------------------

class TestBuildKeepassXml:
    def test_output_is_bytes(self):
        result = build_keepass_xml([])
        assert isinstance(result, bytes)

    def test_xml_declaration_present(self):
        result = build_keepass_xml([])
        assert result.startswith(b"<?xml")

    def test_entry_appears_in_output(self):
        entry = _make_response(title="GitHub", username="alice", password="s3cr3t")  # NOSONAR
        result = build_keepass_xml([entry])
        xml_text = result.decode("utf-8")
        assert "GitHub" in xml_text
        assert "alice" in xml_text
        assert "s3cr3t" in xml_text

    def test_category_becomes_group_name(self):
        entry = _make_response(title="Gmail", category="Email")
        result = build_keepass_xml([entry])
        assert b"Email" in result

    def test_no_category_uses_uncategorized_group(self):
        entry = _make_response(title="NoGroup", category=None)
        result = build_keepass_xml([entry])
        assert b"Uncategorized" in result

    def test_entries_grouped_by_category(self):
        entries = [
            _make_response(id=1, title="A", category="Work"),
            _make_response(id=2, title="B", category="Personal"),
        ]
        result = build_keepass_xml(entries)
        xml_text = result.decode("utf-8")
        assert "Work" in xml_text
        assert "Personal" in xml_text

    def test_website_and_notes_included(self):
        entry = _make_response(
            title="Site",
            website="https://site.com",
            notes="a note",
        )
        result = build_keepass_xml([entry])
        assert b"https://site.com" in result
        assert b"a note" in result


# ---------------------------------------------------------------------------
# build_lastpass_csv
# ---------------------------------------------------------------------------

class TestBuildLastpassCsv:
    def test_output_is_bytes(self):
        result = build_lastpass_csv([])
        assert isinstance(result, bytes)

    def test_header_row_present(self):
        result = build_lastpass_csv([])
        first_line = result.decode("utf-8").splitlines()[0]
        assert "url" in first_line
        assert "username" in first_line
        assert "password" in first_line
        assert "name" in first_line

    def test_entry_data_in_output(self):
        entry = _make_response(
            title="GitHub",
            website="https://github.com",
            username="alice",
            password="s3cr3t",  # NOSONAR — test fixture value, not a real credential
            notes="dev account",
            category="Dev",
        )
        result = build_lastpass_csv([entry])
        text = result.decode("utf-8")
        assert "GitHub" in text
        assert "alice" in text
        assert "s3cr3t" in text
        assert "dev account" in text
        assert "https://github.com" in text
        assert "Dev" in text

    def test_none_fields_become_empty_string(self):
        entry = _make_response(title="NoSite", website=None, notes=None, category=None)
        result = build_lastpass_csv([entry])
        lines = result.decode("utf-8").splitlines()
        assert len(lines) == 2   # header + one data row

    def test_multiple_entries_produce_multiple_rows(self):
        entries = [
            _make_response(id=1, title="A"),
            _make_response(id=2, title="B"),
        ]
        result = build_lastpass_csv(entries)
        lines = result.decode("utf-8").splitlines()
        assert len(lines) == 3   # header + 2 data rows
