"""
app/services/import_export.py

Parsing and serialisation helpers for KeePass XML and LastPass CSV formats.

These functions receive and return PLAINTEXT credential data. They are only
called from authenticated route handlers. The parsed data is immediately
passed to vault_service.create_entry() which encrypts it before writing.

SECURITY: No sensitive data (passwords, usernames, notes) is logged anywhere
in this module. Log lines include only counts and format names.
"""

import csv
import io
import logging
import xml.etree.ElementTree as ET
from collections import defaultdict
from dataclasses import dataclass

logger = logging.getLogger(__name__)

MAX_IMPORT_BYTES = 5 * 1024 * 1024  # 5 MB — limits "billion laughs" surface area


class ImportError(Exception):
    """Raised when a file cannot be parsed as the expected format."""


@dataclass
class ImportedEntry:
    """Intermediate representation of one credential parsed from an import file."""
    title: str
    website: str | None
    username: str
    password: str
    notes: str | None
    category: str | None


# ---------------------------------------------------------------------------
# KeePass XML — import
# ---------------------------------------------------------------------------

def parse_keepass_xml(content: bytes) -> list[ImportedEntry]:
    """Parse a KeePass 2.x XML export and return a list of ImportedEntry objects.

    KeePass XML structure:
        <KeePassFile>
          <Root>
            <Group>                         ← root database group
              <Name>NewDatabase</Name>
              <Group>                       ← category group
                <Name>Email</Name>
                <Entry>
                  <String><Key>Title</Key><Value>Gmail</Value></String>
                  <String><Key>UserName</Key><Value>user@gmail.com</Value></String>
                  <String><Key>Password</Key><Value>…</Value></String>
                  <String><Key>URL</Key><Value>https://gmail.com</Value></String>
                  <String><Key>Notes</Key><Value>…</Value></String>
                </Entry>
              </Group>
            </Group>
          </Root>
        </KeePassFile>

    Group names at depth ≥ 1 are used as the category. Nested sub-groups use
    the name of their immediate parent group as the category.
    """
    try:
        root = ET.fromstring(content)
    except ET.ParseError as exc:
        raise ImportError(f"Invalid XML: {exc}") from exc

    root_group = root.find("Root/Group")
    if root_group is None:
        raise ImportError("Not a valid KeePass XML file (Root/Group element not found).")

    entries: list[ImportedEntry] = []
    _walk_keepass_group(root_group, category=None, entries=entries, depth=0)
    logger.info("KeePass XML parse: found %d entries.", len(entries))
    return entries


def _walk_keepass_group(
    group: ET.Element,
    category: str | None,
    entries: list[ImportedEntry],
    depth: int,
) -> None:
    """Recursively collect entries from a KeePass group element."""
    # Depth 0 is the root database group — its Name is the DB label, not a category.
    # Depth 1+ group names become the category for entries within them.
    if depth > 0:
        name_text = (group.findtext("Name") or "").strip()
        if name_text:
            category = name_text

    for entry_el in group.findall("Entry"):
        strings: dict[str, str] = {
            (s.findtext("Key") or ""): (s.findtext("Value") or "")
            for s in entry_el.findall("String")
        }
        title = strings.get("Title", "").strip()
        if not title:
            continue

        entries.append(ImportedEntry(
            title=title,
            website=strings.get("URL", "").strip() or None,
            username=strings.get("UserName", ""),
            password=strings.get("Password", ""),
            notes=strings.get("Notes", "").strip() or None,
            category=category,
        ))

    for sub_group in group.findall("Group"):
        _walk_keepass_group(sub_group, category, entries, depth + 1)


# ---------------------------------------------------------------------------
# LastPass CSV — import
# ---------------------------------------------------------------------------

def parse_lastpass_csv(content: bytes) -> list[ImportedEntry]:
    """Parse a LastPass CSV export and return a list of ImportedEntry objects.

    Standard LastPass export columns:
        url, username, password, extra, name, grouping, fav

    where  extra = notes,  name = title,  grouping = category.
    Column names are normalised to lowercase before matching.
    """
    try:
        # utf-8-sig strips a UTF-8 BOM if present (Excel-exported CSVs often have one).
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = content.decode("latin-1")

    reader = csv.DictReader(io.StringIO(text))
    entries: list[ImportedEntry] = []

    for row in reader:
        # Normalise all column names: lowercase + strip whitespace.
        row = {(k or "").strip().lower(): (v or "").strip() for k, v in row.items()}

        # LastPass uses "name" for the entry title; some variants use "hostname".
        title = row.get("name") or row.get("title") or row.get("hostname") or ""
        title = title.strip()
        if not title:
            continue

        entries.append(ImportedEntry(
            title=title,
            website=row.get("url", "").strip() or None,
            username=row.get("username", ""),
            password=row.get("password", ""),
            notes=row.get("extra", "").strip() or None,
            category=(row.get("grouping") or row.get("group") or "").strip() or None,
        ))

    logger.info("LastPass CSV parse: found %d entries.", len(entries))
    return entries


# ---------------------------------------------------------------------------
# KeePass XML — export
# ---------------------------------------------------------------------------

def build_keepass_xml(entries: list) -> bytes:
    """Serialise a list of VaultEntryResponse objects as KeePass 2.x XML.

    Entries are grouped by category. Entries without a category go into an
    "Uncategorized" sub-group.

    Returns UTF-8 encoded bytes with an XML declaration.
    """
    keepass_file = ET.Element("KeePassFile")
    meta = ET.SubElement(keepass_file, "Meta")
    ET.SubElement(meta, "Generator").text = "SecureVault"

    root_el = ET.SubElement(keepass_file, "Root")
    root_group = ET.SubElement(root_el, "Group")
    ET.SubElement(root_group, "Name").text = "SecureVault Export"

    # Group entries by category for a tidy category → group structure.
    groups: dict[str, list] = defaultdict(list)
    for entry in entries:
        groups[entry.category or "Uncategorized"].append(entry)

    for cat_name, cat_entries in sorted(groups.items()):
        group_el = ET.SubElement(root_group, "Group")
        ET.SubElement(group_el, "Name").text = cat_name

        for entry in cat_entries:
            entry_el = ET.SubElement(group_el, "Entry")
            for key, val in [
                ("Title",    entry.title),
                ("UserName", entry.username or ""),
                ("Password", entry.password or ""),
                ("URL",      entry.website or ""),
                ("Notes",    entry.notes or ""),
            ]:
                s = ET.SubElement(entry_el, "String")
                ET.SubElement(s, "Key").text = key
                ET.SubElement(s, "Value").text = val

    # ET.indent (Python 3.9+) produces human-readable output.
    try:
        ET.indent(keepass_file, space="  ")
    except AttributeError:
        pass  # Python < 3.9: output is valid but unindented

    return ET.tostring(keepass_file, encoding="utf-8", xml_declaration=True)


# ---------------------------------------------------------------------------
# LastPass CSV — export
# ---------------------------------------------------------------------------

def build_lastpass_csv(entries: list) -> bytes:
    """Serialise a list of VaultEntryResponse objects as LastPass-compatible CSV.

    Column order matches the standard LastPass export format so the file can be
    imported back into LastPass or other managers that accept the same format.

    Returns UTF-8 encoded bytes (no BOM — standard CSV).
    """
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["url", "username", "password", "extra", "name", "grouping", "fav"])
    for entry in entries:
        writer.writerow([
            entry.website or "",
            entry.username or "",
            entry.password or "",
            entry.notes or "",
            entry.title,
            entry.category or "",
            "0",
        ])
    return buf.getvalue().encode("utf-8")
