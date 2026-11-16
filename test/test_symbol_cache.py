# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""Tests for deterministic symbol table selection and ISF discoverability.

These tests use constructed ISF files only; no real memory images are
required.  They verify that:

* when several ISF files share an identifier (e.g. the same kernel banner),
  the chosen symbol table is deterministic and follows the symbol directory
  order (user specified directories first),
* all candidates for an identifier (chosen and shadowed) are visible,
* ISF files without an identifier are still reported,
* caches written by older versions remain readable,
* a unique identifier resolves exactly as before.
"""

import base64
import json
import os
import sqlite3
import subprocess
import sys

import pytest

import volatility3.symbols
from volatility3.framework import constants
from volatility3.framework.automagic import symbol_cache

BANNER_A = b"Linux version 5.10.0-test (builder@host) #1 SMP PREEMPT\x00"
BANNER_B = b"Linux version 6.1.0-other (builder@host) #2 SMP\x00"


def _make_isf(path, banner=None, marker_size=8):
    """Writes a minimal constructed ISF file to path"""
    data = {
        "metadata": {"producer": {"name": "pytest", "version": "1.0.0"}},
        "base_types": {},
        "user_types": {
            "marker": {"kind": "struct", "size": marker_size, "fields": {}}
        },
        "enums": {},
        "symbols": {},
    }
    if banner is not None:
        data["symbols"]["linux_banner"] = {
            "type": {"kind": "base", "name": "char"},
            "address": 0,
            "constant_data": base64.b64encode(banner).decode("ascii"),
        }
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fp:
        json.dump(data, fp)
    return "file://" + os.path.realpath(path)


@pytest.fixture
def symbol_dirs(tmp_path, monkeypatch):
    """Builds two symbol directories containing constructed ISF files:

    * both hold an ISF for BANNER_A (duplicated identifier, differing
      marker sizes so the chosen file is observable through its stats)
    * the "stock" directory additionally holds a unique BANNER_B ISF
    * the "user" directory additionally holds an ISF with no banner
    """
    user_dir = tmp_path / "user_symbols"
    stock_dir = tmp_path / "stock_symbols"

    urls = {
        "user_dup": _make_isf(
            str(user_dir / "linux" / "dup.json"), BANNER_A, marker_size=8
        ),
        "stock_dup": _make_isf(
            str(stock_dir / "linux" / "dup.json"), BANNER_A, marker_size=16
        ),
        "stock_unique": _make_isf(
            str(stock_dir / "linux" / "unique.json"), BANNER_B, marker_size=8
        ),
        "user_nobanner": _make_isf(str(user_dir / "linux" / "nobanner.json"), None),
    }
    monkeypatch.setattr(
        volatility3.symbols, "__path__", [str(user_dir), str(stock_dir)]
    )
    return urls


def _make_cache(tmp_path, name="identifier.cache"):
    cache = symbol_cache.SqliteCache(str(tmp_path / name))
    cache.update()
    return cache


def test_user_symbol_dir_wins(symbol_dirs, tmp_path):
    """The ISF under the first (user specified) symbol directory is chosen"""
    cache = _make_cache(tmp_path)
    dictionary = cache.get_identifier_dictionary(operating_system="linux")
    assert dictionary[BANNER_A] == symbol_dirs["user_dup"]
    assert (
        cache.find_location(BANNER_A, operating_system="linux")
        == symbol_dirs["user_dup"]
    )


def test_selection_is_deterministic_across_cache_rebuilds(symbol_dirs, tmp_path):
    """Clearing the cache and rebuilding it must not change the choice"""
    chosen = set()
    for counter in range(3):
        cache = _make_cache(tmp_path, name=f"identifier{counter}.cache")
        chosen.add(cache.get_identifier_dictionary(operating_system="linux")[BANNER_A])
    assert chosen == {symbol_dirs["user_dup"]}


def test_symbol_dir_order_controls_choice(symbol_dirs, tmp_path, monkeypatch):
    """Reordering the symbol directories flips the choice predictably"""
    monkeypatch.setattr(
        volatility3.symbols,
        "__path__",
        list(reversed(volatility3.symbols.__path__)),
    )
    cache = _make_cache(tmp_path)
    dictionary = cache.get_identifier_dictionary(operating_system="linux")
    assert dictionary[BANNER_A] == symbol_dirs["stock_dup"]


def test_insertion_order_does_not_affect_choice(symbol_dirs, tmp_path):
    """Whatever order rows were inserted in, resolution follows the rules"""
    locations = [symbol_dirs["user_dup"], symbol_dirs["stock_dup"]]
    chosen = set()
    for counter, ordering in enumerate([locations, list(reversed(locations))]):
        path = str(tmp_path / f"manual{counter}.cache")
        # Create an empty cache, then insert the duplicates by hand in a
        # specific order to simulate caches built by older versions
        symbol_cache.SqliteCache(path)
        database = sqlite3.connect(path)
        for location in ordering:
            database.execute(
                "INSERT INTO cache (location, identifier, operating_system, hash, local, cached)"
                " VALUES (?, ?, ?, ?, ?, datetime('now'))",
                (location, BANNER_A, "linux", "", True),
            )
        database.commit()
        database.close()
        cache = symbol_cache.load_cache_manager(path)
        chosen.add(cache.get_identifier_dictionary(operating_system="linux")[BANNER_A])
        assert (
            cache.find_location(BANNER_A, operating_system="linux")
            == symbol_dirs["user_dup"]
        )
    assert chosen == {symbol_dirs["user_dup"]}


def test_all_candidates_are_visible(symbol_dirs, tmp_path):
    """Every candidate (chosen and shadowed) is reported, preferred first"""
    cache = _make_cache(tmp_path)
    locations = cache.get_identifier_locations(operating_system="linux")
    assert locations[BANNER_A] == [symbol_dirs["user_dup"], symbol_dirs["stock_dup"]]
    # The dictionary choice is always the first candidate
    dictionary = cache.get_identifier_dictionary(operating_system="linux")
    for identifier, candidates in locations.items():
        if identifier is not None:
            assert dictionary[identifier] == candidates[0]


def test_unidentified_files_are_listed(symbol_dirs, tmp_path):
    """ISF files without a banner still show up, under the None identifier"""
    cache = _make_cache(tmp_path)
    # Unidentified files have no operating system, so query unfiltered
    locations = cache.get_identifier_locations()
    assert symbol_dirs["user_nobanner"] in locations[None]


def test_unique_banner_resolution_unchanged(symbol_dirs, tmp_path):
    """A unique banner resolves to its only location, as before"""
    cache = _make_cache(tmp_path)
    dictionary = cache.get_identifier_dictionary(operating_system="linux")
    assert dictionary[BANNER_B] == symbol_dirs["stock_unique"]
    assert (
        cache.find_location(BANNER_B, operating_system="linux")
        == symbol_dirs["stock_unique"]
    )
    assert cache.get_identifier_locations(operating_system="linux")[BANNER_B] == [
        symbol_dirs["stock_unique"]
    ]


def test_old_cache_schema_remains_readable(symbol_dirs, tmp_path):
    """A cache file written with the existing (old) schema must not error"""
    path = str(tmp_path / "old.cache")
    database = sqlite3.connect(path)
    database.execute(
        f"CREATE TABLE database_info (schema_version INT DEFAULT {constants.CACHE_SQLITE_SCHEMA_VERSION})"
    )
    database.execute(
        f"INSERT INTO database_info VALUES ({constants.CACHE_SQLITE_SCHEMA_VERSION})"
    )
    database.execute(
        "CREATE TABLE cache (location TEXT UNIQUE NOT NULL, identifier TEXT, operating_system TEXT, hash TEXT,"
        "stats_base_types INT DEFAULT 0, stats_types INT DEFAULT 0, stats_enums INT DEFAULT 0, stats_symbols INT DEFAULT 0, local BOOL, cached DATETIME)"
    )
    database.execute(
        "INSERT INTO cache (location, identifier, operating_system, hash,"
        "stats_base_types, stats_types, stats_enums, stats_symbols, local, cached)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))",
        (symbol_dirs["stock_unique"], BANNER_B, "linux", "", 0, 1, 0, 1, True),
    )
    database.commit()
    database.close()

    cache = symbol_cache.load_cache_manager(path)
    dictionary = cache.get_identifier_dictionary(operating_system="linux")
    assert dictionary[BANNER_B] == symbol_dirs["stock_unique"]
    assert cache.get_identifier_locations(operating_system="linux")[BANNER_B] == [
        symbol_dirs["stock_unique"]
    ]


def test_isfinfo_lists_every_discoverable_isf(
    symbol_dirs, tmp_path, volatility, python
):
    """The isfinfo plugin reports duplicates and banner-less ISF files"""
    cache_path = tmp_path / "cache"
    cache_path.mkdir()
    cmd = (
        python,
        volatility,
        "--cache-path",
        str(cache_path),
        "--symbol-dirs",
        ";".join(volatility3.symbols.__path__),
        "-q",
        "-r",
        "csv",
        "isfinfo.IsfInfo",
    )
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    assert proc.returncode == 0, proc.stderr
    output = proc.stdout
    # Both duplicates of the same banner must appear
    assert output.count("dup.json") == 2
    # The banner-less ISF must appear as well
    assert "nobanner.json" in output
    assert "unique.json" in output
