"""JDK downloads come from My Oracle Support like every other patch: search for the patch, remember it, take the
tarball out of the zip, and refuse anything that isn't a JDK."""
import io
import json
import re
import tarfile
import zipfile
from pathlib import Path

import pytest

from pegasus_connector import oracle

ROW = ('<tr class="OraBGAccentVeryDark"><td><a href="x?aru=999">{patch}</a></td><td>{desc}</td><td>Oracle JDK</td>'
       '<td>{date}</td><td>180 MB</td></tr>')


# how Oracle's search form lists releases (an excerpt of the real page's script)
RELEASES = ('<script>orig_product_17776="Java SE JDK and JRE (java2SE)";\norig_product_12443="Java SE (jdk)";\n'
            'orig_product_856="Something Else (xyz)";\n'
            'orig_release_600000000247513="Oracle Retail Order Management System Cloud Service 21.14.0.0.0";\n'
            'orig_release_600000000259014="Oracle JDK 21.0.13.0.3";\norig_release_600000000259013="Oracle JDK 21.0.13";\n'
            'orig_release_600000000250001="Oracle JDK 21.0.12";</script>')


class Resp:
    def __init__(self, text):
        self.text, self.status_code = text, 200


class FakeMOS:
    BASE = "https://updates.example"

    def __init__(self, rows):
        self.rows, self.urls = rows, []

    def get(self, url, timeout=60, stream=False):
        self.urls.append(url)
        return Resp(RELEASES + "".join(ROW.format(**r) for r in self.rows))


def jdk_zip(path, version, with_java=True):
    tar = io.BytesIO()
    with tarfile.open(fileobj=tar, mode="w:gz") as tf:
        data = b"#!/bin/sh\n"
        ti = tarfile.TarInfo(f"jdk-{version}/bin/java" if with_java else f"jdk-{version}/README")
        ti.size = len(data)
        tf.addfile(ti, io.BytesIO(data))
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("README.txt", "readme")
        z.writestr(f"jdk-{version}_linux-x64_bin.tar.gz", tar.getvalue())


def test_matching_rows():
    assert oracle.jdk_row_matches("Oracle JDK Update 21.0.13", "21.0.13")
    assert oracle.jdk_row_matches("Java SE Development Kit 21.0.13.0.2 (BPR)", "21.0.13.0.2")
    assert not oracle.jdk_row_matches("Oracle JDK Update 21.0.13.0.2", "21.0.13")
    assert not oracle.jdk_row_matches("Oracle JDK Update 21.0.13", "21.0.13.0.2")
    assert not oracle.jdk_row_matches("Oracle JDK Update 21.0.131", "21.0.13")
    assert not oracle.jdk_row_matches("WebLogic patch for 21.0.13", "21.0.13")


@pytest.fixture()
def cfg(tmp_path):
    p = tmp_path / "config.json"
    p.write_text("{}")
    return p


def test_downloads_from_oracle_support_and_remembers_the_patch(cfg, tmp_path, monkeypatch):
    mos = FakeMOS([{"patch": "38100001", "desc": "Oracle JDK Update 21.0.13.0.2", "date": "21-OCT-2026"},
                   {"patch": "38100002", "desc": "Oracle JDK Update 21.0.13", "date": "21-OCT-2026"}])
    calls = []

    def download_patch(config_path, cache_dir, patch, platform, filt, log, m=None):
        calls.append((patch, platform))
        d = Path(cache_dir) / patch
        d.mkdir(parents=True, exist_ok=True)
        jdk_zip(d / f"p{patch}_210_Linux-x86-64.zip", "21.0.13.0.2")
        return sorted(d.iterdir()), m
    monkeypatch.setattr(oracle, "download_patch", download_patch)
    cache, log = tmp_path / "cache", []
    got = oracle.download_jdk(cfg, cache, "21.0.13.0.2", log.append, mos=mos)
    assert calls == [("38100001", "226P")]
    assert [p.name for p in got] == ["jdk-21.0.13.0.2_linux-x64_bin.tar.gz"]
    assert got[0].parent == cache / "jdk-21.0.13.0.2"
    assert json.loads(oracle.jdk_patches_path(cfg).read_text()) == {"21.0.13.0.2": "38100001"}
    # cached: no search, no download
    mos.urls.clear()
    assert oracle.download_jdk(cfg, cache, "21.0.13.0.2", log.append, mos=mos) == got and not mos.urls


def test_a_patch_given_by_hand_and_a_failed_search(cfg, tmp_path, monkeypatch):
    mos = FakeMOS([])
    with pytest.raises(oracle.MOSError, match="jdk-patch 21.0.13 <patch number>"):
        oracle.download_jdk(cfg, tmp_path / "c", "21.0.13", print, mos=mos)
    oracle.save_jdk_patch(cfg, "21.0.13", "38100002")

    def download_patch(config_path, cache_dir, patch, platform, filt, log, m=None):
        d = Path(cache_dir) / patch
        d.mkdir(parents=True, exist_ok=True)
        jdk_zip(d / "p.zip", "21.0.13", with_java=False)               # not a JDK: refused
        return sorted(d.iterdir()), m
    monkeypatch.setattr(oracle, "download_patch", download_patch)
    mos.urls.clear()
    with pytest.raises(RuntimeError, match="no bin/java"):
        oracle.download_jdk(cfg, tmp_path / "c", "21.0.13", print, mos=mos)
    assert not mos.urls                                                   # the saved patch number was used
    assert not list((tmp_path / "c" / "jdk-21.0.13").iterdir())


class SearchMOS(FakeMOS):
    """Oracle Support as it behaves now: the search form lists product and release ids in its script, and a
    product + release search lists that release's patches. JDK update patches are under "Java SE (jdk)"."""

    def __init__(self):
        super().__init__([])
        self.by_release = {
            "600000000259013": [{"patch": "40186074", "desc": "Oracle JDK Update 21.0.13.0.2 (Patch)", "date": "21-OCT-2026"},
                                {"patch": "40132109", "desc": "Oracle JDK Update 21.0.13.0.1 (Patch)", "date": "14-OCT-2026"}],
            "600000000259014": [{"patch": "40211111", "desc": "Oracle JDK Update 21.0.13.0.3 (Patch)", "date": "26-OCT-2026"}]}

    def get(self, url, timeout=60, stream=False):
        self.urls.append(url)
        if "AdvancedSearch" in url:
            return Resp(RELEASES)
        rel = re.search(r"release=(\d+)", url)
        if "search_type=prod" in url and "product=12443" in url and rel:
            return Resp("".join(ROW.format(**r) for r in self.by_release.get(rel.group(1), [])))
        return Resp("<html>Error Your browser does not have Javascript enabled.</html>")


def test_finds_jdk_patches_by_product_and_release_ids(cfg):
    assert oracle.jdk_search_ids(SearchMOS(), "21.0.13.0.3") == (["12443", "17776"],
                                                                 ["600000000259014", "600000000259013"], 4)
    patch, tried = oracle.find_jdk_patch(SearchMOS(), "21.0.13.0.2", cfg)
    assert patch == "40186074"                       # under release "Oracle JDK 21.0.13", and not .0.1
    assert oracle.find_jdk_patch(SearchMOS(), "21.0.13.0.3", cfg)[0] == "40211111"   # its own release id
    assert oracle.jdk_release_ids(SearchMOS(), "", "21.0.12")[0] == ["600000000250001"]


def test_nothing_found_says_what_was_tried(cfg):
    patch, tried = oracle.find_jdk_patch(SearchMOS(), "21.0.14", cfg)
    assert patch is None and "release ids for 21.0.14: none" in tried[0] and "12443" in tried[0]
