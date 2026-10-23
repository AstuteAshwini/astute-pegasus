"""JDK downloads come from My Oracle Support like every other patch: search for the patch, remember it, take the
tarball out of the zip, and refuse anything that isn't a JDK."""
import io
import json
import tarfile
import zipfile
from pathlib import Path

import pytest

from pegasus_connector import oracle

ROW = ('<tr class="OraBGAccentVeryDark"><td><a href="x?aru=999">{patch}</a></td><td>{desc}</td><td>Oracle JDK</td>'
       '<td>{date}</td><td>180 MB</td></tr>')


class Resp:
    def __init__(self, text):
        self.text, self.status_code = text, 200


class FakeMOS:
    BASE = "https://updates.example"

    def __init__(self, rows):
        self.rows, self.urls = rows, []

    def get(self, url, timeout=60, stream=False):
        self.urls.append(url)
        return Resp("".join(ROW.format(**r) for r in self.rows))


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
    """Oracle Support that only finds JDK patches when the search names the Java SE product."""

    def __init__(self, form="", patch_page=""):
        super().__init__([{"patch": "40186074", "desc": "Oracle JDK Update 21.0.13.0.2 (Patch)", "date": "21-OCT-2026"}])
        self.form, self.patch_page = form, patch_page

    def get(self, url, timeout=60, stream=False):
        self.urls.append(url)
        if "metadata" in url:
            return Resp("")
        if "search_type=patch" in url:
            return Resp(self.patch_page)
        if "AdvancedSearch" in url and "description" not in url:
            return Resp(self.form)
        if "product=10120" in url:
            return Resp("".join(ROW.format(**r) for r in self.rows))
        return Resp("")


def test_learns_the_java_product_from_the_search_form(cfg):
    mos = SearchMOS(form='<select name="product"><option value="9480">Oracle Database</option>'
                         '<option value="10120">Java SE JDK and JRE</option></select>')
    patch, tried = oracle.find_jdk_patch(mos, "21.0.13.0.2", cfg)
    assert patch == "40186074"
    assert oracle.load_jdk_patches(cfg)["_java_product"] == "10120"
    mos.urls.clear()                                                     # remembered: no second discovery
    assert oracle.find_jdk_patch(mos, "21.0.13.0.2", cfg)[0] == "40186074"
    assert not any("metadata" in u or "description" not in u for u in mos.urls)


def test_learns_the_java_product_from_a_known_jdk_patch(cfg):
    oracle.save_jdk_patch(cfg, "21.0.13.0.2", "40186074")
    mos = SearchMOS(patch_page='<a href="/Orion/PatchDetails/process_form?patch_num=40186074&product=10120&release=1">x</a>')
    assert oracle.find_jdk_patch(mos, "21.0.13.0.2", cfg)[0] == "40186074"
    assert oracle.load_jdk_patches(cfg)["_java_product"] == "10120"


def test_nothing_found_says_what_was_tried(cfg):
    patch, tried = oracle.find_jdk_patch(SearchMOS(), "21.0.14", cfg)
    assert patch is None and any("product list: nothing" in t for t in tried)
