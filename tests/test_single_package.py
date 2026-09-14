"""One RPM, with the guided interface in it.

The interface used to be an ``alma-certify-tui`` subpackage. The reason was that Textual is not
in EPEL on every release this targets - but vendoring already answered that, so the split was not
avoiding the bundle, only putting a second install step in front of it. The moment somebody wants
the guided interface is often the moment they are at a lab machine with no easy network, being
told to go and fetch another package.

So it is one package now, and these hold the parts of that which are easy to get wrong and
invisible when they are: an upgrade that leaves the old subpackage installed, an install command
in somebody's runbook that stops resolving, or a License tag that no longer covers what is in the
payload.
"""
from __future__ import annotations

import pathlib
import re

import pytest

SPEC = pathlib.Path(__file__).resolve().parent.parent / "packaging" / "alma-certify.spec"


def spec() -> str:
    if not SPEC.is_file():
        pytest.skip("no spec here; this runs from a tarball that omits packaging/")
    return SPEC.read_text(encoding="utf-8")


def test_the_spec_builds_one_package():
    """``%package`` is how a second one comes back, and it would come back empty-handed: the
    files it used to own are in the main ``%files`` now."""
    assert not re.search(r"^%package\b", spec(), re.M)
    # On the same line: ``\s`` would match the newline before the first file and read every
    # %files section as named.
    assert not re.search(r"^%files[ \t]+\S", spec(), re.M), "a %files with a subpackage name"


def test_the_old_names_still_resolve():
    """Somebody's runbook, kickstart, or Ansible play says ``dnf install alma-certify-tui``. It
    has to keep working, and the alias spelling has to as well."""
    text = spec()

    for name in ("%{name}-tui", "almalinux-certify-tui"):
        assert "Provides:       %s = %%{version}-%%{release}" % name in text, name


def test_an_installed_subpackage_is_replaced_rather_than_left_behind():
    """Without Obsoletes the old subpackage stays installed on upgrade, and every file it owns is
    now owned by this package too - a straight file conflict, found by the first person to try
    it rather than by us."""
    text = spec()

    for name in ("%{name}-tui", "almalinux-certify-tui"):
        assert "Obsoletes:      %s < %%{version}-%%{release}" % name in text, name


def test_the_interface_and_its_licenses_are_in_the_files_list():
    """The subpackage's three ``%files`` lines had to land somewhere. A package that Obsoletes
    the old one and then ships none of its files is worse than the split was."""
    text = spec()
    files = text[text.index("\n%files"):]

    assert "%{alma_certify_home}/alma_certify_tui/" in files
    assert "%license bundled/" in files, "the bundled license texts stop being marked %license"


def test_the_license_tag_covers_what_is_bundled():
    """It was MIT when the vendored stack lived elsewhere. typing-extensions is PSF-2.0 and is in
    this payload now, so a tag that still said plain MIT would be wrong about the package."""
    text = spec()
    tag = re.search(r"^License:\s+(.+)$", text, re.M)

    assert tag is not None
    assert tag.group(1).strip() == "MIT AND PSF-2.0"
    assert re.search(r"^Provides:\s+bundled\(python3dist\(textual\)\)", text, re.M), (
        "the bundled list did not come across with the files"
    )


def test_nothing_tells_the_reader_to_install_a_package_that_is_gone():
    """The CLI said "Install it with: dnf install alma-certify-tui" when the import failed. That
    command now resolves to the package they already have, so following it teaches them nothing
    and hides whatever actually broke."""
    from alma_certify import cli

    source = pathlib.Path(cli.__file__).read_text(encoding="utf-8")

    assert "dnf install alma-certify-tui" not in source


def test_the_import_failure_still_says_something_useful():
    """It can still fail - a checkout without the vendored tree, a broken install - and the
    reader needs the reason rather than a traceback or a bare "unavailable"."""
    from alma_certify import cli

    frontend, reason = cli._select_tui()

    if frontend is None:
        assert reason and "could not be loaded" in reason or "TERM" in reason, reason
