"""The GUI's only decision -- what a drop/import adds to the queue -- pulled
out into new_files() so it is testable without a display. The Tk widget tree
itself is not exercised here; it needs a real display and has no logic of its
own beyond wiring these calls to two buttons.
"""

from cleaner.gui import new_files


def test_new_files_filters_to_existing_files(tmp_path):
    real = tmp_path / "a.jpg"
    real.write_bytes(b"x")
    missing = tmp_path / "missing.jpg"
    directory = tmp_path / "subdir"
    directory.mkdir()

    result = new_files([], [real, missing, directory])

    assert result == [real]


def test_new_files_dedupes_against_existing_queue(tmp_path):
    a = tmp_path / "a.jpg"
    b = tmp_path / "b.jpg"
    a.write_bytes(b"x")
    b.write_bytes(b"y")

    result = new_files([a], [a, b])

    assert result == [b]


def test_new_files_dedupes_within_one_call(tmp_path):
    a = tmp_path / "a.jpg"
    a.write_bytes(b"x")

    result = new_files([], [a, a])

    assert result == [a]
