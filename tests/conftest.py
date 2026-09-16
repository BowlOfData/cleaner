import pathlib
import pytest

CORPUS = pathlib.Path(__file__).parent / "corpus"


@pytest.fixture(scope="session")
def corpus() -> pathlib.Path:
    return CORPUS


@pytest.fixture(scope="session")
def unsigned_jpg() -> pathlib.Path:
    return CORPUS / "_gen" / "_base.jpg"
