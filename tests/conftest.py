import hashlib
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"

# 実機の Qt インストール (存在すれば統合テストで使用)
REAL_QT_SBOM_DIR = Path("C:/Qt/6.11.1/msvc2022_64/sbom")


def sha1_of(path: Path) -> str:
    return hashlib.sha1(Path(path).read_bytes()).hexdigest()


def sha256_of(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


@pytest.fixture
def qt_sbom_dir() -> Path:
    return FIXTURES / "qt-sbom"


@pytest.fixture
def vendor_sbom_file() -> Path:
    return FIXTURES / "vendorlib-1.2.3.spdx.json"
