"""Point the app at a throwaway DB/upload dir BEFORE any app module is imported."""
import os
import tempfile
from pathlib import Path

TMP = Path(tempfile.mkdtemp(prefix="iftd-test-"))
os.environ["IFTD_DATABASE_URL"] = f"sqlite:///{(TMP / 'test.db').as_posix()}"
os.environ["IFTD_UPLOAD_DIR"] = str(TMP / "uploads")