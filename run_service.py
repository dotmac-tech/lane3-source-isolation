"""Trusted installation entrypoint; isolated Python omits script path by default."""
import pathlib
import sys
root = pathlib.Path(__file__).resolve().parent
sys.path.insert(0,str(root))
from service import main
try:
    raise SystemExit(main())
except Exception:
    raise SystemExit('Service refused startup; check nonsecret configuration.')
