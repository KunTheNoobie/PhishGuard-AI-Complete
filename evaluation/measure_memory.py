"""Peak memory of the full service with real BERT (int8) and YOLOv8n: python -m evaluation.measure_memory"""
import base64
import io
import os
import time

os.environ.setdefault("PHISHGUARD_DB_PATH", ":memory:")
os.environ.setdefault("PHISHGUARD_RATE_LIMIT", "10000/minute")
os.environ["PHISHGUARD_SEED_DEMO"] = "false"
import psutil  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from PIL import Image  # noqa: E402

from main import app  # noqa: E402

proc = psutil.Process()


def mb() -> float:
    info = proc.memory_info()
    return round(getattr(info, "peak_wset", info.rss) / 1048576, 1)


shot = io.BytesIO()
Image.new("RGB", (1280, 720), (240, 240, 240)).save(shot, "JPEG")
screenshot = "data:image/jpeg;base64," + base64.b64encode(shot.getvalue()).decode()
with TestClient(app, base_url="https://local") as c:
    c.headers["Authorization"] = "Bearer 12345678"
    time.sleep(3)
    print("after start-up (models loaded): current", round(proc.memory_info().rss / 1048576, 1), "MB, peak", mb(), "MB")
    for i in range(30):
        c.post("/api/v1/analyze", json={"url": f"https://account-check-{i}.example.top/login", "dom_content": "<form><input type=password></form>",
                                         "text_content": "verify your account", "screenshot": screenshot})
    print("after 30 analyses with screenshots: current", round(proc.memory_info().rss / 1048576, 1), "MB, peak", mb(), "MB")
