from pathlib import Path
BASE_DIR = Path(__file__).resolve().parent
SECRET_KEY = "change-this-development-secret-before-deployment"
DATABASE = BASE_DIR / "instance" / "updatetrust.db"
UPLOAD_FOLDER = BASE_DIR / "uploads"
KEY_FOLDER = BASE_DIR / "keys"
MAX_CONTENT_LENGTH = 16 * 1024 * 1024
