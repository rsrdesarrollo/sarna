import os
from os import path

DATABASE_PATH = path.abspath(os.getenv('SARNA_DATABASE_PATH', './database'))
UPLOAD_PATH = path.abspath(os.getenv('SARNA_UPLOAD_PATH', './uploaded_data'))
