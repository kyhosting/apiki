import sys
import os

# Tambahkan api/ ke path supaya bisa import app
sys.path.insert(0, os.path.dirname(__file__))

from app import app

# Vercel butuh variable bernama 'app' atau 'handler'
# Untuk @vercel/python, cukup expose 'app'
