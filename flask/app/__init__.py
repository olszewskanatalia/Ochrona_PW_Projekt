import os

from flask_wtf.csrf import CSRFProtect

from flask import Flask

app = Flask(__name__)

# Get the absolute path to the current directory
current_dir = os.path.abspath(os.path.dirname(__file__))

# Connect to the SQLite database using the absolute path
db_path = os.path.join(current_dir, 'sqlite', 'notes.db')

app.config['SQLITE_DATABASE'] = db_path
app.config['SERVER_NAME'] = None  # Turn off headline "Server"
app.config['SECRET_KEY'] = "206363ef77d567cc511df5098695d2b85058952afd5e2b1eecd5aed981805e60"

csrf = CSRFProtect(app)

from app import views
