from pathlib import Path
from flask import Flask, Response, abort, request

app = Flask(__name__)
PAGES = Path(__file__).resolve().parent / "pages"


@app.get("/")
def index():
    return '<h1>Haunted Library</h1><a href="/read?book=welcome.txt">Read a book</a>'


@app.get("/read")
def read():
    # Deliberately vulnerable: the requested path is not confined to PAGES.
    try:
        text = (PAGES / request.args.get("book", "welcome.txt")).read_text()
    except (OSError, ValueError):
        abort(404)
    return Response(text, mimetype="text/plain")
