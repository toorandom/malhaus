"""
API documentation blueprint.
"""
from flask import Blueprint, render_template

api_docs_bp = Blueprint("api_docs_bp", __name__, url_prefix="")


@api_docs_bp.route("/api-docs")
def api_docs():
    return render_template("api_docs.html")
