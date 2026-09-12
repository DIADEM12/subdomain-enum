"""
web/app.py — Flask web UI for the subdomain enumerator.

Like cli.py, this is a thin interface layer: it handles HTTP
routing/rendering only. All real logic lives in enumerator/core.py.

Routes:
    GET  /       -> render the search form (templates/index.html)
    POST /scan   -> run enumeration on submitted domain, re-render
                    the same page with results included
"""

import os
import sys
import time

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, render_template, request

from enumerator.core import run_enumeration

app = Flask(__name__)


@app.route("/", methods=["GET"])
def index():
    return render_template(
        "index.html",
        results=None,
        domain=None,
        error=None,
        elapsed=None,
        passive_only=False,
        include_apex=False,
    )


@app.route("/scan", methods=["POST"])
def scan():
    domain = request.form.get("domain", "").strip()
    passive_only = request.form.get("passive_only") == "on"
    include_apex = request.form.get("include_apex") == "on"

    if not domain:
        return render_template(
            "index.html",
            results=None,
            domain=None,
            error="Please enter a domain.",
            elapsed=None,
            passive_only=passive_only,
            include_apex=include_apex,
        )

    # Time the scan so the results page can show how long it actually
    # took — concrete feedback instead of a silent wait.
    start = time.time()
    results = run_enumeration(
        domain,
        use_bruteforce=not passive_only,
        include_apex=include_apex,
    )
    elapsed = round(time.time() - start, 2)

    return render_template(
        "index.html",
        results=results,
        domain=domain,
        error=None,
        elapsed=elapsed,
        passive_only=passive_only,
        include_apex=include_apex,
    )


if __name__ == "__main__":
    # Debug mode is OFF by default — Flask's debug mode exposes an
    # interactive in-browser debugger that allows arbitrary code
    # execution if the server is reachable by anyone else, which is
    # exactly the case once this is deployed. For local development,
    # run with FLASK_DEBUG=true set in your environment to turn it
    # back on (auto-reload, better tracebacks).
    #
    # Note: this block only runs when you launch the app directly
    # with `python app.py`. In production, gunicorn imports the `app`
    # object and serves it directly — this block never executes there,
    # which is exactly what we want.
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(debug=debug_mode)