#!/usr/bin/env python3
"""Deprecated entrypoint.

PhishCreator previously shipped an `app_enhanced.py` entrypoint.

`phishcreator/app.py` is now the canonical Flask server.
This file remains as a thin wrapper for backward compatibility.

Run:
    python3 -m phishcreator.app
or:
    python3 phishcreator/app.py
"""

from phishcreator.app import app


if __name__ == '__main__':
    # Match app.py defaults
    import os

    port = int(os.environ.get('PORT', 5050))
    app.run(host='0.0.0.0', port=port, debug=False)
