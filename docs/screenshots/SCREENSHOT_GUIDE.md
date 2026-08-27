# Dashboard Screenshots

The screenshots in this folder illustrate the ULPF Web Operations Dashboard:

1. `dashboard-default.png`: Default view with metric overview cards and simplified event stream.
2. `dashboard-professional.png`: Professional operations center with full UES schema columns, perimeter filters, parser matrix, and dark mode.
3. `dashboard-inspector.png`: Traceability split inspector showing raw forensic payload side-by-side with normalized JSON.

To capture fresh screenshots automatically from a running instance:
```bash
python -m ulpf.dashboard.app --port 8000
```
