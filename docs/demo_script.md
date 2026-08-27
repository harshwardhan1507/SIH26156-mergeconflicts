# Demo script (~2 min)

Commands run from the project root. `ulpf` CLI must be installed (`pip install -e .[dev]`).

---

## 0:00-0:15  What we have

```bash
ulpf list-parsers
ls ulpf/sample_logs/
```

Show: 6 parsers registered, 6 log files covering each format.

---

## 0:15-0:40  Run the pipeline

```bash
ulpf --log-level info ingest --input ulpf/sample_logs/ --output output/
```

Output:
```
Starting ingestion from 'ulpf/sample_logs/' -> 'output/' [ndjson]
Done. Processed=28 Valid=28 Invalid=0 Errors=0
```

```bash
ls output/
```

Three things: `events.ndjson`, `dead_letter.ndjson`, `raw_store/`.

---

## 0:40-1:00  Look at normalized output, then look up the raw line

```bash
python -c "
import json
events = [json.loads(l) for l in open('output/events.ndjson')]
for e in events[:2]:
    print(json.dumps({
        'event_id': e['event_id'],
        'parser': e['lineage']['parser_name'],
        'category': e['event']['category'],
        'outcome': e['event']['outcome'],
        'severity': e['event']['severity_numeric'],
        'src': e.get('network') and e['network'].get('src_ip'),
        'dst': e.get('network') and e['network'].get('dst_ip'),
    }, indent=2))
"
```

Copy an `event_id` from the output, then:

```bash
ulpf lookup --event-id <event-id>
```

Prints the exact original log line. Same sha256 is in `raw.raw_hash` of the normalized event.

---

## 1:00-1:10  Dead-letter

```bash
echo '{"broken": true}' | ulpf --log-level info ingest --input - --output output_dl/
cat output_dl/dead_letter.ndjson | python -m json.tool
```

Shows the failed event with `event_id`, `raw_payload`, and the schema validation
errors. It didn't get dropped silently.

---

## 1:10-1:40  Add a new parser, no core changes

Create `ulpf/parsers/fortinet_syslog.py`:

```python
from ulpf.parsers.base import BaseParser
from ulpf.core.registry import register_parser

@register_parser
class FortinetSyslogParser(BaseParser):
    name       = 'fortinet_syslog'
    version    = '1.0.0'
    log_format = 'syslog_rfc3164'

    def match(self, raw_line):
        return 'devname=' in raw_line and 'type=' in raw_line

    def extract(self, raw_line):
        import re
        kv = dict(re.findall(r'(\w+)=(\S+)', raw_line))
        ts = self.parse_timestamp(kv.get('date', '') + ' ' + kv.get('time', ''))
        return {
            '_raw': raw_line,
            '_log_format': self.log_format,
            'timestamp_dt': ts.isoformat() if ts else None,
            'hostname': kv.get('devname'),
            'src_ip': self.validate_ip(kv.get('srcip')),
            'dst_ip': self.validate_ip(kv.get('dstip')),
            'src_port': self.safe_port(kv.get('srcport')),
            'dst_port': self.safe_port(kv.get('dstport')),
            'proto': kv.get('proto'),
            'severity_ues': 5,
            'vendor': 'Fortinet',
            'product': 'FortiGate',
        }
```

Create `ulpf/schemas/mappings/fortinet_syslog.yaml` with the field mapping.
Add `fortinet_syslog` to the imports in `parsers/__init__.py`.

Then:

```bash
ulpf list-parsers   # fortinet_syslog appears

echo 'date=2024-03-15 time=10:22:45 devname=fw01 type=traffic srcip=10.0.0.5 dstip=203.0.113.1 srcport=44321 dstport=443 proto=tcp' \
  | ulpf ingest --input - --output output_fortinet/

python -c "import json; e=json.loads(open('output_fortinet/events.ndjson').read()); print(e['lineage']['parser_name'])"
# fortinet_syslog
```

Nothing in `core/` was touched.

---

## 1:40-2:00  Docker (if available)

```bash
docker compose -f docker/docker-compose.yml build
docker compose -f docker/docker-compose.yml up
```

Point out `network_mode: none` in the compose file. Output lands in `docker/output/`.

The stage 2 build installs everything with `pip install --no-index`, so once
the image is built it has no reason to reach the network.

**If Docker is not available:** show that debug logging produces zero HTTP/DNS/socket lines:

```bash
ulpf --log-level debug ingest --input ulpf/sample_logs/ --output output/ 2>&1 \
  | grep -Ei "(http|dns|socket|connect)" | wc -l
# 0
```
