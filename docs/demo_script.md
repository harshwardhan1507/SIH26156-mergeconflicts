# <img src="ulpf-icon.svg" width="28" height="28" alt="ULPF" /> ULPF Demo Script (~2 min)

Commands run from the project root. `ulpf` CLI must be installed (`pip install -e .[dev]`).
Timings are approximate cut points for recording, not hard pauses.

---

## 0:00–0:15 What we have

```bash
ulpf list-parsers
```

11 parsers: syslog RFC 3164/5424, CEF, LEEF 1.0/2.0, Windows/generic XML, Cisco ASA,
Palo Alto CSV, AWS CloudTrail, Azure Monitor, GCP Audit, generic JSON.

---

## 0:15–0:35 Ingest everything, in parallel

```bash
ulpf ingest --input ulpf/sample_logs/ --output output/ --workers 4
```

```
Starting ingestion from 'ulpf/sample_logs/' -> 'output/' [ndjson] [workers=4]
Done. Processed=63 Valid=63 Invalid=0 Errors=0
```

Point out `--workers 4`: log ingestion is fanned out across processes with a
streaming chunk generator (no buffering the whole input in RAM), and each
sink write goes through the same at-least-once path a single-process run does.

---

## 0:35–1:00 One event, every guarantee at once

```bash
python -c "
import json
e = [json.loads(l) for l in open('output/events.ndjson')
     if json.loads(l)['lineage']['parser_name'] == 'cef'][0]
print('event_id       ', e['event_id'])
print('vendor/product ', e['source']['vendor'], '/', e['source']['product'])
print('category/action', e['event']['category'], '/', e['event']['action'])
print('OCSF class     ', e['event']['class_name'], e['event']['class_uid'])
print('src -> dst     ', e['network']['src_ip'], '->', e['network']['dst_ip'])
print('vendor_attrs   ', e['vendor_attributes'])   # fields with no UES home — kept, not dropped
print('raw_hash       ', e['raw']['raw_hash'][:16], '...')
"
ulpf lookup --event-id <event-id-from-above>
```

Same SHA-256 that's embedded in the normalized event; `lookup` pulls it from
the raw store, byte-for-byte, computed over the original bytes before any
text decoding happened — non-UTF-8 input included.

---

## 1:00–1:20 A log a parser doesn't recognize — nothing is silently dropped

```bash
echo 'this is not a known format @@@###' | ulpf ingest --input - --output output_dl/
cat output_dl/dead_letter.ndjson | python -m json.tool
```

Shows `event_id`, `raw_payload`, `raw_hash`, and the reason. The raw bytes
were written to the raw store *before* detection ran, so even a completely
unrecognized log is retrievable by `ulpf lookup` — it just also gets
quarantined instead of silently vanishing.

---

## 1:20–1:40 Live syslog ingestion — the actual perimeter-device path

```bash
ulpf listen --port 15514 --output output_live/ &
printf '<134>Mar 15 10:22:45 fw01 CEF:0|Fortinet|FortiGate|6.4|13|Traffic Denied|7|src=10.1.1.9 dst=8.8.8.8\n' \
  | nc -u -w0 127.0.0.1 15514
sleep 1
tail -1 output_live/events.ndjson | python -c "import json,sys; e=json.loads(sys.stdin.read()); print(e['source']['vendor'], e['network']['src_ip'])"
```

Real syslog-wrapped CEF over UDP, not a pre-formatted fixture — vendor and
5-tuple come out correctly on the standard RFC3164-plus-CEF wire format.

---

## 1:40–2:00 Plug-and-play — new format, zero core edits

Drop a parser file + YAML mapping into `parsers/` / `schemas/mappings/`
(shown in the README) and:

```bash
ulpf list-parsers   # new format appears automatically — pkgutil discovery
```

No edits anywhere in `core/` — no format enum to update, no detector branch
required for it to round-trip correctly (an unrecognized-but-parseable
format still carries its own `log_format` end to end).
