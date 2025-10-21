import datetime
import json
import time

import logparse_rs as lp
from logparse_rs import rust_accel

rust_accel.load_schema('schema/schema.json')
rust_accel.load_anonymizer('schema/anonymizer.sample.json')

# Perform an anonymized parse first so the integrity table is populated
# result = rust_accel.parse_kv_enriched_anon('Oct 30 09:46:12 1,2012/10/30 09:46:12,01606001116,TRAFFIC,start,1,2012/04/10 04:39:58,192.168.0.2,204.232.231.46,0.0.0.0,0.0.0.0,rule1,crusher,,web-browsing,vsys1,trust,untrust,ethernet1/2,ethernet1/1,forwardAll,2012/04/10 04:39:59,11449,1,59324,80,0,0,0x200000,tcp,allow,78,78,0,1,2012/04/10 04:39:59,0,any,0,0,0x0,192.168.0.0-192.168.255.255,United States,0,1,0')

result = rust_accel.parse_file('sample_logs/pan_inc.log', anonymized=True)

# Now export the integrity table (will contain the values seen above)
rust_accel.export_integrity_table('schema/integrity_table.json')


# lp.load_schema('schema/schema.json')
# lp.load_anonymizer('schema/anonymizer.sample.json')
# result = lp.parse_kv_enriched('Oct 7 22:09:47 panmgt01p 1,2023/10/07 22:09:46,012501002341,TRAFFIC,end,2561,2023/10/07 22:09:45,10.130.175.124,35.161.3.70,134.7.244.124,35.161.3.70,Curtin-CS-Research-Out,student\XXXXXXXX,,ssl,vsys1,bdr-trust,bdr-untrust,ethernet1/23,ethernet1/24,SPLUNK LOG FP,2023/10/07 22:09:45,876830,1,62813,443,13414,443,0x40447a,tcp,allow,11478,4009,7469,30,2023/10/07 22:09:28,16,computer-and-internet-info,,7253419121911235393,0x8000000000000000,10.0.0.0-10.255.255.255,United States,,15,15,tcp-fin,34,0,0,0,,b309-fu-fw,from-policy,,,0,,0,,N/A,0,0,0,0,90431d13-81da-4129-8bc5-ce968fa06b76,0,0,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,2023-10-07T22:09:45.552+08:00,,,encrypted-tunnel,networking,browser-based,4,used-by-malware able-to-transfer-file has-known-vulnerability tunnel-other-application pervasive-use,,ssl,no,no,0')

count = 0
total_runtime_ns = 0

t0 = time.perf_counter_ns()
for rec in result:
    count += 1
    ns = rec.get('runtime_ns_total') or rec.get('runtime_ns') or 0
    try:
        total_runtime_ns += int(ns)
    except Exception:
        pass
    # print(json.dumps(rec))

t1 = time.perf_counter_ns()
summary = {
    "lines": count,
    "sum_runtime_ns_from_records": total_runtime_ns,
    "sum_runtime_ms_from_records": total_runtime_ns // 1_000_000,
    "wall_clock_ns": t1 - t0,
    "wall_clock_ms": (t1 - t0) // 1_000_000,
    "total_runtime_ns": t1 - t0,
    "total_runtime_ms": (t1 - t0) // 1_000_000,
    "avg_runtime_ns_from_records": (total_runtime_ns // count) if count else 0,
    "avg_runtime_ms_from_records": ((total_runtime_ns / count) / 1_000_000.0) if count else 0.0,
}
print(json.dumps({"summary": summary}))
