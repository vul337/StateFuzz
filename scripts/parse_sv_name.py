import sys
import json


f = open(sys.argv[1], "rb")
lines = f.read()
dic = json.loads(lines)

cnt = 0
cnt_type = {}
cnt_type["flags"] = 0
cnt_type["mode"] = 0
cnt_type["size"] = 0
cnt_type["idx"] = 0
cnt_type["explict_state"] = 0
cnt_type["bool"] = 0
cnt_type["unknown"] = 0
for item in dic:
    # if len(item["values"]) == 1:
    #     continue
    if item["fieldname"] == "":
        continue
    cnt += 1
    if "state" in item["fieldname"] or "status" in item["fieldname"]:
        cnt_type["explict_state"] += 1
        continue
    if "mode" in item["fieldname"] or "type" in item["fieldname"]:
        cnt_type["mode"] += 1
        continue
    if "flag" in item["fieldname"] or "mask" in item["fieldname"]:
        cnt_type["flags"] += 1
        continue
    if "len" in item["fieldname"] or "size" in item["fieldname"] or "cnt" in item["fieldname"] or "count" in item["fieldname"] or "num" in item["fieldname"]:
        cnt_type["size"] += 1
        continue
    if "index" in item["fieldname"] or "idx" in item["fieldname"] or "pos" in item["fieldname"] or item["fieldname"].endswith("id") or "offset" in item["fieldname"] :
        cnt_type["idx"] += 1
        continue
    if "is_" in item["fieldname"] or item["fieldname"].endswith("ed") or item["fieldname"].endswith("done") or item["fieldname"].endswith("ing") or item["fieldname"].endswith("able"):
        cnt_type["bool"] += 1
        continue
    else:
        cnt_type["unknown"] += 1
        print item["fieldname"] + "             " + item["name"]
        continue
    

print cnt
print cnt_type
