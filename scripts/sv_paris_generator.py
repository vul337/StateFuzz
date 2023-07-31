# [{"values": [0, 1, 2147483647], "id": 0, "name": "struct.pci_dev,0,37"}]
import sys
import json


f = open(sys.argv[1], "rb")
content = f.read().strip()
# content = '[{"values": [0, 1, 2147483647], "id": 0, "name": "struct.pci_dev,0,37"}]'
dic = json.loads(content)

sv_pairs = []
for sv in dic:
    sv_pair = {}
    sv_pair["name"] = sv["name"]
    sv_pair["id"] = sv["id"]
    sv_pair["values"] = []
    sv_pair["values"].append(sv["id"])
    # id of struct.file,0,7 = 856
    sv_pair["values"].append(856)
    sv_pairs.append(sv_pair)

print json.dumps(sv_pairs)
