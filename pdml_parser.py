import xml.etree.ElementTree as ET
from typing import List, Dict
import ipdb

g_protocol = None

def merge_duplicate_fields(packet_fields):
    merged = {}
    for field in packet_fields:
        key = (field['offset'], field['size'], field['value'])
        if key in merged:
            # merged[key]['field_name'] += '_' + field['field_name']
            pass
        else:
            merged[key] = field.copy() 
    return list(merged.values())

def manual_split():
    global g_protocol
    if g_protocol == "mms":
        return True
    return False

def split_large_fields(fields):
    fields = sorted(fields, key=lambda f: f['offset'])
    result = []
    i = 0

    while i < len(fields):
        f = fields[i]
        if f['size'] > 1:
            start = f['offset']
            end = start + f['size']

            overlapping = []
            for g in fields[i+1:]:
                g_start = g['offset']
                g_end = g_start + g['size']
                if g_start >= start and g_end <= end:
                    overlapping.append(g)

            if overlapping:
                covered = [False] * f['size']
                for g in overlapping:
                    for idx in range(g['offset'], g['offset']+g['size']):
                        covered[idx - start] = True

                if all(covered):
                    i += 1
                    continue
                else:
                    split_start = None
                    split_counter = 0
                    for idx, c in enumerate(covered):
                        if not c:
                            if split_start is None:
                                split_start = idx
                        else:
                            if split_start is not None:
                                if manual_split():
                                    new_offset = start + split_start
                                    new_size = idx - split_start
                                    print(f, new_offset, new_size)
                                    for j in range(new_size):
                                        n_size = 1
                                        n_value = f['value'][split_start*2:(split_start+n_size)*2]
                                        result.append({
                                            'protocol': f['protocol'],
                                            'field_name': f"mark_{j}_{f['field_name']}_split_{split_counter}",
                                            'offset': new_offset,
                                            'size': n_size,
                                            'value': n_value
                                        })
                                        split_start += 1
                                        new_offset += 1
                                        split_counter += 1
                                    split_start = None
                                else:
                                    new_offset = start + split_start
                                    new_size = idx - split_start
                                    new_value = f['value'][split_start*2:(split_start+new_size)*2]
                                    result.append({
                                        'protocol': f['protocol'],
                                        'field_name': f"{f['field_name']}_split_{split_counter}",
                                        'offset': new_offset,
                                        'size': new_size,
                                        'value': new_value
                                    })
                                    split_counter += 1
                                    split_start = None

                    if split_start is not None:
                        if manual_split():
                            new_offset = start + split_start
                            new_size = idx - split_start
                            for j in range(new_size):
                                n_size = 1
                                n_value = f['value'][split_start*2:(split_start+n_size)*2]
                                result.append({
                                    'protocol': f['protocol'],
                                    'field_name': f"mark_{j}_{f['field_name']}_split_{split_counter}",
                                    'offset': new_offset,
                                    'size': n_size,
                                    'value': n_value
                                })
                                split_start += 1
                                new_offset += 1
                                split_counter += 1
                        else:
                            new_offset = start + split_start
                            new_size = f['size'] - split_start
                            new_value = f['value'][split_start*2:]*2
                            result.append({
                                'protocol': f['protocol'],
                                'field_name': f"{f['field_name']}_split_{split_counter}",
                                'offset': new_offset,
                                'size': new_size,
                                'value': f['value'][split_start*2:]
                            })
                            split_counter += 1
            else:
                result.append(f)
        else:
            result.append(f)
        i += 1

    result = sorted(result, key=lambda f: f['offset'])
    return result

def deduplicate_packets(results):
    seen = set()
    deduped_results = {}
    new_idx = 0

    for idx in sorted(results.keys()):
        frame = results[idx]
        frame_signature = tuple(
            (f["field_name"], f["offset"], f["size"]) 
            # (f["field_name"], f["offset"], f["size"], f["value"]) 
            for f in frame
        )

        if frame_signature not in seen:
            seen.add(frame_signature)
            deduped_results[new_idx] = frame
            new_idx += 1
    return deduped_results

def fill_field_gaps(fields, payload_dict, fill_prefix="gap"):
    if not fields:
        return []

    frame_no = ""
    frame_no_name = ""
    for item in fields:
        if 'frame_no' in item:
            frame_no = item['frame_no']
            frame_no_name = "_".join(item['frame_no'].split(" "))

    payload = payload_dict[frame_no]['payload']
    transport_end = payload_dict[frame_no]['transport_end']
    fields_sorted = sorted(fields, key=lambda f: f['offset'])
    filled_fields = []
    gap_counter = 0

    for i, f in enumerate(fields_sorted):
        if filled_fields:
            prev_end = filled_fields[-1]['offset'] + filled_fields[-1]['size']
            gap = f['offset'] - prev_end
            if gap > 0:
                for j in range(gap):
                    rel_offset = prev_end + j
                    value = payload[rel_offset*2:(rel_offset+1)*2]
                    filled_fields.append({
                        'field_name': f"{frame_no_name}_{fill_prefix}_{gap_counter}_{j}",
                        'offset': prev_end + j,
                        'size': 1,
                        'value': value
                    })
                    gap_counter += 1
        filled_fields.append(f)

    return filled_fields

def parse_pdml(pdml_file):
    tree = ET.parse(pdml_file)
    root = tree.getroot()

    results = {}
    payloads = {}

    for pkt_idx, packet in enumerate(root.findall("packet")):
        transport_end = None
        payload = None
        frame_no = None

        for proto in packet.findall("proto"):
            pname = proto.get("name", "")
            if pname == "frame":
                showname = proto.get("showname")
                frame_no = showname.split(":")[0]
                frame_size = proto.get("size")
                if int(frame_size) > 200:
                    break
            if pname in ("tcp", "udp"):
                max_end = None
                pos = int(proto.get("pos"))
                size = int(proto.get("size"))
                transport_end = pos + size
                for field in proto.findall(".//field"):
                    name = field.get("name")
                    if ".payload" in name:
                        payload = field.get("value")

        if transport_end is None or payload is None:
            continue

        results[pkt_idx] = []
        payloads[frame_no] = {'payload': payload, 'transport_end': transport_end}

        for proto in packet.findall("proto"):
            pname = proto.get("name", "")

            if pname in ("frame", "eth", "ip", "ipv6", "tcp", "udp"):
                continue

            for field in proto.findall(".//field"):
                name = field.get("name")
                pos = field.get("pos")
                size = field.get("size")

                if not name:
                    show = field.get("show")
                    name = show.split(":")[0].replace(" ", "_")

                if not name or pos is None or size is None:
                    continue

                size = int(size)
                if size < 1:
                    continue

                pos = int(pos)
                rel_offset = pos - transport_end

                if rel_offset < 0:
                    continue

                value = payload[rel_offset*2:(rel_offset+size)*2]
                if len(value) == size * 2:
                    results[pkt_idx].append({
                        "frame_no": frame_no,
                        "protocol": pname,
                        "field_name": name,
                        "offset": rel_offset,
                        "size": size,
                        "value": value
                    })

    results = deduplicate_packets(results)

    merged = {}
    for pkt_id, packet in results.items():
        merged[pkt_id] = merge_duplicate_fields(packet)

    counter = {}
    for idx, packet in merged.items():
        for item in packet:
            name = item['field_name']
            if name not in counter:
                counter[name] = 1
            else:
                counter[name] += 1
            if counter[name] > 1:
                item['field_name'] = f"{name}_{counter[name]-1}"

    splited = {}
    for pkt_id, packet in merged.items():
        splited[pkt_id] = split_large_fields(packet)

    filled = {}
    for pkt_id, packet in splited.items():
        filled[pkt_id] = fill_field_gaps(packet, payloads)

    return filled