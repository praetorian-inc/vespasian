#!/usr/bin/env bash
# Copyright 2026 Praetorian Security, Inc.
#
# Shared POST-form spec assertion helpers for vespasian live tests.
# Sourced by run-live-tests.sh (live end-to-end assertions) and validate_test.sh
# (offline regression cases). Extracted from run-live-tests.sh (LAB-5611 /
# TEST-006) so the helper parsing logic is locked by the ungated
# validator-regression job, not only the label-gated live 'test' job.
#
# Defines:
#   assert_form_body_fields    <spec.yaml> <expected-paths.json>
#   assert_post_get_operations <spec.yaml> <expected-paths.json>
# Both use log_ok/log_fail from common.sh and require python3.

# assert_form_body_fields verifies each urlencoded POST <form>'s input names
# surface as request-body schema properties UNDER THAT FORM'S OWN ENDPOINT. It
# reads post_form_body_fields_by_path {path: [fields...]} from
# expected-paths.json, resolves each path's POST requestBody schema UNDER THE
# application/x-www-form-urlencoded media type (a $ref into components/schemas, or
# an inline properties block) and asserts that schema's properties are EXACTLY the
# expected fields — every expected field present AND no unexpected/foreign field
# beyond them, and a sibling media type such as application/json cannot satisfy the
# urlencoded form contract. This closes the false-pass gap of the
# previous whole-file `grep "^<indent><field>:"`: a field attributed to the
# wrong operation (e.g. all names collapsing onto one path), or masked by a
# same-named property shared across forms (username/password in both login and
# register), or matched from an unrelated schema property, no longer satisfies
# the check. multipart (/api/feedback) has no inferred body schema and is
# intentionally absent from the map.
# Usage: assert_form_body_fields <spec.yaml> <expected-paths.json>
assert_form_body_fields() {
    local spec=$1 expected=$2
    local result rc=0
    result=$(python3 - "$spec" "$expected" << 'PYEOF'
import sys, json, re

# Scoped POST-form body-field check. argv[1]=spec.yaml argv[2]=expected-paths.json.
spec_file = sys.argv[1]
expected_json = sys.argv[2]

with open(expected_json) as f:
    exp = json.load(f)
by_path = exp["post_form_body_fields_by_path"]

with open(spec_file) as f:
    lines = f.read().split("\n")


def ind(s):
    return len(s) - len(s.lstrip(" "))


def section_block(name_regex, start=0, end=None):
    if end is None:
        end = len(lines)
    for i in range(start, end):
        if re.match(name_regex, lines[i]):
            base = ind(lines[i])
            b_end = end
            for j in range(i + 1, end):
                if lines[j].strip() and ind(lines[j]) <= base:
                    b_end = j
                    break
            return i, base, lines[i + 1:b_end]
    return None, None, None


def find_path_block(path):
    in_paths = False
    paths_indent = None
    for i, line in enumerate(lines):
        st = line.rstrip()
        if re.match(r"^paths:\s*$", st):
            in_paths = True
            continue
        if in_paths:
            if st and not st[0].isspace():
                break
            m = re.match(r'^(\s+)(?:"(/[^"]*)"|\'(/[^\']*)\'|(/[^:"\']*)):\s*$', st)
            if m:
                k_indent = len(m.group(1))
                if paths_indent is None:
                    paths_indent = k_indent
                if k_indent == paths_indent:
                    key = m.group(2) or m.group(3) or m.group(4)
                    if key == path:
                        p_end = len(lines)
                        for j in range(i + 1, len(lines)):
                            if lines[j].strip() and ind(lines[j]) <= k_indent:
                                p_end = j
                                break
                        return lines[i + 1:p_end]
    return None


def schema_properties(schema_name):
    ci = None
    for i, line in enumerate(lines):
        if re.match(r"^components:\s*$", line):
            ci = i
            break
    if ci is None:
        return None
    _, _, sblock = section_block(r'^\s+%s:\s*$' % re.escape(schema_name), start=ci)
    if sblock is None:
        return None
    props = []
    in_props = False
    props_indent = None
    child_indent = None
    for line in sblock:
        if re.match(r"^\s+properties:\s*$", line):
            in_props = True
            props_indent = ind(line)
            continue
        if in_props:
            if line.strip() and ind(line) <= props_indent:
                break
            m = re.match(r"^(\s+)([A-Za-z0-9_.$-]+):\s*$", line)
            if m:
                lvl = len(m.group(1))
                if child_indent is None:
                    child_indent = lvl
                if lvl == child_indent:
                    props.append(m.group(2))
    return props


def body_fields_for_path(path):
    pblock = find_path_block(path)
    if pblock is None:
        return None, None, "path not found"
    post_start = None
    post_indent = None
    for k, line in enumerate(pblock):
        if re.match(r"^\s+post:\s*$", line):
            post_start = k
            post_indent = ind(line)
            break
    if post_start is None:
        return None, None, "no POST operation"
    p_end = len(pblock)
    for j in range(post_start + 1, len(pblock)):
        if pblock[j].strip() and ind(pblock[j]) <= post_indent:
            p_end = j
            break
    postblock = pblock[post_start + 1:p_end]
    rb_start = None
    rb_indent = None
    for k, line in enumerate(postblock):
        if re.match(r"^\s+requestBody:\s*$", line):
            rb_start = k
            rb_indent = ind(line)
            break
    if rb_start is None:
        return None, None, "no requestBody"
    r_end = len(postblock)
    for j in range(rb_start + 1, len(postblock)):
        if postblock[j].strip() and ind(postblock[j]) <= rb_indent:
            r_end = j
            break
    rbblock = postblock[rb_start + 1:r_end]

    # Scope the schema search to the application/x-www-form-urlencoded media type
    # (TEST-001): a sibling media type such as application/json must NOT satisfy a
    # urlencoded form contract. Locate content:, then the urlencoded sub-block
    # within it, and restrict BOTH the $ref scan and the inline-properties scan to
    # it. An absent or empty urlencoded body reaches "no request-body schema
    # properties" below (the JSON sibling's fields are never scanned).
    content_start = None
    content_indent = None
    for k, line in enumerate(rbblock):
        if re.match(r"^\s+content:\s*$", line):
            content_start = k
            content_indent = ind(line)
            break
    urlenc = []
    if content_start is not None:
        c_end = len(rbblock)
        for j in range(content_start + 1, len(rbblock)):
            if rbblock[j].strip() and ind(rbblock[j]) <= content_indent:
                c_end = j
                break
        cblock = rbblock[content_start + 1:c_end]
        mt_start = None
        mt_indent = None
        for k, line in enumerate(cblock):
            if re.match(r"^\s+application/x-www-form-urlencoded:\s*$", line):
                mt_start = k
                mt_indent = ind(line)
                break
        if mt_start is not None:
            m_end = len(cblock)
            for j in range(mt_start + 1, len(cblock)):
                if cblock[j].strip() and ind(cblock[j]) <= mt_indent:
                    m_end = j
                    break
            urlenc = cblock[mt_start + 1:m_end]

    for line in urlenc:
        m = re.search(r"\$ref:\s*'?#/components/schemas/([A-Za-z0-9_.-]+)'?", line)
        if m:
            props = schema_properties(m.group(1))
            if props is None:
                return None, None, "schema %s not found" % m.group(1)
            return set(props), "ref:" + m.group(1), None
    in_props = False
    props_indent = None
    child_indent = None
    props = []
    for line in urlenc:
        if re.match(r"^\s+properties:\s*$", line):
            in_props = True
            props_indent = ind(line)
            continue
        if in_props:
            if line.strip() and ind(line) <= props_indent:
                break
            m = re.match(r"^(\s+)([A-Za-z0-9_.$-]+):\s*$", line)
            if m:
                lvl = len(m.group(1))
                if child_indent is None:
                    child_indent = lvl
                if lvl == child_indent:
                    props.append(m.group(2))
    if props:
        return set(props), "inline:" + path, None
    return None, None, "no request-body schema properties"


failures = 0
schema_by_path = {}
for path in sorted(by_path):
    fields = by_path[path]
    got, schema_id, err = body_fields_for_path(path)
    if got is None:
        sys.stderr.write("  detail: %s: %s\n" % (path, err))
        failures += 1
        continue
    schema_by_path[path] = schema_id
    expected_set = set(fields)
    missing = sorted(expected_set - got)
    unexpected = sorted(got - expected_set)
    if missing:
        sys.stderr.write("  detail: %s request-body missing field(s): %s (found: %s)\n"
                         % (path, ", ".join(missing), ", ".join(sorted(got))))
        failures += 1
    if unexpected:
        sys.stderr.write("  detail: %s request-body has unexpected field(s): %s (expected exactly: %s)\n"
                         % (path, ", ".join(unexpected), ", ".join(sorted(expected_set))))
        failures += 1

# Distinctness guard (TEST-002a): each POST form must resolve to its OWN
# request-body schema. A shared/union $ref referenced by more than one path could
# mask per-endpoint field loss for names common to both forms (username/password),
# so two paths resolving to the same schema identity is a failure.
seen = {}
for path in sorted(schema_by_path):
    sid = schema_by_path[path]
    if sid in seen:
        sys.stderr.write("  detail: %s and %s share request-body schema '%s' (schemas must be distinct per endpoint)\n"
                         % (seen[sid], path, sid))
        failures += 1
    else:
        seen[sid] = path

if failures:
    print("POST-form body fields: %d issue(s) - missing field(s) or a request-body schema shared across endpoints" % failures)
    sys.exit(1)
print("POST-form body fields: every form's input names present under its own distinct request-body schema")
sys.exit(0)
PYEOF
    ) || rc=$?
    if [ "$rc" -ne 0 ]; then
        log_fail "${result:-POST-form body fields: check failed}"
        return 1
    fi
    log_ok "${result}"
    return 0
}

# assert_post_get_operations verifies, for each POST-only form action, that the
# generated spec has a POST operation AND no GET operation UNDER THAT EXACT PATH
# (scoped to the path block, not a whole-file summary grep). The GET-absence half
# is load-bearing for the "must NOT appear" contract, but the mechanism that
# keeps a GET off a POST-only action is target-dependent: on forms-target the
# crawler's GET probe of the form action 404s and is filtered at the default 0.5
# confidence; on rest-api/scan-rest the unrouted action is served by the catch-all
# as 200 text/html and is dropped by non-API/HTML classification instead. Either
# way a GET operation appearing on a POST-only action is a regression in that
# filtering path. Reads post_form_paths from expected-paths.json.
# Usage: assert_post_get_operations <spec.yaml> <expected-paths.json>
assert_post_get_operations() {
    local spec=$1 expected=$2
    local result rc=0
    result=$(python3 - "$spec" "$expected" << 'PYEOF'
import sys, json, re

spec_file = sys.argv[1]
expected_json = sys.argv[2]

with open(expected_json) as f:
    exp = json.load(f)
paths = exp["post_form_paths"]

with open(spec_file) as f:
    lines = f.read().split("\n")


def ind(s):
    return len(s) - len(s.lstrip(" "))


def path_operations(target):
    in_paths = False
    paths_indent = None
    for i, line in enumerate(lines):
        st = line.rstrip()
        if re.match(r"^paths:\s*$", st):
            in_paths = True
            continue
        if in_paths:
            if st and not st[0].isspace():
                break
            m = re.match(r'^(\s+)(?:"(/[^"]*)"|\'(/[^\']*)\'|(/[^:"\']*)):\s*$', st)
            if m:
                k_indent = len(m.group(1))
                if paths_indent is None:
                    paths_indent = k_indent
                if k_indent == paths_indent:
                    key = m.group(2) or m.group(3) or m.group(4)
                    if key == target:
                        ops = set()
                        child_indent = None
                        for j in range(i + 1, len(lines)):
                            if lines[j].strip() and ind(lines[j]) <= k_indent:
                                break
                            mo = re.match(r"^(\s+)([a-z]+):\s*$", lines[j])
                            if mo:
                                lvl = len(mo.group(1))
                                if child_indent is None:
                                    child_indent = lvl
                                if lvl == child_indent and mo.group(2) in (
                                    "get", "post", "put", "patch", "delete", "head", "options"
                                ):
                                    ops.add(mo.group(2))
                        return ops
    return None


failures = 0
for p in paths:
    ops = path_operations(p)
    if ops is None:
        sys.stderr.write("  detail: %s: path not present in spec\n" % p)
        failures += 1
        continue
    if "post" not in ops:
        sys.stderr.write("  detail: %s: expected POST operation, found: %s\n"
                         % (p, ", ".join(sorted(ops)) or "none"))
        failures += 1
    if "get" in ops:
        sys.stderr.write("  detail: %s: unexpected GET operation on POST-only action (404/confidence or non-API/HTML filter regressed?)\n" % p)
        failures += 1

if failures:
    print("POST/GET operations: %d issue(s) on form action paths" % failures)
    sys.exit(1)
print("POST/GET operations: every POST action has a post op and no get op, scoped to its path")
sys.exit(0)
PYEOF
    ) || rc=$?
    if [ "$rc" -ne 0 ]; then
        log_fail "${result:-POST/GET operations: check failed}"
        return 1
    fi
    log_ok "${result}"
    return 0
}

# assert_path_methods locks the per-path HTTP method sets the rest-api fixtures
# declare. TEST-001 (PR #208): this PR made expected-paths.json and
# scan-expected-paths.json deliberately diverge on /api/login and /api/upload
# (two-stage GET-only vs scan GET+POST) to encode real generator behavior, but no
# assertion read the method VALUES — validate_path_coverage keys on path names,
# _assert_fixture_parity's norm() omits methods, and assert_post_get_operations
# reads only post_form_paths (/api/subscribe). So the divergence was inert: a
# regression that flipped either path's classification would not fail a test.
#
# This reads each declared path's method list and asserts its {get,post} membership
# against the generated spec's operation set for that path. The comparison universe
# is deliberately {get,post} — the only verbs these fixtures track — so it is
# immune to any put/patch/delete/options a pipeline legitimately emits, yet still
# catches two-stage-emits-POST and scan-drops-POST in both directions (and, as a
# bonus, locks every resource path GET-only and /api/subscribe POST-only). A
# fixture verb outside {get,post} fails loudly rather than being silently dropped.
# Paths are matched POSITIONALLY (params vs params), because the spec normalizes
# param names ({userId}) while the fixtures use {id}.
# Usage: assert_path_methods <spec.yaml> <expected-paths.json>
assert_path_methods() {
    local spec=$1 expected=$2
    local result rc=0
    result=$(python3 - "$spec" "$expected" << 'PYEOF'
import sys, json, re

spec_file = sys.argv[1]
expected_json = sys.argv[2]
TRACKED = ("get", "post")

with open(expected_json) as f:
    exp = json.load(f)
declared = exp["paths"]

with open(spec_file) as f:
    lines = f.read().split("\n")


def ind(s):
    return len(s) - len(s.lstrip(" "))


def paths_match(expected_path, found_path):
    e_parts = expected_path.strip("/").split("/")
    f_parts = found_path.strip("/").split("/")
    if len(e_parts) != len(f_parts):
        return False
    for e, f in zip(e_parts, f_parts):
        e_is_param = e.startswith("{") and e.endswith("}")
        f_is_param = f.startswith("{") and f.endswith("}")
        if e_is_param or f_is_param:
            continue
        if e != f:
            return False
    return True


# Map every top-level spec path key to its first-level operation set.
def collect_spec_paths():
    result = {}
    in_paths = False
    paths_indent = None
    i = 0
    while i < len(lines):
        st = lines[i].rstrip()
        if re.match(r"^paths:\s*(|\{\})\s*$", st):
            in_paths = True
            if "{}" in st:
                break
            i += 1
            continue
        if in_paths:
            if st and not st[0].isspace():
                break
            m = re.match(r'^(\s+)(?:"(/[^"]*)"|\'(/[^\']*)\'|(/[^:"\']*)):\s*$', st)
            if m:
                k_indent = len(m.group(1))
                if paths_indent is None:
                    paths_indent = k_indent
                if k_indent == paths_indent:
                    key = m.group(2) or m.group(3) or m.group(4)
                    ops = set()
                    child_indent = None
                    j = i + 1
                    while j < len(lines):
                        if lines[j].strip() and ind(lines[j]) <= k_indent:
                            break
                        mo = re.match(r"^(\s+)([a-z]+):\s*$", lines[j])
                        if mo:
                            lvl = len(mo.group(1))
                            if child_indent is None:
                                child_indent = lvl
                            if lvl == child_indent and mo.group(2) in (
                                "get", "post", "put", "patch", "delete", "head", "options"
                            ):
                                ops.add(mo.group(2))
                        j += 1
                    result[key] = ops
        i += 1
    return result


spec_paths = collect_spec_paths()

failures = 0
for path, methods in declared.items():
    lowered = [m.lower() for m in methods]
    untracked = sorted(set(m for m in lowered if m not in TRACKED))
    if untracked:
        sys.stderr.write(
            "  detail: %s: fixture declares verb(s) %s outside the asserted {get,post} universe -- widen assert_path_methods\n"
            % (path, ", ".join(untracked)))
        failures += 1
        continue
    expected_tracked = set(m for m in lowered if m in TRACKED)
    matches = [sp for sp in spec_paths if paths_match(path, sp)]
    if not matches:
        sys.stderr.write("  detail: %s: path not present in spec\n" % path)
        failures += 1
        continue
    actual_tracked = set()
    for sp in matches:
        actual_tracked |= (spec_paths[sp] & set(TRACKED))
    if actual_tracked != expected_tracked:
        sys.stderr.write(
            "  detail: %s: method mismatch: expected get/post set %s, spec has %s\n"
            % (path, ", ".join(sorted(expected_tracked)) or "none",
               ", ".join(sorted(actual_tracked)) or "none"))
        failures += 1

if failures:
    print("path methods: %d path(s) disagree with declared {get,post} method sets" % failures)
    sys.exit(1)
print("path methods: every declared path's {get,post} operations match the fixture")
sys.exit(0)
PYEOF
    ) || rc=$?
    if [ "$rc" -ne 0 ]; then
        log_fail "${result:-path methods: check failed}"
        return 1
    fi
    log_ok "${result}"
    return 0
}
