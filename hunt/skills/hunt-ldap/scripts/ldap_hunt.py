#!/usr/bin/env python3
"""
ldap_hunt.py — single streaming pass over a pre-filtered Suricata EVE JSON log
for LDAP / CLDAP threat hunting. Part of the hunt-ldap skill.

Input : a JSONL file holding event_type:ldap records plus the flow / anomaly /
        alert records for the same traffic (see SKILL.md Step 2 for the prefilter).
Output: a sectioned text report on stdout and CSV ledgers in --artifacts.

Read-only over the input. Never writes credential material: NTLM/Kerberos
response blobs are parsed for identity fields and lengths only, and the
NT/LM responses (crackable NetNTLM material) are never emitted. Attribute
VALUES of secret attributes (unicodePwd, LAPS, ...), PasswordModify request
values and compare-assertion values are never emitted either — only names.

Memory is bounded: every row list and per-key set is capped; anything dropped
is counted and reported in BASELINE so a truncated view is never silent.
"""
import argparse, collections as C, csv, ipaddress, json, os, re, struct, sys
from datetime import datetime

# --------------------------------------------------------------------------- maps
SENSITIVE_ATTRS = {
    # password / secret material — readable only over a privileged, ideally sealed session
    'ms-mcs-admpwd': 'secret:LAPS', 'ms-mcs-admpwdexpirationtime': 'secret:LAPS',
    'mslaps-password': 'secret:LAPS', 'mslaps-encryptedpassword': 'secret:LAPS',
    'mslaps-encryptedpasswordhistory': 'secret:LAPS',
    'mslaps-encrypteddsrmpassword': 'secret:LAPS-DSRM',
    'mslaps-encrypteddsrmpasswordhistory': 'secret:LAPS-DSRM',
    'ms-ds-managedpassword': 'secret:gMSA', 'msds-managedpassword': 'secret:gMSA',
    'msds-groupmsamembership': 'secret:gMSA-readers',
    'unicodepwd': 'secret:password', 'userpassword': 'secret:password',
    'unixuserpassword': 'secret:password', 'mssfu30password': 'secret:password',
    'dbcspwd': 'secret:password', 'ntpwdhistory': 'secret:password',
    'lmpwdhistory': 'secret:password', 'supplementalcredentials': 'secret:password',
    'msfve-recoverypassword': 'secret:BitLocker', 'mstpm-ownerinformation': 'secret:TPM',
    'trustauthincoming': 'secret:trust', 'trustauthoutgoing': 'secret:trust',
    'msds-keycredentiallink': 'shadow-credentials',
    # kerberos attack surface
    'serviceprincipalname': 'kerberoast', 'useraccountcontrol': 'asrep/uac',
    'msds-supportedencryptiontypes': 'kerberoast',
    # delegation
    'msds-allowedtoactonbehalfofotheridentity': 'rbcd',
    'msds-allowedtodelegateto': 'delegation',
    # ACL / privilege
    'ntsecuritydescriptor': 'acl', 'allowedattributeseffective': 'acl-probe',
    'allowedchildclasseseffective': 'acl-probe', 'sidhistory': 'sidhistory',
    'admincount': 'priv-recon', 'ms-ds-machineaccountquota': 'maq',
    'ms-ds-creatorsid': 'maq',
    # ADCS / certificate mapping
    'pkiextendedkeyusage': 'adcs', 'mspki-certificate-name-flag': 'adcs',
    'mspki-enrollment-flag': 'adcs', 'mspki-ra-signature': 'adcs',
    'mspki-certificate-application-policy': 'adcs',
    'cacertificate': 'adcs', 'certificatetemplates': 'adcs',
    'altsecurityidentities': 'cert-mapping (ESC14)',
    # GPO / logon script persistence
    'gpcfilesyspath': 'gpo', 'gplink': 'gpo', 'scriptpath': 'logon-script',
    'gpcmachineextensionnames': 'gpo-extension', 'gpcuserextensionnames': 'gpo-extension',
    # interesting only on WRITE
    'dnshostname': 'certifried? (CVE-2022-26923)',
    'samaccountname': 'samaccountname-rename (noPac?)',
    'userprincipalname': 'upn-change (ESC9/ESC10?)',
    'primarygroupid': 'primaryGroupID-change',
    'member': 'group-membership',
}
WRITE_ONLY_INTEREST = {'dnshostname', 'samaccountname', 'userprincipalname',
                       'primarygroupid', 'member', 'gpcmachineextensionnames',
                       'gpcuserextensionnames'}
SECRET_ATTRS = {k for k, v in SENSITIVE_ATTRS.items() if v.startswith('secret:')}

# Log4Shell / JNDI: a directory reply that hands the client a Java object or codebase
JNDI_ATTRS = {'javacodebase', 'javaclassname', 'javaclassnames', 'javaserializeddata',
              'javafactory', 'javareferenceaddress', 'javaremotelocation'}
JNDI_OBJCLASS = ('javanamingreference', 'javaserializedobject', 'javamarshalledobject',
                 'javaobject', 'javacontainer')

PRIV_GROUPS = ('domain admins', 'enterprise admins', 'administrators', 'schema admins',
               'account operators', 'backup operators', 'server operators',
               'print operators', 'dnsadmins', 'group policy creator owners',
               'key admins', 'enterprise key admins', 'cert publishers',
               'domain controllers', 'enterprise domain controllers',
               'exchange windows permissions', 'exchange trusted subsystem',
               'organization management')
PRIV_GROUP_RE = re.compile(r'^cn=(%s),' % '|'.join(re.escape(g) for g in PRIV_GROUPS))

CONTROLS = {
    '1.2.840.113556.1.4.319': 'paged-results (bulk dump)',
    '1.2.840.113556.1.4.801': 'SD_FLAGS (reads security descriptors)',
    '1.2.840.113556.1.4.841': 'DirSync (secret replication over LDAP)',
    '1.2.840.113556.1.4.2090': 'DirSync_EX (secret replication over LDAP)',
    '1.2.840.113556.1.4.805': 'TREE-DELETE (recursive deletion)',
    '1.2.840.113556.1.4.1504': 'ASQ (attribute-scoped query: group/membership walk)',
    '1.2.840.113556.1.4.417': 'show-deleted',
    '1.2.840.113556.1.4.2064': 'show-recycled',
    '1.2.840.113556.1.4.2065': 'show-deactivated-link',
    '1.2.840.113556.1.4.529': 'extended-DN',
    '1.2.840.113556.1.4.473': 'server-sort',
    '1.2.840.113556.1.4.1339': 'domain-scope',
    '1.2.840.113556.1.4.1413': 'permissive-modify',
    '1.2.840.113556.1.4.2239': 'policy-hints',
    '1.2.840.113556.1.4.2066': 'policy-hints (deprecated OID)',
    '1.2.840.113556.1.4.521': 'cross-domain-move',
    '2.16.840.1.113730.3.4.9': 'VLV',
}
DIRSYNC = {'1.2.840.113556.1.4.841', '1.2.840.113556.1.4.2090'}
PAGED, SDFLAGS, TREEDEL = ('1.2.840.113556.1.4.319', '1.2.840.113556.1.4.801',
                           '1.2.840.113556.1.4.805')
EXT_OPS = {
    '1.3.6.1.4.1.1466.20037': 'StartTLS',
    '1.3.6.1.4.1.4203.1.11.1': 'PasswordModify',
    '1.3.6.1.4.1.4203.1.11.3': 'WhoAmI',
    '1.2.840.113556.1.4.1781': 'FastConcurrentBind',
    '1.3.6.1.4.1.1466.101.119.1': 'DynamicRefresh',
    '1.2.840.113556.1.4.2212': 'BatchRequest',
}
# AD diagnostic "data XXX" sub-codes in bind failures
AD_DATA = {'525': 'user not found', '52e': 'bad password', '530': 'logon time restriction',
           '531': 'workstation restriction', '532': 'password expired',
           '533': 'account disabled', '568': 'too many SIDs', '701': 'account expired',
           '773': 'must reset password', '775': 'ACCOUNT LOCKED OUT'}
WRITE_OPS = ('modify_request', 'add_request', 'del_request', 'mod_dn_request')
NOTABLE_RC = {'invalid_credentials', 'strong_auth_required', 'confidentiality_required',
              'insufficient_access_rights', 'unwilling_to_perform', 'operations_error',
              'inappropriate_authentication', 'auth_method_not_supported'}
LDAP_PORTS = {389, 636, 3268, 3269}
GSS_KRB = (bytes.fromhex('2a864886f712010202'),        # 1.2.840.113554.1.2.2 (krb5)
           bytes.fromhex('2a864882f712010202'))        # 1.2.840.48018.1.2.2 (MS krb5)
NTLM_FLAG_SIGN, NTLM_FLAG_SEAL = 0x10, 0x20

CAP_ROWS = 50000          # per row list
CAP_SET = 2000            # per-key set (identities per source, sources per identity ...)
CAP_KEYS = 200000         # per counter / dict
drops = C.Counter()

# --------------------------------------------------------------------------- helpers
def is_private(ip):
    """Non-global = internal (RFC1918, ULA, loopback, link-local, CGNAT 100.64/10 ...)."""
    try:
        return not ipaddress.ip_address(ip).is_global
    except Exception:
        return True

def add(lst, item, name):
    if len(lst) < CAP_ROWS:
        lst.append(item)
    else:
        drops[name] += 1

def sadd(d, key, val, name):
    """Add val to the set d[key], capping both the key count and each set."""
    if key not in d and len(d) >= CAP_KEYS:
        drops[name] += 1; return
    s = d[key]
    if val in s or len(s) < CAP_SET:
        s.add(val)
    else:
        drops[name] += 1

def bump(counter, key, cap=CAP_KEYS, by=1):
    if key in counter or len(counter) < cap:
        counter[key] += by
    else:
        drops['counter'] += 1

def ntlm_auth(blob):
    """Parse NTLMSSP in a SASL blob. Returns identity fields only — never the responses."""
    i = blob.find(b'NTLMSSP\x00')
    if i < 0:
        return None
    m = blob[i:]
    try:
        t = struct.unpack('<I', m[8:12])[0]
        if t != 3:
            return {'type': t}
        def fld(o):
            ln, _, off = struct.unpack('<HHI', m[o:o + 8])
            return m[off:off + ln]
        nt_len = len(fld(20))
        u = lambda x: x.decode('utf-16le', 'replace')
        flags = struct.unpack('<I', m[60:64])[0]
        return {'type': 3, 'domain': u(fld(28)), 'user': u(fld(36)), 'ws': u(fld(44)),
                'ver': 'NTLMv1' if nt_len == 24 else ('anonymous' if nt_len == 0 else 'NTLMv2'),
                'sign': bool(flags & NTLM_FLAG_SIGN), 'seal': bool(flags & NTLM_FLAG_SEAL)}
    except Exception:
        return {'type': -1}

def sasl_kind(hexstr):
    try:
        b = bytes.fromhex(hexstr)
    except Exception:
        return 'unparsable', None
    if b'NTLMSSP\x00' in b:
        a = ntlm_auth(b)
        if a and a.get('type') == 3:
            return 'ntlm-auth', a
        return 'ntlm-type%s' % (a or {}).get('type'), None
    if any(o in b[:96] for o in GSS_KRB):
        return 'kerberos', None
    if b[:1] == b'\xa1':
        return 'spnego-continuation', None
    return 'other', None

_HEX = re.compile(r'\\x([0-9a-fA-F]{2})')
def unescape_suricata(s):
    """Suricata writes non-UTF-8 bytes as literal '\\xNN' text; undo that."""
    out = bytearray(); i = 0
    while i < len(s):
        if s[i] == '\\' and _HEX.match(s, i):
            out.append(int(s[i + 2:i + 4], 16)); i += 4
        else:
            c = ord(s[i]); out += bytes([c]) if c < 256 else s[i].encode(); i += 1
    return bytes(out)

def _dns_name(b, o, depth=0):
    labels = []
    while o < len(b):
        ln = b[o]
        if ln == 0:
            return '.'.join(labels), o + 1
        if ln & 0xc0 == 0xc0:
            if depth > 8:
                break
            rest, _ = _dns_name(b, ((ln & 0x3f) << 8) | b[o + 1], depth + 1)
            labels.append(rest)
            return '.'.join(x for x in labels if x), o + 2
        labels.append(b[o + 1:o + 1 + ln].decode('utf-8', 'replace')); o += 1 + ln
    return '.'.join(labels), o

def netlogon_response(raw):
    """MS-ADTS NETLOGON_SAM_LOGON_RESPONSE_EX (opcode 23) / USER_UNKNOWN_EX (25)."""
    b = unescape_suricata(raw)
    op = struct.unpack('<H', b[0:2])[0]
    r = {'opcode': op}
    if op in (23, 25):
        o = 24
        for k in ('forest', 'domain', 'dc_host', 'nb_domain', 'nb_dc', 'user',
                  'dc_site', 'client_site'):
            r[k], o = _dns_name(b, o)
    return r

def host_label(name):
    """'DC01$' / 'dc01.corp.local' / 'DC01' -> 'dc01'."""
    return (name or '').strip().rstrip('$').split('.')[0].lower()

# --------------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('eve', help='prefiltered JSONL (ldap + flow/anomaly/alert records)')
    ap.add_argument('--artifacts', required=True)
    ap.add_argument('--bytes', type=int, default=500_000,
                    help='bytes_toclient threshold for bulk-enumeration review')
    ap.add_argument('--spray', type=int, default=5,
                    help='distinct identities (or sources, or probed users) to call it spray/enum')
    ap.add_argument('--enum', type=int, default=1000,
                    help='entries returned to one source (cleartext) to call it enumeration')
    a = ap.parse_args()
    os.makedirs(a.artifacts, exist_ok=True)

    n = C.Counter(); ports = C.Counter(); servers = C.Counter(); clients = C.Counter()
    req_ops = C.Counter(); resp_ops = C.Counter(); rcodes = C.Counter()
    first = last = None
    bind_kind = C.Counter(); simple_named = C.Counter(); anon_bind = C.Counter()
    ntlm_ids = C.Counter(); ntlm_rows = []; ntlm_src_by_id = C.defaultdict(set)
    bind_fail = []; fail_by_src = C.defaultdict(set); fail_cnt_src = C.Counter()
    fail_src_by_id = C.defaultdict(set); first_fail = {}
    bind_ok = C.defaultdict(list)                  # src -> [(ts, ident, mech, fid)]
    bind_servers = C.defaultdict(lambda: [0, set(), C.Counter()])   # dst -> [binds, clients, mechs]
    anon_flows = set(); anon_search = []
    unauth = []; notable = []
    rootdse_fp = C.Counter(); rootdse_cli = C.defaultdict(set)
    sens_req = []; sens_resp = []; writes = []; ext_hits = []
    ctrl_hits = C.Counter(); ctrl_src = C.Counter(); ctrl_set_src = C.defaultdict(set)
    compares = []; jndi = []
    base_dns = C.Counter(); rootdse_domain = {}
    srch = C.defaultdict(lambda: [0, 0, 0, set()])  # src -> [searches, entries, root-subtree, bases]
    nl_inv = C.Counter(); nl_ip_by_host = C.defaultdict(set); nl_unknown = C.Counter()
    nl_known = C.Counter()
    host_ips = C.defaultdict(set)                   # host label -> IPs it was seen at
    dc_names = set(); dc_ips = set()
    cldap_ext = C.Counter()
    flows = []; flow_ext = []; unclass = C.Counter(); anomalies = C.Counter()
    anom_by_srv = C.Counter(); alerts = C.Counter(); alert_hosts = C.Counter()
    bulk = C.defaultdict(list)          # (src,dst) -> [flow.start, ...] for flows >= --bytes

    for line in open(a.eve, errors='replace'):
        try:
            e = json.loads(line)
        except Exception:
            n['bad_json'] += 1; continue
        et = e.get('event_type'); src, dst = e.get('src_ip') or '', e.get('dest_ip') or ''
        ts = e.get('timestamp', ''); fid = e.get('flow_id') or 0

        if et == 'flow':
            f = e.get('flow', {}); dp = e.get('dest_port') or 0; apn = e.get('app_proto')
            pr = e.get('proto') or ''
            if apn == 'ldap':
                n['flow_ldap'] += 1
                flows.append((f.get('bytes_toclient', 0), f.get('bytes_toserver', 0),
                              f.get('tx_cnt', 0), f.get('age', 0), pr,
                              src, dst, dp, fid, f.get('start', '')))
                if f.get('bytes_toclient', 0) >= a.bytes:
                    if (src, dst) in bulk or len(bulk) < CAP_KEYS:
                        if len(bulk[(src, dst)]) < 5000:
                            bulk[(src, dst)].append(f.get('start', ''))
                if len(flows) > 5000:
                    flows.sort(reverse=True); del flows[2000:]
                if not (is_private(src) and is_private(dst)):
                    add(flow_ext, (src, dst, pr, dp, f.get('pkts_toserver', 0),
                                   f.get('bytes_toserver', 0), f.get('pkts_toclient', 0),
                                   f.get('bytes_toclient', 0), f.get('start', '')), 'flow_ext')
            elif dp in LDAP_PORTS:
                scope = 'internal' if (is_private(src) and is_private(dst)) else 'EXTERNAL'
                bump(unclass, (pr, dp, apn or 'none', scope))
            continue
        if et == 'alert':
            if e.get('app_proto') == 'ldap' or e.get('dest_port') in LDAP_PORTS or e.get('src_port') in LDAP_PORTS:
                al = e.get('alert', {})
                bump(alerts, (al.get('signature_id'), al.get('signature')))
                bump(alert_hosts, (src, dst))
            continue
        if et == 'anomaly':
            an = e.get('anomaly', {})
            if an.get('app_proto') == 'ldap':
                anomalies[(an.get('layer'), an.get('event'))] += 1
                bump(anom_by_srv, (dst if e.get('dest_port') in LDAP_PORTS else src))
            continue
        if et != 'ldap':
            continue

        n['ldap'] += 1
        first = ts if first is None or ts < first else first
        last = ts if last is None or ts > last else last
        proto = e.get('proto')
        bump(ports, (proto, e.get('dest_port')))
        bump(servers, dst); bump(clients, src)
        l = e.get('ldap', {}); r = l.get('request') or {}; op = r.get('operation') or '(response-only)'
        req_ops[op] += 1
        resps = l.get('responses') or []
        res_codes = []
        n_entries = 0
        for x in resps:
            xo = x.get('operation')
            resp_ops[xo] += 1
            for k, v in x.items():
                if isinstance(v, dict) and 'result_code' in v:
                    rcodes[(xo, v['result_code'])] += 1
                    res_codes.append((xo, v['result_code'], v.get('message', '')))
            for c in x.get('controls') or []:
                ctrl_hits[('response', c.get('control_type'))] += 1
            if xo in ('extended_response', 'intermediate_response') and not r:
                # only when the request is missing — otherwise the request row already counts it
                nm = (x.get(xo) or {}).get('name', '')
                add(ext_hits, (ts, fid, src, dst, xo, nm, EXT_OPS.get(nm, '')), 'ext_hits')
            se = x.get('search_result_entry')
            if not se:
                continue
            n_entries += 1
            sbase = se.get('base_object', '')
            bump(base_dns, sbase)
            sattrs = se.get('attributes') or []
            stypes = {(at.get('type') or '').lower() for at in sattrs}
            if sbase == '' and stypes & {'dsservicename', 'domaincontrollerfunctionality',
                                          'isglobalcatalogready'}:
                dc_ips.add(dst)                             # rootDSE of an AD DC
            for at in sattrs:
                t = at.get('type', ''); tl = t.lower(); vals = at.get('values') or []
                if tl in SENSITIVE_ATTRS and tl not in WRITE_ONLY_INTEREST:
                    add(sens_resp, (ts, fid, src, dst, sbase, t, SENSITIVE_ATTRS[tl], len(vals)),
                        'sens_resp')
                if tl in JNDI_ATTRS or (tl == 'objectclass' and any(
                        str(v).lower() in JNDI_OBJCLASS for v in vals)):
                    srv_pub = not is_private(dst)
                    add(jndi, (ts, fid, src, dst, sbase, t,
                               ','.join(str(v) for v in vals)[:120] if tl != 'javaserializeddata'
                               else '<%d serialized value(s)>' % len(vals),
                               'PUBLIC server' if srv_pub else 'internal server'), 'jndi')
                if tl == 'defaultnamingcontext' and vals:
                    rootdse_domain[dst] = vals[0]
                if tl == 'dnshostname' and sbase == '' and vals and 'dsservicename' in stypes:
                    dc_names.add(host_label(vals[0])); sadd(host_ips, host_label(vals[0]), dst, 'host_ips')
                if tl == 'netlogon':
                    for v in vals:
                        try:
                            nl = netlogon_response(v)
                        except Exception:
                            n['netlogon_unparsed'] += 1; continue
                        if nl['opcode'] not in (23, 25):
                            continue
                        usr = nl.get('user', '')
                        if nl['opcode'] == 23:
                            bump(nl_inv, (dst, nl['domain'], nl['dc_host'], nl['nb_domain'],
                                          nl['dc_site']))
                            nl_ip_by_host[nl['dc_host'].lower()].add(dst)
                            dc_ips.add(dst)
                            for nm in (nl['dc_host'], nl.get('nb_dc', '')):
                                if nm:
                                    dc_names.add(host_label(nm)); sadd(host_ips, host_label(nm), dst, 'host_ips')
                            if usr:
                                bump(nl_known, (src, dst, nl.get('domain', ''), usr))
                        else:
                            bump(nl_unknown, (src, dst, nl.get('domain', ''), usr))
                        if usr.endswith('$'):
                            sadd(host_ips, host_label(usr), src, 'host_ips')   # the host pinging for itself
        for c in r.get('controls') or []:
            oid = c.get('control_type')
            ctrl_hits[('request', oid)] += 1
            bump(ctrl_src, (src, dst, oid))
            sadd(ctrl_set_src, src, oid, 'ctrl_set_src')
        if proto == 'UDP' and not (is_private(src) and is_private(dst)):
            bump(cldap_ext, (src, dst))

        # ---- bind
        br = r.get('bind_request')
        if br is not None:
            sasl = br.get('sasl'); info = None; mech = ''
            if sasl:
                kind, info = sasl_kind(sasl.get('credentials', ''))
                mech = 'sasl:%s:%s' % (sasl.get('mechanism'), kind)
                if info:
                    rc = next((c[1] for c in res_codes if c[0] == 'bind_response'), 'no-response')
                    key = (src, dst, info['domain'], info['user'], info['ws'], info['ver'],
                           'sign' if info['sign'] else 'NOSIGN', rc)
                    bump(ntlm_ids, key)
                    sadd(ntlm_src_by_id, (info['domain'].lower(), info['user'].lower()), src, 'ntlm_src')
                    add(ntlm_rows, (ts, fid) + key, 'ntlm_rows')
            elif br.get('name'):
                mech = 'simple:named (CLEARTEXT PASSWORD ON WIRE)'
                bump(simple_named, (src, dst, br['name']))
            else:
                mech = 'simple:anonymous'
                bump(anon_bind, (src, dst))
            bind_kind[mech] += 1
            if proto == 'TCP':
                bs = bind_servers[dst] if (dst in bind_servers or len(bind_servers) < CAP_KEYS) else None
                if bs is not None:
                    bs[0] += 1; bs[2][mech.split(' ')[0]] += 1
                    if len(bs[1]) < CAP_SET: bs[1].add(src)
            ident = br.get('name') or ''
            if info:
                ident = '%s\\%s@%s' % (info['domain'], info['user'], info['ws'])
            for (o, rc, msg) in res_codes:
                if o != 'bind_response' or rc == 'sasl_bind_in_progress':
                    continue
                if rc == 'success':
                    if mech == 'simple:anonymous':
                        if len(anon_flows) < CAP_KEYS: anon_flows.add(fid)
                    elif ident and len(bind_ok[src]) < 500 and (src in bind_ok or len(bind_ok) < CAP_KEYS):
                        bind_ok[src].append((ts, ident, mech, fid))
                    continue
                m = re.search(r'data ([0-9a-f]{3})', msg or '')
                sub = m.group(1) if m else ''
                add(bind_fail, (ts, fid, src, dst, ident, rc, sub, AD_DATA.get(sub, ''),
                                (msg or '')[:100]), 'bind_fail')
                sadd(fail_by_src, src, ident.lower(), 'fail_by_src')
                bump(fail_cnt_src, src)
                if ident:
                    sadd(fail_src_by_id, ident.split('@')[0].lower(), src, 'fail_src_by_id')
                if src not in first_fail or ts < first_fail[src]:
                    if src in first_fail or len(first_fail) < CAP_KEYS:
                        first_fail[src] = ts

        # ---- search
        sr = r.get('search_request')
        if sr is not None:
            attrs = sr.get('attributes') or []
            base = sr.get('base_object', '')
            if base == '' and proto == 'TCP':
                fp = (sr.get('time_limit'), sr.get('size_limit'),
                      (sr.get('filter') or {}).get('value', '<unlogged>'), len(attrs),
                      ','.join(attrs)[:60])
                bump(rootdse_fp, fp); sadd(rootdse_cli, fp, src, 'rootdse_cli')
            if base != '' and proto == 'TCP':
                s = srch[src] if (src in srch or len(srch) < CAP_KEYS) else None
                if s is not None:
                    s[0] += 1; s[1] += n_entries
                    if base.lower().startswith('dc=') and str(sr.get('scope', '')).lower() in (
                            'wholesubtree', '2', 'subtree'):
                        s[2] += 1
                    if len(s[3]) < CAP_SET: s[3].add(base.lower())
                if fid in anon_flows:
                    rc = ';'.join(c[1] for c in res_codes if c[0] == 'search_result_done') or 'no-done'
                    add(anon_search, (ts, fid, src, dst, base, sr.get('scope'),
                                      ','.join(attrs)[:80], n_entries, rc), 'anon_search')
            for at in attrs:
                tl = at.lower()
                if tl in SENSITIVE_ATTRS and tl not in WRITE_ONLY_INTEREST:
                    add(sens_req, (ts, fid, src, dst, base, at, SENSITIVE_ATTRS[tl], sr.get('scope')),
                        'sens_req')
                if at == '*' or at == '+':
                    add(sens_req, (ts, fid, src, dst, base, at, 'all-attributes', sr.get('scope')),
                        'sens_req')
        elif n_entries and src in srch:
            srch[src][1] += n_entries                     # entries on a response-only record

        # ---- compare (password oracle / attribute probing) — the asserted value is never kept
        cr = r.get('compare_request')
        if cr is not None:
            ava = cr.get('attribute_value_assertion') or {}
            at = ava.get('description', ''); tl = at.lower()
            cat = SENSITIVE_ATTRS.get(tl, '')
            rc = ';'.join(c[1] for c in res_codes) or 'no-response'
            add(compares, (ts, fid, src, dst, cr.get('entry', ''), at, cat, rc), 'compares')

        # ---- writes
        if op in WRITE_OPS:
            body = r.get(op, {})
            target = body.get('object') or body.get('entry') or body.get('dn') or ''
            low = target.lower()
            touched = []; hot = set()
            for ch in body.get('changes') or []:
                md = ch.get('modification') or {}
                atn = md.get('attribute_type', ''); atl = atn.lower()
                touched.append('%s:%s' % (ch.get('operation', '?'), atn))
                vals = [str(v) for v in md.get('attribute_values') or []]
                if atl == 'samaccountname' and vals and not any(v.endswith('$') for v in vals):
                    if any(host_label(v) in dc_names for v in vals):
                        hot.add('NOPAC: sAMAccountName set to a DC name without $')
                    else:
                        hot.add('noPac? sAMAccountName set without trailing $')
                if atl == 'ntsecuritydescriptor':
                    if low.startswith('dc='):
                        hot.add('DACL WRITE ON DOMAIN ROOT (DCSync-rights grant?)')
                    elif low.startswith('cn=adminsdholder,'):
                        hot.add('DACL WRITE ON AdminSDHolder (persistence)')
                    elif 'cn=policies,cn=system' in low:
                        hot.add('DACL write on GPO')
            add_attrs = {}
            for at in body.get('attributes') or []:
                nm = at.get('name', '')
                touched.append('add:%s' % nm)
                add_attrs[nm.lower()] = [str(v).lower() for v in at.get('values') or []]
            if op == 'mod_dn_request':
                touched.append('rename->%s %s' % (body.get('new_rdn', ''), body.get('new_superior', '')))
            for t in touched:
                if ':' in t:
                    k = t.split(':', 1)[1].lower()
                    if k in SENSITIVE_ATTRS:
                        hot.add(SENSITIVE_ATTRS[k])
            if op == 'add_request' and ('computer' in add_attrs.get('objectclass', []) or
                                        any(v.endswith('$') for v in add_attrs.get('samaccountname', [])) or
                                        low.startswith('cn=') and ',cn=computers,' in low):
                hot.add('machine-account-add')
            if PRIV_GROUP_RE.match(low):
                hot.add('PRIVILEGED-GROUP')
            if op == 'del_request':
                req_oids = {c.get('control_type') for c in r.get('controls') or []}
                hot.add('TREE-DELETE (recursive)' if TREEDEL in req_oids else 'delete')
            rc = ';'.join(c[1] for c in res_codes) or 'no-response'
            add(writes, (ts, fid, src, dst, op, target, '|'.join(touched)[:300],
                         ','.join(sorted(hot)), rc), 'writes')
        if op == 'extended_request':
            nm = (r.get('extended_request') or {}).get('name', '')   # value deliberately not kept
            add(ext_hits, (ts, fid, src, dst, op, nm, EXT_OPS.get(nm, '')), 'ext_hits')

        # ---- unauthenticated operation / notable result codes
        for (o, rc, msg) in res_codes:
            if '000004DC' in (msg or ''):
                add(unauth, (ts, fid, src, dst, op, (sr or {}).get('base_object', ''),
                             ','.join((sr or {}).get('attributes') or [])[:80]), 'unauth')
            elif rc in NOTABLE_RC and o != 'bind_response':
                add(notable, (ts, fid, src, dst, op, o, rc, (msg or '')[:100]), 'notable')

    # ======================================================================= report
    def W(path):
        fh = open(os.path.join(a.artifacts, path), 'w', newline='')
        opened.append(fh)
        return csv.writer(fh)
    opened = []
    def sec(t): print('\n=== %s ===' % t)
    def top(c, k=15, fmt=lambda k, v: '%8d  %s' % (v, k)):
        for kk, v in c.most_common(k): print(fmt(kk, v))
    def none(cond):
        if not cond: print('  none')

    sec('BASELINE')
    print('ldap events: %d   ldap flows: %d   window: %s -> %s' % (n['ldap'], n['flow_ldap'], first, last))
    top(ports); print('-- request operations'); top(req_ops)
    print('-- response operations'); top(resp_ops); print('-- result codes'); top(rcodes, 25)
    print('-- top servers'); top(servers, 10); print('-- top clients'); top(clients, 10)
    print('-- domain controllers known (CLDAP + AD rootDSE): %d IPs, names: %s' %
          (len(dc_ips), ', '.join(sorted(dc_names)[:20]) or '-'))
    if drops:
        print('-- WARNING: caps reached, rows dropped (view is truncated): %s' % dict(drops))

    sec('H1 BIND MECHANISMS'); top(bind_kind)
    sec('H2 CLEARTEXT SIMPLE BINDS (named)'); top(simple_named, 30); none(simple_named)
    sec('H3 ANONYMOUS BINDS'); top(anon_bind, 20); none(anon_bind)

    sec('H4 NTLM-OVER-LDAP IDENTITIES (identity fields only)')
    top(ntlm_ids, 40)
    if not ntlm_ids: print('  none — all SASL binds are Kerberos or no NTLM AUTHENTICATE seen')
    w = W('ntlm_binds.csv'); w.writerow(['timestamp', 'flow_id', 'src_ip', 'dest_ip', 'domain',
          'user', 'workstation', 'ntlm_version', 'signing', 'bind_result']); w.writerows(ntlm_rows)
    print('-- relay / misuse indicators')
    hit = False
    for (src, dst, dom, usr, ws, ver, sg, rc), v in ntlm_ids.items():
        why = []
        if ver != 'NTLMv2': why.append(ver)
        if sg == 'NOSIGN' and rc == 'success': why.append('unsigned successful bind (relayable)')
        if usr.endswith('$'):
            m = host_label(usr); known = host_ips.get(m, set()); is_dc = m in dc_names
            if known and src not in known:
                why.append('RELAY: machine acct %s bound from %s but %s is seen at %s%s' %
                           (usr, src, m, ','.join(sorted(known)[:4]),
                            ' [DC ACCOUNT — coerced DC auth relayed]' if is_dc else ''))
            elif not known and is_dc and src not in dc_ips:
                why.append('RELAY: DC machine acct %s bound from non-DC IP %s' % (usr, src))
            if ws and m != ws.lower():
                why.append('workstation field %s != account (tool-built message?)' % ws)
            if sg == 'NOSIGN':
                why.append('machine-account NTLM without SIGN (relay with --remove-mic?)')
        n_src = len(ntlm_src_by_id[(dom.lower(), usr.lower())])
        if n_src > 1:
            why.append('identity seen from %d src IPs' % n_src)
        if why:
            hit = True; print('  %s -> %s  %s\\%s @%s  x%d  :: %s' % (src, dst, dom, usr, ws, v, '; '.join(why)))
    none(hit)

    sec('H5 BIND FAILURES')
    w = W('bind_failures.csv'); w.writerow(['timestamp', 'flow_id', 'src_ip', 'dest_ip', 'identity',
          'result_code', 'ad_data', 'ad_meaning', 'message']); w.writerows(sorted(bind_fail))
    agg = C.Counter((b[2], b[3], b[4], b[5], b[6], b[7]) for b in bind_fail)
    top(agg, 30); none(bind_fail)
    print('-- spray / brute-force (distinct failing identities per source)')
    for s, ids in sorted(fail_by_src.items(), key=lambda x: -len(x[1])):
        tag = ('SPRAY' if len(ids) >= a.spray else
               'brute/stale' if fail_cnt_src[s] >= 5 else 'low')
        print('  %-40s distinct=%d attempts=%d  %s' % (s, len(ids), fail_cnt_src[s], tag))
    print('-- SUCCESS AFTER FAILURES from the same source (spray/brute that found a password)')
    w = W('success_after_failures.csv'); w.writerow(['timestamp', 'flow_id', 'src_ip', 'identity',
          'mechanism', 'first_failure', 'distinct_failed_identities', 'identity_failed_before'])
    hit = False
    for s, oks in bind_ok.items():
        ff = first_fail.get(s)
        if not ff:
            continue
        for (ts, ident, mech, fid) in sorted(oks):
            if ts <= ff:
                continue
            prior = ident.lower() in fail_by_src[s]
            w.writerow([ts, fid, s, ident, mech, ff, len(fail_by_src[s]), prior])
            tag = ('SPRAY->SUCCESS' if len(fail_by_src[s]) >= a.spray else
                   'BRUTE->SUCCESS' if prior else 'success after failures')
            hit = True
            print('  %s %s %s %s  (first failure %s, %d identities failed)  %s' %
                  (ts, s, ident, mech, ff, len(fail_by_src[s]), tag))
    none(hit)
    print('-- one identity failing from many sources (distributed brute force / password reuse test)')
    hit = False
    for ident, ss in sorted(fail_src_by_id.items(), key=lambda x: -len(x[1])):
        if len(ss) >= a.spray:
            hit = True; print('  %-50s sources=%d  %s' % (ident, len(ss), ','.join(sorted(ss)[:6])))
    none(hit)
    print('-- cadence (fixed-interval failures = scheduled task / stale creds)')
    by = C.defaultdict(list)
    for b in bind_fail: by[(b[2], b[4])].append(b[0])
    for k, tss in by.items():
        if len(tss) >= 3:
            mm = C.Counter(t[14:19] for t in tss).most_common(1)[0]
            print('  %s %s attempts=%d  most common mm:ss=%s (x%d)' % (k[0], k[1], len(tss), mm[0], mm[1]))

    sec('H6 UNAUTHENTICATED OPERATIONS (000004DC — bind required)')
    w = W('unauth_ops.csv'); w.writerow(['timestamp', 'flow_id', 'src_ip', 'dest_ip', 'operation',
          'base_object', 'attributes']); w.writerows(unauth)
    top(C.Counter((u[2], u[3], u[5], u[6]) for u in unauth), 20); none(unauth)
    sec('H6b SEARCHES ON ANONYMOUS-BOUND CONNECTIONS (DC allows anonymous reads?)')
    w = W('anon_searches.csv'); w.writerow(['timestamp', 'flow_id', 'src_ip', 'dest_ip', 'base_object',
          'scope', 'attributes', 'entries_returned', 'result']); w.writerows(anon_search)
    agg = C.Counter(); ent = C.Counter()
    for x in anon_search:
        agg[(x[2], x[3], x[4], x[8])] += 1; ent[(x[2], x[3], x[4], x[8])] += x[7]
    for k, v in agg.most_common(20):
        flag = '  <== ENTRIES RETURNED ANONYMOUSLY' if ent[k] else ''
        print('%8d  %s entries=%d%s' % (v, k, ent[k], flag))
    none(anon_search)

    sec('H7 SENSITIVE ATTRIBUTES — requested')
    w = W('sensitive_attrs.csv'); w.writerow(['direction', 'timestamp', 'flow_id', 'src_ip', 'dest_ip',
          'object', 'attribute', 'category', 'scope_or_nvalues'])
    w.writerows([('request',) + x for x in sens_req] + [('response',) + x for x in sens_resp])
    top(C.Counter((x[2], x[3], x[5], x[6]) for x in sens_req), 30); none(sens_req)
    print('-- per-source category combination (SharpHound-shaped = acl + kerberoast + rbcd/delegation)')
    cats = C.defaultdict(set)
    for x in sens_req: cats[x[2]].add(x[6])
    for s_, cs in sorted(cats.items(), key=lambda x: -len(x[1]))[:15]:
        bh = ('acl' in cs and 'kerberoast' in cs and ({'rbcd', 'delegation'} & cs))
        print('  %-40s %s%s' % (s_, ','.join(sorted(cs)),
                                '  <== BLOODHOUND-SHAPED' + (' (from a DC)' if s_ in dc_ips else '')
                                if bh else ''))
    sec('H7b SENSITIVE ATTRIBUTES — returned in cleartext (values never printed)')
    top(C.Counter((x[2], x[3], x[5], x[6]) for x in sens_resp), 30); none(sens_resp)

    sec('H8 DIRECTORY WRITES (modify/add/del/moddn)')
    w = W('ldap_writes.csv'); w.writerow(['timestamp', 'flow_id', 'src_ip', 'dest_ip', 'operation',
          'target_dn', 'changes', 'flags', 'result']); w.writerows(writes)
    for x in sorted(writes, key=lambda x: (not x[7], x[0]))[:40]:
        print('  %s %s->%s %s %s [%s] {%s} %s' % (x[0], x[2], x[3], x[4], x[5], x[6][:120], x[7], x[8]))
    none(writes)

    sec('H9 CONTROLS & EXTENDED OPERATIONS')
    for (d, oid), v in ctrl_hits.most_common(30):
        print('%8d  %-8s %s  %s' % (v, d, oid, CONTROLS.get(oid, '')))
    w = W('controls_by_source.csv'); w.writerow(['src_ip', 'dest_ip', 'control_oid', 'meaning',
          'requests', 'src_is_dc'])
    w.writerows([(s_, d_, o_, CONTROLS.get(o_, ''), v, s_ in dc_ips) for (s_, d_, o_), v in ctrl_src.most_common()])
    print('-- per source (request controls)')
    for (s_, d_, o_), v in ctrl_src.most_common(20):
        print('%8d  %s -> %s  %s  %s' % (v, s_, d_, o_, CONTROLS.get(o_, '')))
    print('-- flags')
    hit = False
    for s_, oids in ctrl_set_src.items():
        why = []
        if oids & DIRSYNC and s_ not in dc_ips:
            why.append('DIRSYNC from non-DC (secret replication — treat like DCSync; '
                       'allow-list Entra Connect / sync servers)')
        if PAGED in oids and SDFLAGS in oids:
            why.append('SD_FLAGS + paged results (security-descriptor bulk collection)')
        if TREEDEL in oids:
            why.append('TREE-DELETE control (recursive deletion)')
        if why:
            hit = True; print('  %-40s %s' % (s_, '; '.join(why)))
    none(hit)
    print('-- extended operations (request values are never printed: PasswordModify carries the new password)')
    top(C.Counter((x[2], x[3], x[4], x[5], x[6]) for x in ext_hits), 20)
    if not ctrl_hits and not ext_hits: print('  none')

    sec('H10 rootDSE / TOOL FINGERPRINTS (time_limit, size_limit, filter, n_attrs, attrs)')
    for fp, v in rootdse_fp.most_common(20):
        print('%8d  clients=%-4d %s' % (v, len(rootdse_cli[fp]), fp))
    print('-- rare fingerprints (<=3 clients) — non-Windows tooling candidates')
    for fp, v in rootdse_fp.items():
        if len(rootdse_cli[fp]) <= 3:
            print('  %s  clients=%s' % (fp, sorted(rootdse_cli[fp])[:5]))

    sec('H11 CLDAP NETLOGON — DC inventory, user probes, rogue LDAP servers')
    w = W('dc_inventory.csv'); w.writerow(['responder_ip', 'dns_domain', 'dc_host', 'netbios_domain',
          'dc_site', 'responses']); w.writerows([k + (v,) for k, v in nl_inv.most_common()])
    top(nl_inv, 20)
    print('-- one DC hostname answering from >1 IP (rogue DC / readdressing)')
    multi = {h: sorted(s) for h, s in nl_ip_by_host.items() if len(s) > 1}
    print('  ' + (json.dumps(multi) if multi else 'none'))
    print('-- USER_UNKNOWN_EX (opcode 25) — unknown users / broken machine accounts')
    top(nl_unknown, 20); none(nl_unknown)
    print('-- CLDAP user probes per source (opcode 23 with a user = VALID, 25 = unknown)')
    w = W('cldap_user_probes.csv'); w.writerow(['src_ip', 'dest_ip', 'domain', 'user', 'result', 'responses'])
    w.writerows([k + ('valid', v) for k, v in nl_known.items()] + [k + ('unknown', v) for k, v in nl_unknown.items()])
    valid = C.defaultdict(set); unknown = C.defaultdict(set)
    for (s_, d_, dom, usr) in nl_known: valid[s_].add(usr.lower())
    for (s_, d_, dom, usr) in nl_unknown: unknown[s_].add(usr.lower())
    hit = False
    for s_ in set(valid) | set(unknown):
        own = {u for u in valid[s_] | unknown[s_] if u.endswith('$') and s_ in host_ips.get(host_label(u), ())}
        probed = (valid[s_] | unknown[s_]) - own
        if len(probed) >= a.spray:
            hit = True
            vv = sorted(valid[s_] - own)
            print('  ENUMERATION: %s probed %d users — %d VALID %s, %d unknown' %
                  (s_, len(probed), len(vv), vv[:10], len(unknown[s_] - own)))
    none(hit)
    print('-- hosts receiving TCP LDAP binds that are NOT known DCs (rogue LDAP / credential capture)')
    w = W('ldap_bind_servers.csv'); w.writerow(['server_ip', 'binds', 'distinct_clients', 'mechanisms',
          'known_dc', 'public'])
    hit = False
    for d_, (cnt, cl, mechs) in sorted(bind_servers.items(), key=lambda x: -x[1][0]):
        w.writerow([d_, cnt, len(cl), ';'.join('%s=%d' % kv for kv in mechs.most_common()),
                    d_ in dc_ips, not is_private(d_)])
        if dc_ips and d_ not in dc_ips:
            hit = True
            print('  %-40s binds=%d clients=%d %s%s' % (d_, cnt, len(cl), dict(mechs),
                  '  <== PUBLIC' if not is_private(d_) else ''))
    if not dc_ips: print('  (no DC inventory in this log — cannot separate DCs from other LDAP servers)')
    elif not hit: print('  none')

    sec('H12 EXTERNAL / INTERNET LDAP & CLDAP (flow-anchored)')
    w = W('external_ldap_flows.csv'); w.writerow(['src_ip', 'dest_ip', 'proto', 'dest_port',
          'pkts_toserver', 'bytes_toserver', 'pkts_toclient', 'bytes_toclient', 'start']); w.writerows(flow_ext)
    cat = C.Counter(); answered = C.Counter(); amp = C.defaultdict(lambda: [0, 0, 0, set()])
    for (s, d, pr, dp, pts, bts, ptc, btc, st) in flow_ext:
        k = ('inbound-from-internet' if not is_private(s) and is_private(d) else
             'outbound-to-internet' if is_private(s) else 'internet-to-internet')
        cat[(k, pr, dp)] += 1
        if ptc: answered[(k, pr, dp)] += 1
        q = amp[d]; q[0] += bts; q[1] += btc; q[2] += 1
        if len(q[3]) < CAP_SET: q[3].add(s)
    for k, v in cat.most_common(15):
        tag = '  <== INBOUND ANSWERED: directory exposed to the internet' if k[0] == 'inbound-from-internet' and answered[k] else ''
        print('%8d  %s answered=%d%s' % (v, k, answered[k], tag))
    for d, (bts, btc, cnt, ss) in sorted(amp.items(), key=lambda x: -x[1][2])[:15]:
        r_ = (btc / bts) if bts else 0
        print('  dst %-40s flows=%-5d sources=%-4d bytes_out=%d bytes_back=%d amp=%.2fx%s' %
              (d, cnt, len(ss), bts, btc, r_, '  <== OPEN REFLECTOR (amp>10x)' if r_ > 10 else ''))
    none(flow_ext)
    if cldap_ext: print('-- of which logged as event_type:ldap:'); top(cldap_ext, 10)

    sec('H13 VOLUME — largest LDAP flows (bulk enumeration even when sealed)')
    flows.sort(reverse=True)
    w = W('top_ldap_flows.csv'); w.writerow(['bytes_toclient', 'bytes_toserver', 'tx_cnt', 'age',
          'proto', 'src_ip', 'dest_ip', 'dest_port', 'flow_id', 'start']); w.writerows(flows[:200])
    for f in flows[:15]:
        print('  %10d B<- %8d B-> tx=%-4s age=%-5s %s %s -> %s:%s flow_id=%s%s%s' %
              (f[0], f[1], f[2], f[3], f[4], f[5], f[6], f[7], f[8],
               '  <== REVIEW' if f[0] >= a.bytes else '',
               ' (src is a DC)' if f[0] >= a.bytes and f[5] in dc_ips else ''))
    print('-- repeated bulk pulls per src->dst (flows >= %d B to client) and median gap' % a.bytes)
    def _t(x):
        try: return datetime.strptime(x[:19], '%Y-%m-%dT%H:%M:%S')
        except Exception: return None
    for (s_, d_), starts in sorted(bulk.items(), key=lambda x: -len(x[1]))[:15]:
        tt = sorted(t for t in map(_t, starts) if t)
        gaps = sorted((b - a_).total_seconds() / 60 for a_, b in zip(tt, tt[1:]) if (b - a_).total_seconds() < 6 * 3600)
        med = '%.0f min' % gaps[len(gaps) // 2] if gaps else '-'
        hint = ('  (90-120 min = GPO background refresh)' if gaps and 85 <= gaps[len(gaps) // 2] <= 125 else
                '  <== ONE-OFF PULL' if len(starts) == 1 else '')
        print('  %s -> %s  flows=%d  median_gap=%s%s' % (s_, d_, len(starts), med, hint))
    none(bulk)

    sec('H14 PARSER ANOMALIES & UNCLASSIFIED LDAP-PORT FLOWS (visibility gaps)')
    top(anomalies); print('-- servers with most ldap anomalies'); top(anom_by_srv, 8)
    print('-- LDAP-port flows NOT classified ldap (LDAPS / StartTLS / midstream)'); top(unclass)

    sec('H15 COMPARE OPERATIONS (password oracle / attribute probing — values never kept)')
    w = W('compare_ops.csv'); w.writerow(['timestamp', 'flow_id', 'src_ip', 'dest_ip', 'entry',
          'attribute', 'category', 'result']); w.writerows(compares)
    agg = C.Counter((x[2], x[3], x[5], x[6], x[7]) for x in compares)
    top(agg, 20)
    pw = C.Counter(x[2] for x in compares if x[6].startswith('secret:'))
    for s_, v in pw.most_common(10):
        print('  PASSWORD COMPARE: %s sent %d compare(s) against secret attributes%s' %
              (s_, v, ' — BRUTE FORCE' if v >= a.spray else ''))
    none(compares)

    sec('H16 JNDI / LOG4SHELL REFERENCES IN LDAP RESPONSES')
    w = W('jndi_responses.csv'); w.writerow(['timestamp', 'flow_id', 'client_ip', 'server_ip',
          'object', 'attribute', 'value_excerpt', 'server']); w.writerows(jndi)
    for x in jndi[:30]:
        print('  %s %s <- %s  %s  %s=%s  [%s]' % (x[0], x[2], x[3], x[4], x[5], x[6], x[7]))
    none(jndi)

    sec('H17 CLEARTEXT SEARCH VOLUME PER SOURCE (non-rootDSE TCP searches)')
    w = W('search_volume.csv'); w.writerow(['src_ip', 'searches', 'entries_returned',
          'domain_root_subtree_searches', 'distinct_bases', 'src_is_dc'])
    rows = sorted(srch.items(), key=lambda x: (-x[1][1], -x[1][0]))
    w.writerows([(s_, v[0], v[1], v[2], len(v[3]), s_ in dc_ips) for s_, v in rows])
    for s_, v in rows[:15]:
        flag = ''
        if v[1] >= a.enum or v[0] >= max(200, a.enum // 5):
            flag = '  <== ENUMERATION' + (' (src is a DC)' if s_ in dc_ips else '')
        print('  %-40s searches=%d entries=%d root_subtree=%d bases=%d%s' %
              (s_, v[0], v[1], v[2], len(v[3]), flag))
    none(srch)

    sec('SURICATA ALERTS ON LDAP TRAFFIC (detection-gap check)')
    top(alerts, 20)
    if not alerts: print('  none — every finding above is behavioural; no signature fired')
    else: print('-- alerted host pairs'); top(alert_hosts, 10)

    sec('OTHER NOTABLE RESULT CODES')
    top(C.Counter((x[2], x[3], x[4], x[6], x[7][:60]) for x in notable), 20); none(notable)
    for fh in opened:
        fh.close()
    if drops:
        print('\n[WARNING: caps reached, some rows dropped: %s]' % dict(drops))
    print('\n[artifacts written to %s]' % a.artifacts)

if __name__ == '__main__':
    main()
