# redact.jq — make an EVE record safe to quote in a hunt-ldap report.
#
#   grep ... "$eve" | jq -c -f "$skill_dir/scripts/redact.jq"
#
# Removes credential material and secret attribute VALUES while keeping every other
# field verbatim. Each rewrite is guarded with `if … then … else . end` so that a
# record without that path is passed through untouched (a bare `|=` would CREATE the
# path with null and the excerpt would no longer be verbatim).
#
# Keep SECRET in step with SECRET_ATTRS in ldap_hunt.py — tests/test_ldap_hunt.py checks it.

def SECRET: [
  "dbcspwd", "lmpwdhistory", "ms-ds-managedpassword", "ms-mcs-admpwd",
  "ms-mcs-admpwdexpirationtime", "msds-groupmsamembership", "msds-managedpassword",
  "msfve-recoverypassword", "mslaps-encrypteddsrmpassword",
  "mslaps-encrypteddsrmpasswordhistory", "mslaps-encryptedpassword",
  "mslaps-encryptedpasswordhistory", "mslaps-password", "mssfu30password",
  "mstpm-ownerinformation", "ntpwdhistory", "supplementalcredentials",
  "trustauthincoming", "trustauthoutgoing", "unicodepwd", "unixuserpassword",
  "userpassword"
];
def is_secret: (. // "" | ascii_downcase) as $a | SECRET | index([$a]) != null;
def red: "…[redacted — secret value]";

# SASL bind token: NetNTLM challenge-response or Kerberos AP-REQ
  (if .ldap.request.bind_request.sasl.credentials? then
     .ldap.request.bind_request.sasl.credentials |= (.[0:32] + "…[truncated — credential material]")
   else . end)
# server SASL creds (NTLM CHALLENGE / AP-REP)
| (if .ldap.responses? then
     .ldap.responses |= map(if .bind_response.server_sasl_creds? then
                              .bind_response.server_sasl_creds |= (.[0:32] + "…[truncated — credential material]")
                            else . end)
   else . end)
# extended request value — PasswordModify carries the new (and old) password in BER
| (if .ldap.request.extended_request.value? then .ldap.request.extended_request.value = red else . end)
# compare assertion against a secret attribute = a password guess
| (if (.ldap.request.compare_request.attribute_value_assertion.description? | is_secret)
      and .ldap.request.compare_request.attribute_value_assertion.value? then
     .ldap.request.compare_request.attribute_value_assertion.value = red
   else . end)
# modify / add of a secret attribute (password set, machine account add with unicodePwd)
| (if .ldap.request.modify_request.changes? then
     .ldap.request.modify_request.changes |= map(
       if (.modification.attribute_type? | is_secret) and .modification.attribute_values? then
         .modification.attribute_values |= map(red) else . end)
   else . end)
| (if .ldap.request.add_request.attributes? then
     .ldap.request.add_request.attributes |= map(
       if (.name? | is_secret) and .values? then .values |= map(red) else . end)
   else . end)
# secret attribute returned in a search entry (LAPS, gMSA, BitLocker ...)
| (if .ldap.responses? then
     .ldap.responses |= map(
       if .search_result_entry.attributes? then
         .search_result_entry.attributes |= map(
           if (.type? | is_secret) and .values? then .values |= map(red) else . end)
       else . end)
   else . end)
