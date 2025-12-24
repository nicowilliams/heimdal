#!/usr/bin/env python3
"""
Generate fuzz corpus for kadmind RPC testing.

Message format:
  4-byte big-endian length prefix
  N bytes of message data

The message data starts with a 4-byte command number (kadm_ops enum).
"""

import struct
import os

# kadm_ops enum values
KADM_GET = 0
KADM_DELETE = 1
KADM_CREATE = 2
KADM_RENAME = 3
KADM_CHPASS = 4
KADM_MODIFY = 5
KADM_RANDKEY = 6
KADM_GET_PRIVS = 7
KADM_GET_PRINCS = 8
KADM_CHPASS_WITH_KEY = 9
KADM_NOP = 10
KADM_PRUNE = 11

# KADM5 mask bits (from admin.h)
KADM5_PRINCIPAL = 0x000001
KADM5_PRINC_EXPIRE_TIME = 0x000002
KADM5_PW_EXPIRATION = 0x000004
KADM5_LAST_PWD_CHANGE = 0x000008
KADM5_ATTRIBUTES = 0x000010
KADM5_MAX_LIFE = 0x000020
KADM5_MOD_TIME = 0x000040
KADM5_MOD_NAME = 0x000080
KADM5_KVNO = 0x000100
KADM5_MKVNO = 0x000200
KADM5_AUX_ATTRIBUTES = 0x000400
KADM5_POLICY = 0x000800
KADM5_POLICY_CLR = 0x001000
KADM5_MAX_RLIFE = 0x002000
KADM5_LAST_SUCCESS = 0x004000
KADM5_LAST_FAILED = 0x008000
KADM5_FAIL_AUTH_COUNT = 0x010000
KADM5_KEY_DATA = 0x020000
KADM5_TL_DATA = 0x040000


def pack_int32(val):
    """Pack a 32-bit big-endian integer."""
    return struct.pack('>i', val)


def pack_uint32(val):
    """Pack a 32-bit big-endian unsigned integer."""
    return struct.pack('>I', val)


def pack_string(s):
    """Pack a string (4-byte length + data + null terminator)."""
    # Heimdal krb5_store_string includes null terminator in length
    data = s.encode('utf-8') + b'\x00'
    return pack_uint32(len(data)) + data


def pack_data(d):
    """Pack binary data (4-byte length + data)."""
    return pack_uint32(len(d)) + d


def pack_principal(name, realm="FUZZ.REALM"):
    """
    Pack a Kerberos principal.
    Format: name_type (4), num_components (4), realm (string),
            components (string each)
    """
    parts = name.split('/')
    # KRB5_NT_PRINCIPAL = 1
    result = pack_int32(1)  # name_type
    result += pack_int32(len(parts))  # num_components
    result += pack_string(realm)  # realm
    for part in parts:
        result += pack_string(part)
    return result


def pack_principal_ent(principal_name, mask, realm="FUZZ.REALM"):
    """
    Pack a kadm5_principal_ent structure.
    Only includes fields indicated by mask.
    """
    result = pack_int32(mask)  # mask comes first

    if mask & KADM5_PRINCIPAL:
        result += pack_principal(principal_name, realm)
    if mask & KADM5_PRINC_EXPIRE_TIME:
        result += pack_int32(0)  # princ_expire_time
    if mask & KADM5_PW_EXPIRATION:
        result += pack_int32(0)  # pw_expiration
    if mask & KADM5_LAST_PWD_CHANGE:
        result += pack_int32(0)  # last_pwd_change
    if mask & KADM5_MAX_LIFE:
        result += pack_int32(86400)  # max_life = 1 day
    if mask & KADM5_MOD_NAME:
        result += pack_int32(0)  # mod_name is NULL
    if mask & KADM5_MOD_TIME:
        result += pack_int32(0)  # mod_date
    if mask & KADM5_ATTRIBUTES:
        result += pack_int32(0)  # attributes
    if mask & KADM5_KVNO:
        result += pack_int32(1)  # kvno
    if mask & KADM5_MKVNO:
        result += pack_int32(1)  # mkvno
    if mask & KADM5_POLICY:
        result += pack_int32(0)  # policy is NULL
    if mask & KADM5_AUX_ATTRIBUTES:
        result += pack_int32(0)  # aux_attributes
    if mask & KADM5_MAX_RLIFE:
        result += pack_int32(604800)  # max_renewable_life = 1 week
    if mask & KADM5_LAST_SUCCESS:
        result += pack_int32(0)
    if mask & KADM5_LAST_FAILED:
        result += pack_int32(0)
    if mask & KADM5_FAIL_AUTH_COUNT:
        result += pack_int32(0)
    if mask & KADM5_KEY_DATA:
        result += pack_int32(0)  # n_key_data = 0
    if mask & KADM5_TL_DATA:
        result += pack_int32(0)  # n_tl_data = 0

    return result


def wrap_message(data):
    """Wrap message data with 4-byte length prefix."""
    return pack_uint32(len(data)) + data


def write_corpus(filename, data):
    """Write a corpus file."""
    path = os.path.join(os.path.dirname(__file__), filename)
    with open(path, 'wb') as f:
        f.write(wrap_message(data))
    print(f"Created {filename} ({len(data)} bytes payload)")


# Generate corpus files

# 1. NOP with reply wanted
write_corpus("nop_reply.bin",
    pack_int32(KADM_NOP) + pack_int32(1))

# 2. NOP without reply (interrupt request)
write_corpus("nop_noreply.bin",
    pack_int32(KADM_NOP) + pack_int32(0))

# 3. GET principal
write_corpus("get_principal.bin",
    pack_int32(KADM_GET) +
    pack_principal("test/user") +
    pack_int32(KADM5_PRINCIPAL | KADM5_KVNO | KADM5_ATTRIBUTES))

# 4. GET principal with all fields
write_corpus("get_principal_all.bin",
    pack_int32(KADM_GET) +
    pack_principal("test/user") +
    pack_int32(0x7FFFF))  # All mask bits

# 5. DELETE principal
write_corpus("delete_principal.bin",
    pack_int32(KADM_DELETE) +
    pack_principal("test/delete"))

# 6. CREATE principal (minimal)
mask = KADM5_PRINCIPAL | KADM5_MAX_LIFE | KADM5_MAX_RLIFE
write_corpus("create_principal.bin",
    pack_int32(KADM_CREATE) +
    pack_principal_ent("test/new", mask) +
    pack_int32(mask) +
    pack_string("password123"))

# 7. CREATE principal with attributes
mask = KADM5_PRINCIPAL | KADM5_ATTRIBUTES | KADM5_MAX_LIFE | KADM5_MAX_RLIFE
write_corpus("create_principal_attrs.bin",
    pack_int32(KADM_CREATE) +
    pack_principal_ent("test/attrs", mask) +
    pack_int32(mask) +
    pack_string("password456"))

# 8. MODIFY principal
mask = KADM5_PRINCIPAL | KADM5_ATTRIBUTES
write_corpus("modify_principal.bin",
    pack_int32(KADM_MODIFY) +
    pack_principal_ent("test/modify", mask) +
    pack_int32(mask))

# 9. RENAME principal
write_corpus("rename_principal.bin",
    pack_int32(KADM_RENAME) +
    pack_principal("test/old") +
    pack_principal("test/new"))

# 10. CHPASS principal
write_corpus("chpass_principal.bin",
    pack_int32(KADM_CHPASS) +
    pack_principal("test/chpass") +
    pack_string("newpassword") +
    pack_int32(0))  # keepold = false

# 11. CHPASS principal with keepold
write_corpus("chpass_principal_keepold.bin",
    pack_int32(KADM_CHPASS) +
    pack_principal("test/chpass") +
    pack_string("newpassword") +
    pack_int32(1))  # keepold = true

# 12. RANDKEY principal (simple)
write_corpus("randkey_principal.bin",
    pack_int32(KADM_RANDKEY) +
    pack_principal("test/randkey"))

# 13. RANDKEY principal with keepold and ks_tuples
write_corpus("randkey_principal_full.bin",
    pack_int32(KADM_RANDKEY) +
    pack_principal("test/randkey") +
    pack_int32(1) +  # keepold
    pack_int32(2) +  # n_ks_tuple
    pack_int32(17) + pack_int32(0) +  # aes128-cts-hmac-sha1-96, normal salt
    pack_int32(18) + pack_int32(0))   # aes256-cts-hmac-sha1-96, normal salt

# 14. GET_PRIVS
write_corpus("get_privs.bin",
    pack_int32(KADM_GET_PRIVS))

# 15. GET_PRINCS (list principals) - old style
write_corpus("get_princs_all.bin",
    pack_int32(KADM_GET_PRINCS) +
    pack_int32(0))  # no expression

# 16. GET_PRINCS with expression
write_corpus("get_princs_expr.bin",
    pack_int32(KADM_GET_PRINCS) +
    pack_int32(1) +  # has expression
    pack_string("test/*"))

# 17. GET_PRINCS online iteration
write_corpus("get_princs_iter.bin",
    pack_int32(KADM_GET_PRINCS) +
    pack_int32(0x55555555) +  # want online iteration
    pack_string("*"))

# 18. PRUNE principal
write_corpus("prune_principal.bin",
    pack_int32(KADM_PRUNE) +
    pack_principal("test/prune") +
    pack_int32(2))  # kvno to keep

# 19. PRUNE principal (no kvno - keep all)
write_corpus("prune_principal_all.bin",
    pack_int32(KADM_PRUNE) +
    pack_principal("test/prune"))

# 20. CHPASS_WITH_KEY
# key_data format: ver (4), kvno (4), type[0] (4), data[0] (len+data), type[1] (4), data[1] (len+data)
key_data = (
    pack_int32(2) +  # key_data_ver
    pack_int32(1) +  # key_data_kvno
    pack_int32(17) +  # key_data_type[0] = aes128
    pack_data(b'\x00' * 16) +  # key contents (16 bytes for aes128)
    pack_int32(0) +  # key_data_type[1] = no salt
    pack_data(b'')   # empty salt
)
write_corpus("chpass_with_key.bin",
    pack_int32(KADM_CHPASS_WITH_KEY) +
    pack_principal("test/keychange") +
    pack_int32(1) +  # n_key_data
    pack_int32(0) +  # keepold
    key_data)

# 21. Invalid command
write_corpus("invalid_cmd.bin",
    pack_int32(99))  # invalid command

# 22. Truncated message (just command, no data)
write_corpus("truncated_get.bin",
    pack_int32(KADM_GET))

# 23. Malformed principal (bad component count)
write_corpus("malformed_principal.bin",
    pack_int32(KADM_GET) +
    pack_int32(1) +  # name_type
    pack_int32(-1) +  # invalid num_components
    pack_string("FUZZ.REALM"))

# 24. Very long principal name
write_corpus("long_principal.bin",
    pack_int32(KADM_GET) +
    pack_principal("A" * 1000))

# 25. Principal with many components
write_corpus("many_components.bin",
    pack_int32(KADM_GET) +
    pack_principal("/".join(["c"] * 50)))

# 26. Empty password create
mask = KADM5_PRINCIPAL
write_corpus("create_empty_password.bin",
    pack_int32(KADM_CREATE) +
    pack_principal_ent("test/empty", mask) +
    pack_int32(mask) +
    pack_string(""))

# 27. Create with TL_DATA
mask = KADM5_PRINCIPAL | KADM5_TL_DATA
# Build principal_ent manually to include TL_DATA
tl_data = (
    pack_int32(1) +  # tl_data_type
    pack_data(b'test tl data')
)
princ_with_tl = (
    pack_int32(mask) +
    pack_principal("test/tldata") +
    pack_int32(1) +  # n_tl_data
    tl_data
)
write_corpus("create_with_tldata.bin",
    pack_int32(KADM_CREATE) +
    princ_with_tl +
    pack_int32(mask) +
    pack_string("password"))

# 28. Large n_key_data value (potential integer overflow)
write_corpus("large_nkeydata.bin",
    pack_int32(KADM_CHPASS_WITH_KEY) +
    pack_principal("test/overflow") +
    pack_int32(0x7FFFFFFF) +  # huge n_key_data
    pack_int32(0))

# 29. Negative n_key_data
write_corpus("negative_nkeydata.bin",
    pack_int32(KADM_CHPASS_WITH_KEY) +
    pack_principal("test/negative") +
    pack_int32(-1) +  # negative n_key_data
    pack_int32(0))

# 30. Zero-length message (just length prefix of 0)
with open(os.path.join(os.path.dirname(__file__), "empty_message.bin"), 'wb') as f:
    f.write(pack_uint32(0))
print("Created empty_message.bin (0 bytes payload)")

print("\nCorpus generation complete!")
