#!/usr/bin/env python3

import sys

UAC_FLAGS = {
    0x00000001: {
        "name": "SCRIPT",
        "description": "Logon script is executed",
        "security": False,
    },
    0x00000002: {
        "name": "ACCOUNTDISABLE",
        "description": "Account is disabled",
        "security": True,
    },
    0x00000008: {
        "name": "HOMEDIR_REQUIRED",
        "description": "Home directory is required",
        "security": False,
    },
    0x00000010: {
        "name": "LOCKOUT",
        "description": "Account is locked out",
        "security": True,
    },
    0x00000020: {
        "name": "PASSWD_NOTREQD",
        "description": "Password is not required",
        "security": True,
    },
    0x00000040: {
        "name": "PASSWD_CANT_CHANGE",
        "description": "User cannot change password",
        "security": False,
    },
    0x00000080: {
        "name": "ENCRYPTED_TEXT_PASSWORD_ALLOWED",
        "description": "Reversible password encryption is allowed",
        "security": True,
    },
    0x00000100: {
        "name": "TEMP_DUPLICATE_ACCOUNT",
        "description": "Temporary duplicate account",
        "security": False,
    },
    0x00000200: {
        "name": "NORMAL_ACCOUNT",
        "description": "Normal user account",
        "security": False,
    },
    0x00000800: {
        "name": "INTERDOMAIN_TRUST_ACCOUNT",
        "description": "Inter-domain trust account",
        "security": False,
    },
    0x00001000: {
        "name": "WORKSTATION_TRUST_ACCOUNT",
        "description": "Computer/workstation trust account",
        "security": False,
    },
    0x00002000: {
        "name": "SERVER_TRUST_ACCOUNT",
        "description": "Domain controller trust account",
        "security": False,
    },
    0x00010000: {
        "name": "DONT_EXPIRE_PASSWORD",
        "description": "Password never expires",
        "security": True,
    },
    0x00020000: {
        "name": "MNS_LOGON_ACCOUNT",
        "description": "MNS logon account",
        "security": False,
    },
    0x00040000: {
        "name": "SMARTCARD_REQUIRED",
        "description": "Smart card is required for logon",
        "security": False,
    },
    0x00080000: {
        "name": "TRUSTED_FOR_DELEGATION",
        "description": "Account is trusted for unconstrained delegation",
        "security": True,
    },
    0x00100000: {
        "name": "NOT_DELEGATED",
        "description": "Account cannot be delegated",
        "security": False,
    },
    0x00200000: {
        "name": "USE_DES_KEY_ONLY",
        "description": "Restrict Kerberos to DES encryption",
        "security": True,
    },
    0x00400000: {
        "name": "DONT_REQUIRE_PREAUTH",
        "description": "Kerberos pre-authentication is not required",
        "security": True,
    },
    0x00800000: {
        "name": "PASSWORD_EXPIRED",
        "description": "Password has expired",
        "security": False,
    },
    0x01000000: {
        "name": "TRUSTED_TO_AUTH_FOR_DELEGATION",
        "description": "Trusted for constrained delegation with protocol transition",
        "security": True,
    },
    0x04000000: {
        "name": "PARTIAL_SECRETS_ACCOUNT",
        "description": "Read-only domain controller account",
        "security": False,
    },
}


def separator(char="-", length=100):
    print(char * length)


def account_type(uac):
    types = []

    if uac & 0x00000200:
        types.append("Normal user account")

    if uac & 0x00001000:
        types.append("Workstation / Computer account")

    if uac & 0x00002000:
        types.append("Domain Controller account")

    if uac & 0x00000800:
        types.append("Inter-domain trust account")

    if uac & 0x00000100:
        types.append("Temporary duplicate account")

    if not types:
        return "Unknown / special account"

    return ", ".join(types)


def print_summary(uac):
    print()
    separator("=")
    print("USERACCOUNTCONTROL DECODER")
    separator("=")

    print(f"Decimal : {uac}")
    print(f"Hex     : 0x{uac:08X}")
    print(f"Binary  : {uac:032b}")

    print()

    if uac & 0x00000002:
        print("Account status : DISABLED")
    else:
        print("Account status : ENABLED")

    print(f"Account type   : {account_type(uac)}")


def print_active_flags(uac):
    print()
    separator("=")
    print("ACTIVE FLAGS")
    separator("=")

    found = False

    for value, flag in UAC_FLAGS.items():
        if uac & value:
            found = True

            marker = "[!]" if flag["security"] else "[+]"

            print(
                f"{marker} "
                f"{flag['name']:<35} "
                f"0x{value:08X} "
                f"({value:<8}) "
                f"{flag['description']}"
            )

    if not found:
        print("No known UAC flags detected.")


def print_inactive_flags(uac):
    print()
    separator("=")
    print("INACTIVE FLAGS")
    separator("=")

    for value, flag in UAC_FLAGS.items():
        if not uac & value:
            print(
                f"[-] "
                f"{flag['name']:<35} "
                f"0x{value:08X} "
                f"({value:<8}) "
                f"{flag['description']}"
            )


def print_security_findings(uac):
    print()
    separator("=")
    print("SECURITY INTERESTING FLAGS")
    separator("=")

    findings = []

    for value, flag in UAC_FLAGS.items():
        if uac & value and flag["security"]:
            findings.append((value, flag))

    if not findings:
        print("[+] No security-interesting UAC flags detected.")
        return

    for value, flag in findings:
        print(f"[!] {flag['name']}")
        print(f"    Value       : {value}")
        print(f"    Hex         : 0x{value:08X}")
        print(f"    Description : {flag['description']}")

        if flag["name"] == "ACCOUNTDISABLE":
            print("    Meaning     : The account cannot currently authenticate normally.")

        elif flag["name"] == "PASSWD_NOTREQD":
            print("    Meaning     : AD does not require a password for this account.")
            print("    Pentest     : Review password configuration and account exposure.")

        elif flag["name"] == "ENCRYPTED_TEXT_PASSWORD_ALLOWED":
            print("    Meaning     : Reversible password encryption is permitted.")
            print("    Pentest     : Potential credential exposure risk.")

        elif flag["name"] == "DONT_EXPIRE_PASSWORD":
            print("    Meaning     : The password does not expire.")
            print("    Pentest     : Interesting especially for service or stale accounts.")

        elif flag["name"] == "TRUSTED_FOR_DELEGATION":
            print("    Meaning     : Unconstrained delegation is enabled.")
            print("    Pentest     : High-value delegation configuration to investigate.")

        elif flag["name"] == "USE_DES_KEY_ONLY":
            print("    Meaning     : Kerberos DES-only encryption is configured.")
            print("    Pentest     : Legacy and weak cryptographic configuration.")

        elif flag["name"] == "DONT_REQUIRE_PREAUTH":
            print("    Meaning     : Kerberos pre-authentication is disabled.")
            print("    Pentest     : Account may be AS-REP roastable.")

        elif flag["name"] == "TRUSTED_TO_AUTH_FOR_DELEGATION":
            print("    Meaning     : Protocol transition / constrained delegation flag.")
            print("    Pentest     : Investigate the account's delegation configuration.")

        print()


def print_all_flags(uac):
    print()
    separator("=")
    print("ALL UAC FLAGS")
    separator("=")

    print(
        f"{'STATUS':<10}"
        f"{'FLAG':<37}"
        f"{'DECIMAL':<12}"
        f"{'HEX':<12}"
        f"DESCRIPTION"
    )

    separator()

    for value, flag in UAC_FLAGS.items():
        enabled = bool(uac & value)
        status = "ENABLED" if enabled else "DISABLED"

        print(
            f"{status:<10}"
            f"{flag['name']:<37}"
            f"{value:<12}"
            f"0x{value:08X}  "
            f"{flag['description']}"
        )


def detect_unknown_bits(uac):
    known_mask = 0

    for value in UAC_FLAGS:
        known_mask |= value

    unknown = uac & ~known_mask

    if unknown:
        print()
        separator("=")
        print("UNKNOWN / UNMAPPED BITS")
        separator("=")

        print(f"Decimal : {unknown}")
        print(f"Hex     : 0x{unknown:08X}")
        print(f"Binary  : {unknown:032b}")
        print()
        print(
            "The supplied UAC value contains bits that are not present "
            "in this decoder's ADS_USER_FLAG_ENUM mapping."
        )


def decode_uac(uac):
    print_summary(uac)
    print_active_flags(uac)
    print_security_findings(uac)
    print_all_flags(uac)
    detect_unknown_bits(uac)


def parse_value(value):
    value = value.strip()

    # int(..., 0) allows:
    #
    # 514
    # 0x202
    # 0b1000000010

    return int(value, 0)


def main():
    if len(sys.argv) > 1:
        raw_value = sys.argv[1]
    else:
        raw_value = input("Enter userAccountControl value: ")

    try:
        uac = parse_value(raw_value)

        if uac < 0:
            raise ValueError

    except ValueError:
        print(
            "Invalid UAC value.\n"
            "\n"
            "Examples:\n"
            "  514\n"
            "  66048\n"
            "  0x202\n"
            "  0b1000000010"
        )

        sys.exit(1)

    decode_uac(uac)


if __name__ == "__main__":
    main()
