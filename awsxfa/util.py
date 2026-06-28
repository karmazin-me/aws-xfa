# SPDX-License-Identifier: 0BSD
import platform
import re
import subprocess
import sys


def log_error_and_exit(logger, message):
    """Log an error message and exit with error"""
    logger.error(message)
    print()
    sys.exit(1)


def detect_aws_cli_version():
    """Returns (major: int, version_str: str) or (None, None) if not installed.

    NOTE: aws-cli v1 prints version to stderr; v2 prints to stdout.
    Concatenate both streams to capture the version regardless of stream.
    """
    try:
        result = subprocess.run(
            ["aws", "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
            text=True,
        )
        output = (result.stdout or "") + (result.stderr or "")
        match = re.search(r"aws-cli/(\d+)\.", output)
        if match:
            return int(match.group(1)), output.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass
    return None, None


def get_v2_install_suggestions():
    """Returns platform-appropriate AWS CLI v2 installation options."""
    system = platform.system().lower()
    if system == "darwin":
        return [
            "  Option 1 (Homebrew):  brew install awscli",
            "  Option 2 (pkg):       https://awscli.amazonaws.com/AWSCLIV2.pkg",
        ]
    elif system == "linux":
        return [
            "  Option 1 (pkg mgr):   use your Linux package manager "
            "(apt, dnf, yum, pacman, zypper, etc.) to install 'awscli'",
            "  Option 2 (official):  "
            "https://docs.aws.amazon.com/cli/latest/userguide/"
            "getting-started-install.html",
        ]
    elif system == "windows":
        return [
            "  Option 1 (winget):    winget install Amazon.AWSCLI",
            "  Option 2 (choco):     choco install awscli",
        ]
    else:
        return [
            "  See: https://docs.aws.amazon.com/cli/latest/userguide/"
            "getting-started-install.html",
        ]


def get_otp_from_1password(item_name, logger):
    """Fetch a TOTP code from 1Password CLI.

    Returns the OTP string on success, or None on any failure (with a warning).
    """
    try:
        result = subprocess.run(
            ["op", "item", "get", item_name, "--otp"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            text=True,
        )
        if result.returncode != 0:
            logger.warning(
                "1Password CLI failed for item '%s': %s",
                item_name,
                result.stderr.strip(),
            )
            return None
        otp = result.stdout.strip()
        if not otp:
            logger.warning("1Password returned empty OTP for item '%s'", item_name)
            return None
        return otp
    except FileNotFoundError:
        logger.warning("'op' CLI not found in PATH; cannot fetch MFA from 1Password")
        return None
    except subprocess.TimeoutExpired:
        logger.warning("'op' CLI timed out fetching OTP for item '%s'", item_name)
        return None


def get_otp_from_ykman(account_query, logger, timeout=30):
    """Fetch a 6-digit OATH-TOTP from a YubiKey via ``ykman``.

    Returns the code on success, or None on any failure (with a warning).
    stderr is inherited so the "Touch your YubiKey" / password prompt is
    visible; stdin is closed so a stdin-based prompt can't hang the call
    (a locked/uncached OATH keyring reads /dev/tty, so the real bound there
    is *timeout*). The raw value is never logged on the reject path.
    """
    if not account_query or not account_query.strip():
        logger.warning("No ykman OATH account configured; cannot fetch MFA code.")
        return None
    try:
        result = subprocess.run(
            ["ykman", "oath", "accounts", "code", "--single", "--", account_query],
            stdout=subprocess.PIPE,
            stderr=None,
            stdin=subprocess.DEVNULL,
            timeout=timeout,
            text=True,
        )
    except FileNotFoundError:
        logger.warning(
            "'ykman' not found in PATH. Install yubikey-manager "
            "(brew install ykman / pipx install yubikey-manager)."
        )
        return None
    except subprocess.TimeoutExpired:
        logger.warning(
            "ykman timed out (waiting for touch, an OATH password prompt, a "
            "locked keyring, a wedged PC/SC stack, or multiple keys inserted)."
        )
        return None
    if result.returncode != 0:
        logger.warning(
            "Couldn't get a code from the YubiKey. Check: the key is inserted "
            "and CCID/OATH enabled; 'ykman oath accounts list' shows the "
            "account (--single errors on zero or multiple matches); for FIPS "
            "keys run 'ykman oath access remember' once; require ykman >= 5.x."
        )
        return None
    code = (result.stdout or "").strip()
    if not is_valid_totp(code):
        # Never log the raw value — it may be a valid secret.
        logger.warning(
            "ykman returned a non-TOTP value (length=%d numeric=%s).",
            len(code),
            code.isdigit(),
        )
        return None
    return code


def list_ykman_accounts(logger, timeout=10):
    """Return the list of OATH account labels on the key, or None if listing
    isn't possible (ykman missing, key absent, or OATH locked)."""
    try:
        result = subprocess.run(
            ["ykman", "oath", "accounts", "list"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            timeout=timeout,
            text=True,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    return [ln.strip() for ln in (result.stdout or "").splitlines() if ln.strip()]


def validate_access_key_id(value):
    """Check AWS access key ID format: AKIA prefix, >=15 chars."""
    if not value:
        return False, "AWS Access Key ID is required."
    if not value.startswith("AKIA"):
        if value.startswith("ASIA"):
            return False, (
                "Key starts with ASIA (temporary STS credential). "
                "Enter a long-term key starting with AKIA."
            )
        return False, "AWS Access Key ID must start with 'AKIA'."
    if len(value) < 15:
        return False, "AWS Access Key ID is too short (minimum 15 characters)."
    if not re.match(r'^[A-Za-z0-9]+$', value):
        return False, (
            "AWS Access Key ID must contain only "
            "alphanumeric characters."
        )
    return True, ""


def validate_secret_access_key(value):
    """Check AWS secret access key format: >=35 chars, base64 alphabet."""
    if not value:
        return False, "AWS Secret Access Key is required."
    if len(value) < 35:
        return False, (
            "AWS Secret Access Key is too short "
            "(minimum 35 characters)."
        )
    if not re.match(r'^[A-Za-z0-9+/=]+$', value):
        return False, (
            "AWS Secret Access Key contains invalid characters."
        )
    return True, ""


def validate_mfa_arn(value):
    """Check MFA device ARN format."""
    if not value:
        return False, "MFA device ARN is required."
    if ":u2f/" in value:
        return False, (
            "This is a FIDO/U2F security key ARN. FIDO works only for AWS "
            "Console sign-in; the CLI/STS needs a virtual MFA (OATH-TOTP) "
            "device. Register one in IAM and use its ':mfa/' ARN."
        )
    if not re.match(r'^arn:aws[a-z-]*:iam::\d{12}:mfa/.+$', value):
        return False, (
            "Invalid MFA ARN format. "
            "Expected: arn:aws:iam::<12-digit-account>:mfa/<username>"
        )
    return True, ""


def is_valid_totp(code):
    """True only for a 6-digit ASCII TOTP code (after stripping surrounding
    whitespace). Uses [0-9] (not \\d, which is Unicode-wide) and never int()
    (which would drop leading zeros)."""
    return isinstance(code, str) and bool(re.fullmatch(r"[0-9]{6}", code.strip()))


def looks_like_modhex(value):
    """True if *value* looks like a Yubico OTP (modhex), e.g. the 44-char
    string emitted by a YubiKey's OTP slot on touch."""
    return isinstance(value, str) and bool(
        re.fullmatch(r"[cbdefghijklnrtuv]{32,48}", value)
    )


def validate_totp_code(value):
    """(ok, msg) validator for prompt_with_validation: accept a 6-digit TOTP,
    reject everything else with an actionable message."""
    if is_valid_totp(value):
        return True, ""
    if looks_like_modhex(value):
        return False, (
            "That looks like a YubiKey OTP (modhex), not an AWS TOTP code. "
            "AWS codes come from the OATH app (ykman / Yubico Authenticator), "
            "not from touching the key at this prompt."
        )
    return False, "AWS STS requires a 6-digit TOTP code (digits only)."


def validate_role_arn(value):
    """Check IAM role ARN format."""
    if not value:
        return False, "Role ARN is required."
    if not re.match(r'^arn:aws[a-z-]*:iam::\d{12}:role/.+$', value):
        return False, (
            "Invalid Role ARN format. "
            "Expected: arn:aws:iam::<12-digit-account>:role/<role-name>"
        )
    return True, ""


def prompt_with_validation(prompt_text, validator, log, secret=False):
    """Prompt in a loop until validator passes. Warns on bad input."""
    while True:
        if secret:
            value = getpass_starred(prompt_text).strip()
        else:
            value = input(prompt_text).strip()
        ok, msg = validator(value)
        if ok:
            return value
        log.warning(msg)


def prompter():
    return input


def getpass_starred(prompt=""):
    """Prompt for a secret, echoing * for each character typed.

    Falls back to no-echo (getpass behaviour) if the terminal cannot be
    put into raw mode (e.g. when stdin is piped/redirected).
    """
    sys.stdout.write(prompt)
    sys.stdout.flush()
    chars = []
    try:
        import tty
        import termios

        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            while True:
                ch = sys.stdin.read(1)
                if ch in ("\r", "\n"):
                    break
                elif ch in ("\x7f", "\x08"):  # backspace / DEL
                    if chars:
                        chars.pop()
                        sys.stdout.write("\b \b")
                        sys.stdout.flush()
                elif ch == "\x03":  # Ctrl-C
                    raise KeyboardInterrupt
                else:
                    chars.append(ch)
                    sys.stdout.write("*")
                    sys.stdout.flush()
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
    except ImportError:
        import msvcrt

        while True:
            ch = msvcrt.getwch()
            if ch in ("\r", "\n"):
                break
            elif ch in ("\x08", "\x7f"):  # backspace
                if chars:
                    chars.pop()
                    sys.stdout.write("\b \b")
                    sys.stdout.flush()
            elif ch == "\x03":
                raise KeyboardInterrupt
            else:
                chars.append(ch)
                sys.stdout.write("*")
                sys.stdout.flush()
    except termios.error:
        import getpass

        sys.stdout.write("\n")
        return getpass.getpass("").strip()
    sys.stdout.write("\n")
    return "".join(chars)
