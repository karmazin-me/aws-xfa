# SPDX-License-Identifier: 0BSD
import argparse
import configparser
from configparser import NoOptionError, NoSectionError
import datetime
from importlib.metadata import version as _pkg_version, PackageNotFoundError
import logging
import os
import platform
import sys

try:
    __version__ = _pkg_version("aws-xfa")
except PackageNotFoundError:
    __version__ = "1.0.0"

import boto3

from botocore.exceptions import ClientError, ParamValidationError
from awsxfa.util import (
    log_error_and_exit,
    prompter,
    detect_aws_cli_version,
    get_v2_install_suggestions,
    get_otp_from_1password,
    prompt_with_validation,
    validate_access_key_id,
    validate_secret_access_key,
    validate_mfa_arn,
    validate_role_arn,
)
from awsxfa.xfa_config import (
    load_xfa_config,
    save_xfa_config,
    get_1pass_item,
    set_1pass_item,
)

logger = logging.getLogger("aws-xfa")

_env_creds = os.environ.get("AWS_SHARED_CREDENTIALS_FILE")
AWS_CREDS_PATH = (
    os.path.expanduser(_env_creds)
    if _env_creds
    else os.path.join(os.path.expanduser("~"), ".aws", "credentials")
)


def _daemon_cmd(argv):
    """Handle ``aws-xfa daemon {install,stop,status,delete}``."""
    setup_logger(logging.INFO)
    parser = argparse.ArgumentParser(
        prog="aws-xfa daemon",
        description="Manage the aws-xfa credential-refresh daemon.",
    )
    sub = parser.add_subparsers(dest="action", metavar="ACTION")

    p_install = sub.add_parser("install", help="Install and start the daemon.")
    p_install.add_argument("profile", help="AWS profile name to manage.")

    p_stop = sub.add_parser("stop", help="Stop the daemon.")
    p_stop.add_argument("profile", help="AWS profile name.")

    p_status = sub.add_parser("status", help="Show daemon status.")
    p_status.add_argument("profile", help="AWS profile name.")

    p_delete = sub.add_parser(
        "delete", help="Stop daemon and remove all artifacts and logs."
    )
    p_delete.add_argument("profile", help="AWS profile name.")

    args = parser.parse_args(argv)
    if not args.action:
        parser.print_help()
        sys.exit(1)
    from awsxfa.daemon import daemon_install, daemon_stop, daemon_status, daemon_delete

    if args.action == "install":
        xfa_config = load_xfa_config()
        xfa_config = _bootstrap_1pass(xfa_config, args.profile)
        save_xfa_config(xfa_config)
        daemon_install(args.profile, AWS_CREDS_PATH)
    elif args.action == "stop":
        daemon_stop(args.profile)
    elif args.action == "status":
        daemon_status(args.profile)
    elif args.action == "delete":
        daemon_delete(args.profile)


def _add_subprofile_cmd(argv):
    """Handle ``aws-xfa add-subprofile PARENT_PROFILE``."""
    setup_logger(logging.INFO)
    parser = argparse.ArgumentParser(
        prog="aws-xfa add-subprofile",
        description="Add role-based sub-profiles for an existing profile.",
    )
    parser.add_argument(
        "parent_profile",
        help="Parent AWS profile name (must already exist in credentials).",
    )
    args = parser.parse_args(argv)

    config = get_config(AWS_CREDS_PATH)
    long_term_name = "%s-long-term" % args.parent_profile
    if not config.has_section(long_term_name):
        log_error_and_exit(
            logger,
            "Profile '%s' not found. Section '[%s]' must exist in %s."
            % (args.parent_profile, long_term_name, AWS_CREDS_PATH),
        )

    region = _resolve_region(args.parent_profile)
    if not region:
        console_input = prompter()
        region = console_input("Enter AWS region (e.g. us-east-1): ").strip()
        if not region:
            log_error_and_exit(logger, "AWS region is required.")

    _collect_sub_profiles(args.parent_profile, region)
    print("\nAll set\n")


def main():
    if "--daemon-loop" in sys.argv:
        try:
            idx = sys.argv.index("--profile")
            profile = sys.argv[idx + 1]
        except (ValueError, IndexError):
            sys.stderr.write("--daemon-loop requires --profile PROFILE\n")
            sys.exit(1)
        from awsxfa.daemon import run_refresh_loop

        run_refresh_loop(AWS_CREDS_PATH, profile)
        return

    _print_header()

    if len(sys.argv) > 1 and sys.argv[1] == "daemon":
        _daemon_cmd(sys.argv[2:])
        return

    if len(sys.argv) > 1 and sys.argv[1] == "add-subprofile":
        _add_subprofile_cmd(sys.argv[2:])
        return

    parser = argparse.ArgumentParser(
        description="Exchange long-term AWS credentials (with MFA) for "
        "temporary STS credentials.",
        epilog=(
            "subcommands:\n"
            "  daemon {install,stop,status,delete}\n"
            "                        Manage the credential-refresh daemon.\n"
            "  add-subprofile PROFILE\n"
            "                        Add role-based sub-profiles for PROFILE.\n\n"
            'Run "aws-xfa daemon --help" or "aws-xfa add-subprofile --help"\n'
            "for subcommand details.\n "
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "profile",
        nargs="?",
        default="default",
        help="AWS profile name (default: 'default'). Reads long-term keys "
        "from [PROFILE-long-term] and writes temporary credentials "
        "to [PROFILE].",
    )
    parser.add_argument(
        "--duration",
        type=int,
        help="Session duration in seconds (min 900, max 129600). "
        "Defaults to 43200 (12 hours). "
        "Can also be set via the MFA_STS_DURATION environment variable.",
    )
    parser.add_argument(
        "--force",
        help="Refresh credentials even if currently valid.",
        action="store_true",
    )
    parser.add_argument(
        "--log-level",
        help="Set log level: 'regular' shows info and above (default), "
        "'debug' enables verbose output.",
        choices=["regular", "debug"],
        default="regular",
    )
    parser.add_argument(
        "--1pass",
        dest="onepassword",
        action="store_true",
        help="Use 1Password CLI to fetch MFA code. On first use, prompts for "
        "the 1Password item name and saves it for the profile.",
    )
    args = parser.parse_args()

    level = logging.DEBUG if args.log_level == "debug" else logging.INFO
    setup_logger(level)

    try:
        if not os.path.isfile(AWS_CREDS_PATH):
            console_input = prompter()
            create = console_input(
                "Could not locate credentials file at {}, "
                "would you like to create one? [y/n]: ".format(AWS_CREDS_PATH)
            )
            if create.lower() == "y":
                os.makedirs(os.path.dirname(AWS_CREDS_PATH), exist_ok=True)
                with open(AWS_CREDS_PATH, "a"):
                    pass
            else:
                log_error_and_exit(
                    logger, "Could not locate credentials file at %s" % AWS_CREDS_PATH
                )

        config = get_config(AWS_CREDS_PATH)
        xfa_config = load_xfa_config()
        validate(args, config, xfa_config)
    except KeyboardInterrupt:
        print("\nGot it, shutting down...\n")
        sys.exit(0)


def get_config(aws_creds_path):
    config = configparser.RawConfigParser()
    try:
        config.read(aws_creds_path)
    except configparser.ParsingError:
        e = sys.exc_info()[1]
        log_error_and_exit(
            logger,
            "There was a problem reading or parsing "
            "your credentials file: %s" % (e.args[0],),
        )
    return config


def _get_region_from_aws_config(profile):
    """Read region from ~/.aws/config for the given profile.

    AWS CLI v2 convention stores region in ~/.aws/config, not credentials.
    Respects the AWS_CONFIG_FILE env var override.
    """
    _env_config = os.environ.get("AWS_CONFIG_FILE")
    config_path = (
        os.path.expanduser(_env_config)
        if _env_config
        else os.path.join(os.path.expanduser("~"), ".aws", "config")
    )
    if not os.path.isfile(config_path):
        return None
    cfg = configparser.RawConfigParser()
    try:
        cfg.read(config_path)
    except configparser.Error:
        return None
    section = "default" if profile == "default" else "profile %s" % profile
    try:
        return cfg.get(section, "region")
    except (configparser.NoSectionError, configparser.NoOptionError):
        return None


def _ensure_aws_config(profile, region):
    """Write or update region and output=json in ~/.aws/config for profile."""
    _env_config = os.environ.get("AWS_CONFIG_FILE")
    config_path = (
        os.path.expanduser(_env_config)
        if _env_config
        else os.path.join(os.path.expanduser("~"), ".aws", "config")
    )
    os.makedirs(os.path.dirname(config_path), exist_ok=True)
    cfg = configparser.RawConfigParser()
    if os.path.isfile(config_path):
        try:
            cfg.read(config_path)
        except configparser.Error:
            pass

    section = "default" if profile == "default" else "profile %s" % profile

    if not cfg.has_section(section):
        cfg.add_section(section)

    cfg.set(section, "region", region)
    cfg.set(section, "output", "json")

    with open(config_path, "w") as f:
        cfg.write(f)
    logger.info(
        "Updated %s: profile='%s', region=%s, output=json", config_path, profile, region
    )


def _add_creds_section(config, section_name):
    """Add a section to the credentials config."""
    config.add_section(section_name)


def _resolve_duration(args):
    """Return session duration in seconds from CLI arg, env var, or default."""
    if args.duration:
        return args.duration
    if os.environ.get("MFA_STS_DURATION"):
        return int(os.environ.get("MFA_STS_DURATION"))
    return 43200


def _resolve_region(profile):
    """Return region from environment variables or ~/.aws/config."""
    return (
        os.environ.get("AWS_REGION")
        or os.environ.get("AWS_DEFAULT_REGION")
        or _get_region_from_aws_config(profile)
    )


def validate(args, config, xfa_config):
    profile = args.profile
    long_term_name = "%s-long-term" % profile
    short_term_name = profile

    cli_major, cli_version_str = detect_aws_cli_version()
    if cli_major is None:
        logger.warning(
            "AWS CLI not found. aws-xfa manages credentials but you need "
            "the AWS CLI to use them. Please install AWS CLI v2:"
        )
        for suggestion in get_v2_install_suggestions():
            logger.warning(suggestion)
        print()
    elif cli_major < 2:
        logger.warning(
            "AWS CLI v1 detected (%s). v1 enters maintenance July 2026 "
            "and end-of-support July 2027. To upgrade to AWS CLI v2:",
            cli_version_str,
        )
        for suggestion in get_v2_install_suggestions():
            logger.warning(suggestion)
        print()

    has_long_term = config.has_section(long_term_name)
    has_short_term = config.has_section(short_term_name)

    if has_long_term:
        _state_a_refresh(
            args, config, profile, long_term_name, short_term_name, xfa_config
        )
    elif has_short_term:
        _state_b_migrate(
            args, config, profile, long_term_name, short_term_name, xfa_config
        )
    else:
        _state_c_create(
            args, config, profile, long_term_name, short_term_name, xfa_config
        )


def _state_a_refresh(
    args, config, profile, long_term_name, short_term_name, xfa_config
):
    """Long-term section exists: perform normal credential refresh."""
    logger.info("Validating credentials for profile: %s", short_term_name)

    try:
        key_id = config.get(long_term_name, "aws_access_key_id")
        access_key = config.get(long_term_name, "aws_secret_access_key")
    except NoSectionError:
        log_error_and_exit(
            logger,
            "Long term credentials section '[%s]' is missing. "
            "You must add this section to your credentials file along with "
            "'aws_access_key_id' and "
            "'aws_secret_access_key'." % long_term_name,
        )
    except NoOptionError as e:
        log_error_and_exit(logger, e)

    try:
        mfa_device = config.get(long_term_name, "aws_mfa_device")
    except (NoSectionError, NoOptionError):
        log_error_and_exit(
            logger,
            "No 'aws_mfa_device' found in '[%s]'. Add it to your credentials "
            "file or run 'aws-xfa %s' to reconfigure." % (long_term_name, profile),
        )

    duration = _resolve_duration(args)
    region = _resolve_region(profile)

    force_refresh = False
    if not config.has_section(short_term_name):
        logger.info(
            "Short term credentials section '%s' is missing, "
            "obtaining new credentials.",
            short_term_name,
        )
        _add_creds_section(config, short_term_name)
        force_refresh = True
    else:
        required_options = [
            "aws_access_key_id",
            "aws_secret_access_key",
            "aws_session_token",
            "expiration",
        ]
        try:
            for option in required_options:
                config.get(short_term_name, option)
        except NoOptionError:
            logger.warning(
                "Your existing credentials are missing or invalid, "
                "obtaining new credentials."
            )
            force_refresh = True

        if args.force:
            logger.info("Forcing refresh of credentials.")
            force_refresh = True

    should_refresh = True
    if not force_refresh:
        try:
            exp_str = config.get(short_term_name, "expiration")
            exp = datetime.datetime.strptime(exp_str, "%Y-%m-%d %H:%M:%S")
            diff = exp - datetime.datetime.utcnow()
            if diff.total_seconds() <= 0:
                logger.info("Your credentials have expired, renewing.")
            else:
                should_refresh = False
                logger.info(
                    "Your credentials are still valid for %s, they will expire at %s",
                    _bold(_format_duration(diff.total_seconds())),
                    _bold(_format_expiration(exp)),
                )
                print()
        except (NoOptionError, NoSectionError):
            logger.info("Could not read expiration, obtaining new credentials.")

    if should_refresh:
        get_credentials(
            short_term_name,
            key_id,
            access_key,
            mfa_device,
            duration,
            config,
            args,
            xfa_config,
            profile,
            region=region,
        )


def _state_b_migrate(
    args, config, profile, long_term_name, short_term_name, xfa_config
):
    """Short-term section exists but no long-term: migrate to MFA setup."""
    logger.info(
        "Profile '%s' found without long-term credentials section. "
        "Migrating to MFA configuration.",
        profile,
    )

    try:
        key_id = config.get(short_term_name, "aws_access_key_id")
    except (NoSectionError, NoOptionError):
        key_id = None
    try:
        access_key = config.get(short_term_name, "aws_secret_access_key")
    except (NoSectionError, NoOptionError):
        access_key = None

    if not key_id or not access_key:
        log_error_and_exit(
            logger,
            "Profile '[%s]' is missing 'aws_access_key_id' or "
            "'aws_secret_access_key'. Cannot configure MFA." % short_term_name,
        )

    try:
        mfa_device = config.get(short_term_name, "aws_mfa_device")
    except (NoSectionError, NoOptionError):
        mfa_device = None

    if not mfa_device:
        mfa_device = prompt_with_validation(
            "Enter MFA device ARN for profile '%s' "
            "(e.g. arn:aws:iam::123456789012:mfa/username): " % profile,
            validate_mfa_arn, logger,
        )

    config.add_section(long_term_name)
    config.set(long_term_name, "aws_access_key_id", key_id)
    config.set(long_term_name, "aws_secret_access_key", access_key)
    config.set(long_term_name, "aws_mfa_device", mfa_device)

    for field in ("aws_access_key_id", "aws_secret_access_key", "aws_mfa_device"):
        config.remove_option(short_term_name, field)

    with open(AWS_CREDS_PATH, "w") as f:
        config.write(f)
    logger.info("Created '[%s]' with long-term credentials.", long_term_name)

    region = _resolve_region(profile)
    if not region:
        console_input = prompter()
        region = console_input("Enter AWS region (e.g. us-east-1): ").strip()
        if not region:
            log_error_and_exit(logger, "AWS region is required.")
    _ensure_aws_config(profile, region)
    _prompt_sub_profiles(profile, region)

    xfa_config = _prompt_1pass_setup(xfa_config, profile)
    duration = _resolve_duration(args)
    get_credentials(
        short_term_name,
        key_id,
        access_key,
        mfa_device,
        duration,
        config,
        args,
        xfa_config,
        profile,
        region=region,
    )


def _state_c_create(args, config, profile, long_term_name, short_term_name, xfa_config):
    """Neither section exists: full from-scratch profile creation."""
    logger.info("Profile '%s' not found. Creating new MFA-enabled profile.", profile)

    key_id = prompt_with_validation(
        "AWS Access Key ID: ", validate_access_key_id, logger
    )
    access_key = prompt_with_validation(
        "AWS Secret Access Key: ", validate_secret_access_key, logger, secret=True
    )
    mfa_device = prompt_with_validation(
        "MFA device ARN (e.g. arn:aws:iam::123456789012:mfa/username): ",
        validate_mfa_arn, logger,
    )

    console_input = prompter()
    region = console_input("AWS region (e.g. us-east-1): ").strip()
    if not region:
        log_error_and_exit(logger, "AWS region is required.")

    config.add_section(long_term_name)
    config.set(long_term_name, "aws_access_key_id", key_id)
    config.set(long_term_name, "aws_secret_access_key", access_key)
    config.set(long_term_name, "aws_mfa_device", mfa_device)

    _add_creds_section(config, short_term_name)

    with open(AWS_CREDS_PATH, "w") as f:
        config.write(f)
    logger.info("Created '[%s]'.", long_term_name)

    _ensure_aws_config(profile, region)
    _prompt_sub_profiles(profile, region)

    xfa_config = _prompt_1pass_setup(xfa_config, profile)
    duration = _resolve_duration(args)
    get_credentials(
        short_term_name,
        key_id,
        access_key,
        mfa_device,
        duration,
        config,
        args,
        xfa_config,
        profile,
        region=region,
    )


def _prompt_1pass_setup(xfa_config, profile):
    """During profile setup, offer to configure 1Password integration."""
    console_input = prompter()
    use_1pass = (
        console_input("Use 1Password CLI to automatically fetch MFA codes? [y/N]: ")
        .strip()
        .lower()
    )
    if use_1pass == "y":
        item_name = console_input("1Password item name (e.g. 'aws work'): ").strip()
        if item_name:
            xfa_config = set_1pass_item(xfa_config, profile, item_name)
            save_xfa_config(xfa_config)
            logger.info("1Password item saved for profile '%s'.", profile)
    return xfa_config


def _write_sub_profile(parent_profile, sub_name, role_arn, region):
    """Write a single sub-profile to ~/.aws/config."""
    _env_config = os.environ.get("AWS_CONFIG_FILE")
    config_path = (
        os.path.expanduser(_env_config)
        if _env_config
        else os.path.join(os.path.expanduser("~"), ".aws", "config")
    )
    os.makedirs(os.path.dirname(config_path), exist_ok=True)
    cfg = configparser.RawConfigParser()
    if os.path.isfile(config_path):
        try:
            cfg.read(config_path)
        except configparser.Error:
            pass

    full_name = "%s-%s" % (parent_profile, sub_name)
    section = "profile %s" % full_name

    if not cfg.has_section(section):
        cfg.add_section(section)

    cfg.set(section, "source_profile", parent_profile)
    cfg.set(section, "region", region)
    cfg.set(section, "role_arn", role_arn)
    cfg.set(section, "output", "json")

    with open(config_path, "w") as f:
        cfg.write(f)
    logger.info("Added sub-profile '%s' to %s", full_name, config_path)


def _collect_sub_profiles(profile, region):
    """Loop collecting sub-profiles until the user is done."""
    console_input = prompter()
    while True:
        sub_name = console_input("Sub-profile name (e.g. prod, stage): ").strip()
        if not sub_name:
            log_error_and_exit(logger, "Sub-profile name is required.")

        role_arn = prompt_with_validation(
            "Role ARN to assume (e.g. arn:aws:iam::123456789012:role/role-name): ",
            validate_role_arn, logger,
        )

        if region:
            sub_region = console_input("Region [%s]: " % region).strip() or region
        else:
            sub_region = console_input("Region (e.g. us-east-1): ").strip()
            if not sub_region:
                log_error_and_exit(logger, "Region is required.")

        _write_sub_profile(profile, sub_name, role_arn, sub_region)

        another = console_input("Add another sub-profile? [y/N]: ").strip().lower()
        if another != "y":
            break


def _prompt_sub_profiles(profile, region):
    """Ask whether to add sub-profiles, then collect them if yes."""
    console_input = prompter()
    want = console_input("Would you like to add sub-profiles? [y/N]: ").strip().lower()
    if want == "y":
        _collect_sub_profiles(profile, region)


def _bootstrap_1pass(xfa_config, profile):
    """If 1Password not yet configured for this profile, prompt and save."""
    if get_1pass_item(xfa_config, profile):
        return xfa_config
    console_input = prompter()
    item_name = console_input(
        "Enter 1Password item name for profile '%s' (e.g. 'aws work'): " % profile
    ).strip()
    if not item_name:
        log_error_and_exit(logger, "1Password item name is required with --1pass.")
    xfa_config = set_1pass_item(xfa_config, profile, item_name)
    save_xfa_config(xfa_config)
    logger.info("1Password item saved for profile '%s'.", profile)
    return xfa_config


def get_credentials(
    short_term_name,
    lt_key_id,
    lt_access_key,
    mfa_device,
    duration,
    config,
    args,
    xfa_config,
    profile,
    region=None,
):
    console_input = prompter()

    if args.onepassword:
        xfa_config = _bootstrap_1pass(xfa_config, profile)

    item = get_1pass_item(xfa_config, profile)
    if item:
        mfa_token = get_otp_from_1password(item, logger)
        if mfa_token is None:
            if not sys.stdin.isatty():
                log_error_and_exit(
                    logger,
                    "1Password OTP lookup failed and no interactive "
                    "terminal is available for manual entry.",
                )
            logger.warning("Falling back to manual MFA entry.")
            mfa_token = console_input(
                "Enter AWS MFA code for device [%s] "
                "(renewing for %s seconds): " % (mfa_device, duration)
            )
    else:
        if not sys.stdin.isatty():
            log_error_and_exit(
                logger,
                "No 1Password item configured for profile '%s' and no "
                "interactive terminal is available. Run "
                "'aws-xfa %s --1pass' to configure." % (profile, profile),
            )
        mfa_token = console_input(
            "Enter AWS MFA code for device [%s] "
            "(renewing for %s seconds): " % (mfa_device, duration)
        )

    sts_kwargs = dict(
        aws_access_key_id=lt_key_id,
        aws_secret_access_key=lt_access_key,
    )
    if region:
        sts_kwargs["region_name"] = region
        logger.debug("Using regional STS endpoint: sts.%s.amazonaws.com", region)
    else:
        logger.debug("No region configured; using global STS endpoint")

    client = boto3.client("sts", **sts_kwargs)

    if duration < 900:
        log_error_and_exit(
            logger,
            "Duration %d is too short. Minimum is 900 seconds (15 minutes)." % duration,
        )

    logger.info(
        "Fetching Credentials - Profile: %s, Duration: %s",
        _bold(short_term_name),
        duration,
    )
    try:
        response = client.get_session_token(
            DurationSeconds=duration, SerialNumber=mfa_device, TokenCode=mfa_token
        )
    except ClientError as e:
        log_error_and_exit(
            logger, "An error occurred while calling get-session-token: {}".format(e)
        )
    except ParamValidationError as e:
        log_error_and_exit(logger, str(e))

    options = [
        ("aws_access_key_id", "AccessKeyId"),
        ("aws_secret_access_key", "SecretAccessKey"),
        ("aws_session_token", "SessionToken"),
        ("aws_security_token", "SessionToken"),
    ]
    for option, value in options:
        config.set(short_term_name, option, response["Credentials"][value])

    config.set(
        short_term_name,
        "expiration",
        response["Credentials"]["Expiration"].strftime("%Y-%m-%d %H:%M:%S"),
    )
    with open(AWS_CREDS_PATH, "w") as configfile:
        config.write(configfile)
    logger.info(
        "Success! Your credentials will expire in %s at: %s",
        _bold(_format_duration(duration)),
        _format_expiration(response["Credentials"]["Expiration"]),
    )
    print()
    sys.exit(0)


def _format_duration(total_seconds):
    """Convert seconds into a human-readable string like '11h 55m 34s'."""
    total_seconds = int(total_seconds)
    hours, remainder = divmod(total_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    parts = []
    if hours:
        parts.append("%dh" % hours)
    if minutes:
        parts.append("%dm" % minutes)
    parts.append("%ds" % seconds)
    return " ".join(parts)


def _format_expiration(dt):
    """Format expiration as UTC, appending local time only when the local
    timezone differs from UTC.

    Accepts both naive datetimes (assumed UTC) and timezone-aware datetimes.
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    dt_utc = dt.astimezone(datetime.timezone.utc)
    dt_local = dt.astimezone()
    utc_str = dt_utc.strftime("%Y-%m-%d %H:%M:%S UTC")
    if dt_local.utcoffset() != datetime.timedelta(0):
        local_label = dt_local.strftime("%Z") or "local"
        local_str = _bold(
            "%s %s" % (dt_local.strftime("%Y-%m-%d %H:%M:%S"), local_label)
        )
        return "%s / %s" % (local_str, utc_str)
    return utc_str


_LOG_COLORS = {
    logging.DEBUG: "\033[36m",  # cyan
    logging.INFO: "\033[32m",  # green
    logging.WARNING: "\033[33m",  # yellow
    logging.ERROR: "\033[31m",  # red
    logging.CRITICAL: "\033[1;31m",  # bold red
}
_RESET = "\033[0m"


def _color_enabled():
    if "FORCE_COLOR" in os.environ:
        return True
    if "NO_COLOR" in os.environ:
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    return getattr(sys.stdout, "isatty", lambda: False)()


def _bold(text):
    return "\033[1m%s\033[0m" % text if _color_enabled() else text


def _print_header():
    if not _color_enabled():
        return
    # Windows detached processes fall back to cp* encodings that cannot
    # represent the ▓ characters used in the banner.
    if platform.system() == "Windows":
        enc = getattr(sys.stdout, "encoding", "") or ""
        if enc.lower().startswith("cp"):
            return
    c = "\033[38;5;%dm"
    _A = [" ▓▓▓ ", "▓   ▓", "▓▓▓▓▓", "▓   ▓", "▓   ▓"]
    _W = ["▓   ▓", "▓   ▓", "▓ ▓ ▓", "▓▓ ▓▓", "▓   ▓"]
    _S = [" ▓▓▓▓", "▓    ", " ▓▓▓ ", "    ▓", "▓▓▓▓ "]
    _X = ["▓   ▓", " ▓ ▓ ", "  ▓  ", " ▓ ▓ ", "▓   ▓"]
    _F = ["▓▓▓▓▓", "▓    ", "▓▓▓▓ ", "▓    ", "▓    "]
    sp = [" "] * 5
    gp = ["  "] * 5
    segs = [
        (c % 214, _A),  # A — bright orange
        ("", sp),
        (c % 208, _W),  # W — orange
        ("", sp),
        (c % 202, _S),  # S — dark orange
        ("", gp),  # word gap
        (c % 248, _X),  # X — light grey
        ("", sp),
        (c % 244, _F),  # F — medium grey
        ("", sp),
        (c % 240, _A),  # A — dark grey
    ]
    sys.stdout.write("\n")
    for i in range(5):
        line = "  "
        for color, rows in segs:
            line += color + rows[i]
        sys.stdout.write(line + _RESET + "\n")
    ver = (c % 244) + ("v%s" % __version__).center(36) + _RESET
    sys.stdout.write("  " + ver + "\n\n")


class _ColorFormatter(logging.Formatter):
    def format(self, record):
        color = _LOG_COLORS.get(record.levelno, "") if _color_enabled() else ""
        if color:
            r = logging.makeLogRecord(record.__dict__)
            r.levelname = "%s%s%s" % (color, record.levelname, _RESET)
            return super().format(r)
        return super().format(record)


def setup_logger(level=logging.DEBUG):
    stdout_handler = logging.StreamHandler(stream=sys.stdout)
    stdout_handler.setFormatter(_ColorFormatter("%(levelname)s - %(message)s"))
    stdout_handler.setLevel(level)
    logger.addHandler(stdout_handler)
    logger.setLevel(level)


if __name__ == "__main__":
    main()
