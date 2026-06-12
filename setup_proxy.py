#!/usr/bin/python3

import os
import sys
import json
import re
import shlex
import shutil

from collections.abc import Mapping
from pathlib import Path, PosixPath

import ruamel.yaml  # pip install ruamel.yaml

"""
Why not just use the included yaml package?
Because this one preservs order and comments (and also allows adding them)
"""

blacklist = ["remote_pcap_folder", "caronte", "tulip", "ctf_proxy"]
compose_filenames = (
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
)

yaml = ruamel.yaml.YAML()
yaml.preserve_quotes = True
yaml.indent(sequence=3, offset=1)

dirs: list[PosixPath] = []
services_dict = {}


class WrongArgument(Exception):
    pass


def find_compose_file(directory):
    for filename in compose_filenames:
        file = Path(directory, filename)
        if file.is_file():
            return file
    raise FileNotFoundError(
        f"No docker compose file found in {directory}. Tried: "
        + ", ".join(compose_filenames)
    )


def run_bash(command):
    os.system(f"bash -c {shlex.quote(command)}")


def split_compose_port_mapping(port_mapping):
    """Split a Compose short port mapping without splitting inside ${...}."""
    parts = []
    current = []
    brace_depth = 0
    bracket_depth = 0
    i = 0

    while i < len(port_mapping):
        char = port_mapping[i]

        if char == "$" and i + 1 < len(port_mapping) and port_mapping[i + 1] == "{":
            brace_depth += 1
            current.append("${")
            i += 2
            continue

        if char == "}" and brace_depth:
            brace_depth -= 1
            current.append(char)
            i += 1
            continue

        if char == "[" and not brace_depth:
            bracket_depth += 1
        elif char == "]" and bracket_depth and not brace_depth:
            bracket_depth -= 1

        if char == ":" and not brace_depth and not bracket_depth:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)

        i += 1

    parts.append("".join(current))
    return parts


def resolve_compose_interpolation(value):
    """Resolve simple Docker Compose environment interpolation."""
    braced_pattern = re.compile(
        r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?:(:-|:\?|\:\+|-|\?|\+)([^}]*))?\}"
    )
    unbraced_pattern = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)")

    def replace_braced(match):
        var_name = match.group(1)
        operator = match.group(2)
        replacement = match.group(3) or ""
        env_value = os.environ.get(var_name)

        if operator is None:
            return env_value if env_value is not None else match.group(0)
        if operator == ":-":
            return env_value if env_value else replacement
        if operator == "-":
            return env_value if env_value is not None else replacement
        if operator == ":?":
            return env_value if env_value else match.group(0)
        if operator == "?":
            return env_value if env_value is not None else match.group(0)
        if operator == ":+":
            return replacement if env_value else ""
        if operator == "+":
            return replacement if env_value is not None else ""

        return match.group(0)

    def replace_unbraced(match):
        env_value = os.environ.get(match.group(1))
        return env_value if env_value is not None else match.group(0)

    return unbraced_pattern.sub(replace_unbraced, braced_pattern.sub(replace_braced, value))


def normalize_compose_port(port_value):
    """Return a numeric port after resolving Compose interpolation."""
    port = str(port_value).strip().strip("\"'")
    port = port.split("/", 1)[0]
    port = resolve_compose_interpolation(port).strip()
    return port if port.isdigit() else None


def parse_compose_port_mapping(port_mapping):
    """Return (target_port, listen_port) from Compose short or long syntax."""
    if isinstance(port_mapping, Mapping):
        target = port_mapping.get("target")
        published = port_mapping.get("published")
        if target is None or published is None:
            return None

        target_port = normalize_compose_port(target)
        listen_port = normalize_compose_port(published)
        if target_port and listen_port:
            return target_port, listen_port
        return None

    port_str = str(port_mapping).strip()
    port_parts = split_compose_port_mapping(port_str)
    if len(port_parts) < 2:
        return None

    target_port = normalize_compose_port(port_parts[-1])
    listen_port = normalize_compose_port(port_parts[-2])
    if target_port and listen_port:
        return target_port, listen_port
    return None


def parse_dirs():
    """
    If the user provided arguments use them as paths to find the services.
    If not, iterate through the directories and ask for confirmation
    """
    global dirs

    if sys.argv[1:]:
        for dir in sys.argv[1:]:
            d = Path(dir)
            if not d.exists():
                raise WrongArgument(f"The path {dir} doesn't exist")
            if not d.is_dir():
                raise WrongArgument(f"The path {dir} is not a directory")
            dirs.append(d)
    else:
        print(f"No arguments were provided; automatically scanning for services.")
        for file in Path(".").iterdir():
            if file.is_dir() and file.stem[0] != "." and file.stem not in blacklist:
                if "y" in input(f"Is {file.stem} a service? [y/N] "):
                    dirs.append(Path(".", file))


def make_backup():
    global dirs

    for dir in dirs:
        if not Path(dir.name + f"_backup.zip").exists():
            shutil.make_archive(dir.name + f"_backup", "zip", dir)


def parse_services():
    """
    If services.json is present, load it into the global dictionary.
    Otherwise, parse all the docker-compose yamls to build the dictionary and
    then save the result into services.json
    """
    global services_dict, dirs

    for service in dirs:
        file = find_compose_file(service)

        with open(file, "r") as fs:
            ymlfile = yaml.load(file)

        services_dict[service.stem] = {"path": str(service.resolve()), "containers": {}}

        for container in ymlfile["services"]:
            try:
                ports_string = ymlfile["services"][container]["ports"]
                ports_list = []
                for port_mapping in ports_string:
                    parsed_port = parse_compose_port_mapping(port_mapping)
                    if parsed_port is None:
                        print(
                            f"[!] Warning: could not parse published port mapping "
                            f"{port_mapping!r} for {service.stem}_{container}; skipping"
                        )
                        continue
                    ports_list.append(parsed_port)

                http = []
                for _, listen_port in ports_list:
                    http.append(
                        True
                        if "y"
                        in input(
                            f"Is the service {service.stem}:{listen_port} http? [y/N] "
                        )
                        else False
                    )

                container_dict = {
                    "target_port": [target for target, _ in ports_list],
                    "listen_port": [listen for _, listen in ports_list],
                    "http": [h for h in http],
                }
                services_dict[service.stem]["containers"][container] = container_dict

            except KeyError:
                print(f"{service.stem}_{container} has no ports binding")
            except Exception as e:
                raise e

        with open("services.json", "w") as backupfile:
            json.dump(services_dict, backupfile, indent=2)
    print("Found services:")
    for service in services_dict:
        print(f"\t{service}")


def edit_services():
    """
    Prepare the docker-compose for each service; comment out the ports, add hostname, add the external network, add an external volume for data persistence (this alone isn't enough - it' s just for convenience since we are already here)
    """
    global services_dict

    for service in services_dict:
        file = find_compose_file(services_dict[service]["path"])

        with open(file, "r") as fs:
            ymlfile = yaml.load(file)

        for container in services_dict[service]["containers"]:
            try:
                # Add a comment with the ports
                target_ports = services_dict[service]["containers"][container][
                    "target_port"
                ]
                listen_ports = services_dict[service]["containers"][container][
                    "listen_port"
                ]
                ports_string = "ports: "
                for target, listen in zip(target_ports, listen_ports):
                    ports_string += f"- {listen}:{target} "

                ymlfile["services"].yaml_add_eol_comment(ports_string, container)

                # Remove the actual port bindings
                try:
                    ymlfile["services"][container].pop("ports")
                except KeyError:
                    pass  # this means we had already had removed them

                # Add hostname
                hostname = f"{service}_{container}"
                if "hostname" in ymlfile["services"][container]:
                    print(
                        f"[!] Error: service {service}_{container} already has a hostname. Skipping this step, review it manually before restarting."
                    )
                else:
                    ymlfile["services"][container]["hostname"] = hostname

                # If this service has its own networks list, ensure it joins
                # `default` too — that's how it gets onto ctf_network without
                # losing whatever networks it was already attached to.
                svc = ymlfile["services"][container]
                if "networks" in svc:
                    if isinstance(svc["networks"], list):
                        if "default" not in svc["networks"]:
                            svc["networks"].append("default")
                    elif isinstance(svc["networks"], dict):
                        if "default" not in svc["networks"]:
                            svc["networks"]["default"] = None
                    else:
                        print(
                            f"[!] Warning: service {service}_{container} has an unexpected networks value; review manually."
                        )

            except Exception as e:
                json.dump(ymlfile, sys.stdout, indent=2)
                print(f"\n{container = }")
                raise e

            # TODO: Add restart: always

        # Add external ctf_network as the file's `default` network — once per
        # compose file, not per container. Services with no explicit networks
        # join `default` automatically; those with explicit networks were
        # patched above to also include `default`.
        net = {"name": "ctf_network", "external": True}
        if "networks" in ymlfile:
            if "default" not in ymlfile["networks"]:
                ymlfile["networks"]["default"] = net
            else:
                existing = ymlfile["networks"]["default"]
                if not (isinstance(existing, dict)
                        and existing.get("name") == "ctf_network"
                        and existing.get("external")):
                    print(
                        f"[!] Error: service {service} already has a default network. Skipping this step, review it manually before restarting."
                    )
        else:
            ymlfile["networks"] = {"default": net}

        # write file
        with open(file, "w") as fs:
            yaml.dump(ymlfile, fs)


def configure_proxy():
    """
    Properly configure both the proxy's docker-compose with the listening ports and the config.json with all the services.
    We can't automatically configure ssl for now, so it's better to set https services as not http so they keep working at least. Manually configure the SSL later and turn http back on.
    """
    # Download ctf_proxy
    if not Path("./ctf_proxy").exists():
        os.system("git clone https://github.com/Metagripwn/ctf_proxy.git")

    proxy_compose_file = find_compose_file("./ctf_proxy")

    with open(proxy_compose_file, "r") as file:
        ymlfile = yaml.load(file)

    # Add all the ports to the compose
    ports = []
    for service in services_dict:
        for container in services_dict[service]["containers"]:
            for port in services_dict[service]["containers"][container]["listen_port"]:
                ports.append(f"0.0.0.0:{port}:{port}")
    # ymlfile["services"]["proxy"]["ports"] = ports
    ymlfile["services"]["nginx"]["ports"] = ports
    with open(proxy_compose_file, "w") as fs:
        yaml.dump(ymlfile, fs)

    # Proxy config.json
    print("Remember to manually edit the config for SSL")
    services = []
    for service in services_dict:
        for container in services_dict[service]["containers"]:
            name = f"{service}_{container}"
            target_ports = services_dict[service]["containers"][container][
                "target_port"
            ]
            listen_ports = services_dict[service]["containers"][container][
                "listen_port"
            ]
            http = services_dict[service]["containers"][container]["http"]
            for i, (target, listen) in enumerate(zip(target_ports, listen_ports)):
                services.append(
                    {
                        "name": name + str(i),
                        "target_ip": name,
                        "target_port": int(target),
                        "listen_port": int(listen),
                        "http": http[i],
                    }
                )

    with open("./ctf_proxy/proxy/config/config.json", "r") as fs:
        proxy_config = json.load(fs)
    proxy_config["services"] = services
    with open("./ctf_proxy/proxy/config/config.json", "w") as fs:
        json.dump(proxy_config, fs, indent=2)


def restart_services():
    """
    Make sure every service is off and then start them one by one after the proxy
    """

    def compose_command(service, action):
        file = shlex.quote(str(find_compose_file(services_dict[service]["path"])))
        return f"(docker compose --file {file} {action}) &"

    down_cmds = " ".join(
        compose_command(service, "down")
        for service in services_dict
    )
    run_bash(f"{down_cmds} wait")

    proxy_compose_file = shlex.quote(str(find_compose_file("ctf_proxy")))
    run_bash(
        f"docker compose --file {proxy_compose_file} restart; docker compose --file {proxy_compose_file} up -d"
    )

    up_cmds = " ".join(
        compose_command(service, "up -d")
        for service in services_dict
    )
    run_bash(f"{up_cmds} wait")


def main():
    global services_dict

    if Path(os.getcwd()).name == "ctf_proxy":
        os.chdir("..")

    if Path("./services.json").exists():
        print("Found existing services file")
        with open("./services.json", "r") as fs:
            services_dict = json.load(fs)

    if "RESTART" in sys.argv:
        if not services_dict:
            print(
                f"Can't restart without first parsing the services. Please run the script at least once without the RESTART flag"
            )
        else:
            restart_services()
        return

    parse_dirs()
    parse_services()
    make_backup()

    edit_services()
    configure_proxy()
    confirmation = input(
        "You are about to restart all your services! Make sure that no catastrophic configuration error has occurred.\nPress Enter to continue"
    )
    restart_services()


if __name__ == "__main__":
    main()
