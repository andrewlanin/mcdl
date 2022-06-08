#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import pathlib
import platform
import re
import urllib.request
import uuid
import stat
import sys


verbose = False


def list_versions():
    manifest = get_versions_manifest()
    print('Latest release:  {}'.format(manifest['latest']['release']))
    print('Latest snapshot: {}'.format(manifest['latest']['snapshot']))
    print('All versions:')
    for version in manifest['versions']:
        print('    {} {}    {}'.format(
            version['id'].ljust(25, ' '),
            version['releaseTime'][:10],
            version['type'],
        ))


def download_client_and_create_launch_script(
        version,
        output_path,
        java_command,
        player_name):
    manifest = get_version_manifest(version)
    jars = download_client(manifest, output_path)
    create_client_launch_script(
        manifest,
        output_path,
        java_command,
        jars,
        player_name
    )


def download_server_and_create_launch_script(
        version,
        output_path,
        java_command):
    manifest = get_version_manifest(version)
    jar = download_server(manifest, output_path)
    create_server_launch_script(
        manifest,
        output_path,
        java_command,
        jar
    )
    accept_server_eula(output_path)


def download_client(manifest, output_path):
    version_id = manifest['id']
    jars = []
    downloads = []

    print('Verifying instalation...', file=sys.stderr, flush=True)

    client_url = manifest['downloads']['client']['url']
    client_path = output_path / 'versions' / version_id / 'client.jar'
    chient_sha1 = manifest['downloads']['client']['sha1']
    jars.append(client_path)
    if not verify_file(client_path, chient_sha1):
        downloads.append({
            'url': client_url,
            'path': client_path,
            'sha1': chient_sha1
        })

    libs_path = output_path / 'libraries'
    for lib_info in manifest['libraries']:
        rules = None
        rules_passed = None
        if 'rules' in lib_info:
            rules = lib_info['rules']
            rules_passed = check_rules(rules)

        if verbose:
            print(
                'Library {}: rules={}, rules_passed={}'.format(
                    lib_info['name'],
                    rules,
                    rules_passed
                ),
                file=sys.stderr,
                flush=True
            )

        if rules_passed is False:
            continue

        if 'artifact' in lib_info['downloads']:
            lib_url = lib_info['downloads']['artifact']['url']
            lib_path = libs_path / lib_info['downloads']['artifact']['path']
            lib_sha1 = lib_info['downloads']['artifact']['sha1']
            if lib_path not in jars:
                jars.append(lib_path)
            if not verify_file(lib_path, lib_sha1):
                downloads.append({
                    'url': lib_url,
                    'path': lib_path,
                    'sha1': lib_sha1
                })

        native_lib_info = None
        if 'classifiers' in lib_info['downloads']:
            os = platform.system()
            classifiers = lib_info['downloads']['classifiers']
            if os == 'Windows' and 'natives-windows' in classifiers:
                native_lib_info = classifiers['natives-windows']
            elif os == 'Linux' and 'natives-linux' in classifiers:
                native_lib_info = classifiers['natives-linux']
            elif os == 'Darwin' and 'natives-macos' in classifiers:
                native_lib_info = classifiers['natives-macos']
            elif os == 'Darwin' and 'natives-osx' in classifiers:
                native_lib_info = classifiers['natives-osx']

        if native_lib_info:
            if verbose:
                print(
                    'Use native library {}'.format(native_lib_info),
                    file=sys.stderr,
                    flush=True
                )
            native_lib_url = native_lib_info['url']
            native_lib_path = libs_path / native_lib_info['path']
            native_lib_sha1 = native_lib_info['sha1']
            if native_lib_path not in jars:
                jars.append(native_lib_path)
            if not verify_file(native_lib_path, native_lib_sha1):
                downloads.append({
                    'url': native_lib_url,
                    'path': native_lib_path,
                    'sha1': native_lib_sha1
                })

    assets_path = output_path / 'assets'
    assets_version = manifest['assetIndex']['id']
    assets_index_url = manifest['assetIndex']['url']
    assets_index_path = assets_path / 'indexes' / (assets_version + '.json')
    assets_index_sha1 = manifest['assetIndex']['sha1']
    download_and_verify_file(
        assets_index_url,
        assets_index_path,
        assets_index_sha1
    )
    assets_manifest = load_json_file(assets_index_path)

    for asset in assets_manifest['objects'].values():
        asset_sha1 = asset['hash']
        asset_url = (
            'http://resources.download.minecraft.net/' +
            asset_sha1[:2] +
            '/' +
            asset_sha1
        )
        asset_path = assets_path / 'objects' / asset_sha1[:2] / asset_sha1
        if not verify_file(asset_path, asset_sha1):
            downloads.append({
                'url': asset_url,
                'path': asset_path,
                'sha1': asset_sha1
            })

    download_files(downloads)
    return jars


def download_server(manifest, output_path):
    version_id = manifest['id']
    downloads = []

    print('Verifying instalation...', file=sys.stderr, flush=True)

    server_url = manifest['downloads']['server']['url']
    server_path = output_path / 'versions' / version_id / 'server.jar'
    server_sha1 = manifest['downloads']['server']['sha1']
    if not verify_file(server_path, server_sha1):
        downloads.append({
            'url': server_url,
            'path': server_path,
            'sha1': server_sha1
        })

    download_files(downloads)
    return server_path


def get_versions_manifest():
    url = 'https://launchermeta.mojang.com/mc/game/version_manifest.json'
    return request_json(url)


def get_version_manifest(version):
    versions_manifest = get_versions_manifest()

    if verbose:
        print(
            'Requested version: {}'.format(version),
            file=sys.stderr,
            flush=True
        )

    if version == 'release':
        version = versions_manifest['latest']['release']
    elif version == 'snapshot':
        version = versions_manifest['latest']['snapshot']

    if verbose:
        print(
            'Resolved version: {}'.format(version),
            file=sys.stderr,
            flush=True
        )

    version_info = None
    for info in versions_manifest['versions']:
        if info['id'] == version:
            version_info = info
            break
    if version_info is None:
        raise VersionException(version)

    if verbose:
        print('Version info: {}'.format(info), file=sys.stderr, flush=True)

    return request_json(version_info['url'])


def request_json(url):
    return json.load(urllib.request.urlopen(url))


def load_json_file(path):
    with open(str(path)) as f:
        return json.load(f)


def download_files(downloads):
    total = len(downloads)
    if total == 0:
        print('Everything is up-to-date', file=sys.stderr, flush=True)
        return

    for i, download in enumerate(downloads):
        idx = i + 1
        url = download['url']
        path = download['path']
        sha1 = download['sha1']
        print(
            '[{}/{}] Downloading {}...'.format(idx, total, url),
            file=sys.stderr,
            flush=True
        )
        download_and_verify_file(url, path, sha1, tries=5)


def download_and_verify_file(url, path, sha1, tries=1):
    while tries > 0:
        download_file(url, path)
        if verify_file(path, sha1):
            return
        tries -= 1

    if tries == 0:
        raise VerificationException(url, path, sha1, calc_file_sha1(path))


def download_file(url, path):
    if not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)

    urllib.request.urlretrieve(url, str(path))


def verify_file(path, sha1):
    return calc_file_sha1(path) == sha1


def calc_file_sha1(path):
    digest = hashlib.sha1()

    try:
        with open(path, 'rb') as f:
            chunk_size = 1024 * 1024
            while True:
                data = f.read(chunk_size)
                if not data:
                    break
                digest.update(data)
    except FileNotFoundError:
        return None

    return digest.hexdigest()


def create_client_launch_script(
        manifest,
        output_path,
        java_command,
        jars,
        player_name):
    version_id = manifest['id']
    command = [java_command]

    if 'arguments' in manifest:
        add_arguments(command, manifest['arguments']['jvm'])
    else:
        add_arguments(command, ['-cp', r'${classpath}'])

    command.append(manifest['mainClass'])

    if 'arguments' in manifest:
        add_arguments(command, manifest['arguments']['game'])
    elif 'minecraftArguments' in manifest:
        add_arguments(command, manifest['minecraftArguments'].split(' '))

    natives_path = pathlib.Path('versions') / version_id / 'natives'
    class_path = make_class_path(output_path, jars)

    command = ' '.join(command)
    command = command.replace(
        r'${natives_directory}',
        '"' + str(natives_path) + '"'
    )
    command = command.replace(r'${launcher_name}', 'mcdl')
    command = command.replace(r'${launcher_version}', '1.0')
    command = command.replace(r'${classpath}', '"' + class_path + '"')
    command = command.replace(r'${auth_player_name}', '"' + player_name + '"')
    command = command.replace(r'${version_name}', version_id)
    command = command.replace(r'${game_directory}', '.')
    command = command.replace(r'${assets_root}', 'assets')
    command = command.replace(
        r'${assets_index_name}',
        manifest['assetIndex']['id']
    )
    command = command.replace(r'${auth_uuid}', str(uuid.uuid4()))
    command = command.replace(
        r'${auth_access_token}',
        '00000000000000000000000000000000'
    )
    command = command.replace(r'${clientid}', '0000')
    command = command.replace(r'${auth_xuid}', '0000')
    command = command.replace(r'${user_type}', 'mojang')
    command = command.replace(r'${version_type}', manifest['type'])

    if verbose:
        print('Command: {}'.format(command), file=sys.stderr, flush=True)

    create_script(output_path, 'mc-' + version_id, command)


def create_server_launch_script(
        manifest,
        output_path,
        java_command,
        jar_path):
    version_id = manifest['id']
    command = ' '.join([
        java_command,
        '-jar', str(jar_path.relative_to(output_path)),
        '-nogui'
    ])

    if verbose:
        print('Command: {}'.format(command), file=sys.stderr, flush=True)

    create_script(output_path, 'mc-' + version_id + '-server', command)


def create_script(output_path, script_base_name, command):
    if platform.system() == 'Windows':
        path = output_path / (script_base_name + '.bat')
        with open(path, 'w') as f:
            f.write('cd /D "%~dp0"\n')
            f.write(command)
    else:
        path = output_path / (script_base_name + '.sh')
        with open(path, 'w') as f:
            f.write('#!/bin/sh\n')
            f.write('cd $(dirname $0)\n')
            f.write(command)
        st = os.stat(path)
        os.chmod(path, st.st_mode | stat.S_IEXEC)


def add_arguments(command, args):
    for arg in args:
        add_argument(command, arg)


def add_argument(command, arg):
    if type(arg) is str:
        if ' ' in arg:
            arg = '"' + arg + '"'
        command.append(arg)
    elif type(arg) is list:
        for e in arg:
            add_argument(command, e)
    elif type(arg) is dict:
        if 'rules' in arg:
            if check_rules(arg['rules']):
                add_argument(command, arg['value'])
        else:
            print('[WARN] Unexpected launch argument dict:', arg)
    else:
        print('[WARN] Unexpected launch argument:', arg)


def check_rules(rules):
    result = False
    for rule in rules:
        allow = check_rule(rule)
        if verbose:
            print(
                'Rule {}: allow={}'.format(rule, allow),
                file=sys.stderr,
                flush=True
            )
        if allow is not None:
            result = allow
    return result


def check_rule(rule):
    match = True
    allow = True

    for k, v in rule.items():
        if k == 'action':
            allow = v == 'allow'
        elif k == 'os':
            for k, v in v.items():
                if k == 'name':
                    current_os = platform.system()
                    match = match and (
                        (current_os == 'Windows' and v == 'windows') or
                        (current_os == 'Linux' and v == 'linux') or
                        (current_os == 'Darwin' and v == 'osx')
                    )
                elif k == 'arch':
                    match = match and (platform.machine() == v)
                elif k == 'version':
                    match = match and re.match(v, platform.version())
                else:
                    print(
                        'WARN: Unexpected key os.{} in rule {}'.format(
                            k,
                            rule
                        ),
                        file=sys.stderr,
                        flush=True
                    )
        elif k == 'features':
            for feature, enabled in v.items():
                if feature == 'is_demo_user':
                    match = match and not enabled
                elif feature == 'has_custom_resolution':
                    match = match and not enabled
                else:
                    match = match and not enabled
                    print(
                        'Unknown feature {} in rule {}'.format(feature, rule),
                        file=sys.stderr,
                        flush=True
                    )
        else:
            print(
                'WARN: Unexpected key {} in rule {}'.format(k, rule),
                file=sys.stderr,
                flush=True
            )

    if match:
        return allow

    return None


def make_class_path(output_path, jars):
    relative_paths = [str(path.relative_to(output_path)) for path in jars]
    if platform.system() == 'Windows':
        return ';'.join(relative_paths)
    else:
        return ':'.join(relative_paths)


def accept_server_eula(output_path):
    with open(output_path / 'eula.txt', 'w') as f:
        f.write('eula=true\n')


class VerificationException(Exception):
    def __init__(self, url, path, expected_sha1, real_sha1):
        self.url = url
        self.path = path
        self.expected_sha1 = expected_sha1
        self.real_sha1 = real_sha1


class VersionException(Exception):
    def __init__(self, version):
        self.version = version


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Download Minecraft client')
    parser.add_argument(
        '-v', '--version',
        type=str,
        default='release',
        help='game version, use "release", "snapshot" or specific version'
    )
    parser.add_argument(
        '-n', '--name',
        type=str,
        default='Anon',
        help='player name'
    )
    parser.add_argument(
        '-o', '--output',
        type=pathlib.Path,
        default=pathlib.Path.cwd(),
        help='output path'
    )
    parser.add_argument(
        '-j', '--java',
        type=str,
        default='java',
        help='java command'
    )
    parser.add_argument(
        '-s', '--server',
        action='store_true',
        help='download server instead of client'
    )
    parser.add_argument(
        '--list-versions',
        action='store_true',
        help='list available versions and exit'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='enable verbose logging'
    )

    args = parser.parse_args()

    if args.verbose:
        verbose = True

    if args.list_versions:
        list_versions()
        sys.exit(0)

    try:
        if args.server:
            download_server_and_create_launch_script(
                args.version,
                args.output,
                args.java
            )
        else:
            download_client_and_create_launch_script(
                args.version,
                args.output,
                args.java,
                args.name
            )
    except VersionException as e:
        print('Unknown version: {}.'.format(e.version))
        print('Run "mcdl.py --list-versions" to see all available versions.')
        sys.exit(1)
    except VerificationException as e:
        print('''Failed to download file, hash mismatch:
            url = {}
           path = {}
  expected_sha1 = {}
      real_sha1 = {}'''.format(
            e.url,
            e.path,
            e.expected_sha1,
            e.real_sha1
        ))
        sys.exit(1)
