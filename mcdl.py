#!/usr/bin/env python3
import argparse, json, os, pathlib, platform, urllib.request, uuid, stat, sys

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

def download(version, player_name):
	path = pathlib.Path()
	manifest = get_version_manifest(version)
	version_id = manifest['id']
	class_path = []

	client_path = path / 'versions' / version_id / (version_id + '.jar')
	download_file(manifest['downloads']['client']['url'], client_path)
	class_path.append(str(client_path))

	libs_path = path / 'libraries'
	for lib_info in manifest['libraries']:
		if 'rules' in lib_info:
			if not check_rules(lib_info['rules']):
				continue

		url = lib_info['downloads']['artifact']['url']
		lib_path = libs_path / lib_info['downloads']['artifact']['path']
		download_file(url, lib_path)
		class_path.append(str(lib_path))

	assets_path = path / 'assets'
	assets_version = manifest['assetIndex']['id']
	assets_index_path = assets_path / 'indexes' / (assets_version + '.json')
	download_file(manifest['assetIndex']['url'], assets_index_path)
	assets_manifest = load_json(assets_index_path)

	for asset in assets_manifest['objects'].values():
		hash = asset['hash']
		url = 'http://resources.download.minecraft.net/' + hash[:2] + '/' + hash
		asset_path = assets_path / 'objects' / hash[:2] / hash
		download_file(url, asset_path)

	command = ['java']

	for arg in manifest['arguments']['jvm']:
		if type(arg) is str:
			command.append(arg)
		elif type(arg) is dict:
			if 'rules' in arg:
				if check_rules(arg['rules']):
					append_flat(command, arg['value'])
		else:
			print('Unexpected JVM argument: {}'.format(arg))

	command.append(manifest['mainClass'])

	for arg in manifest['arguments']['game']:
		if type(arg) is str:
			command.append(arg)
		elif type(arg) is dict:
			if 'rules' in arg:
				if check_rules(arg['rules']):
					append_flat(command, arg['value'])
		else:
			print('Unexpected game argument: {}'.format(arg))

	natives_path = path / 'versions' / version_id / 'natives'

	if platform.system() == 'Windows':
		class_path = ';'.join(class_path)
	else:
		class_path = ':'.join(class_path)

	command = ' '.join(command)
	command = command.replace(r'${natives_directory}', str(natives_path))
	command = command.replace(r'${launcher_name}', 'mcdl')
	command = command.replace(r'${launcher_version}', '1.0')
	command = command.replace(r'${classpath}', class_path)
	command = command.replace(r'${auth_player_name}', player_name)
	command = command.replace(r'${version_name}', version_id)
	command = command.replace(r'${game_directory}', '.')
	command = command.replace(r'${assets_root}', 'assets')
	command = command.replace(r'${assets_index_name}', assets_version)
	command = command.replace(r'${auth_uuid}', str(uuid.uuid4()))
	command = command.replace(r'${auth_access_token}', '00000000000000000000000000000000')
	command = command.replace(r'${clientid}', '0000')
	command = command.replace(r'${auth_xuid}', '0000')
	command = command.replace(r'${user_type}', 'mojang')
	command = command.replace(r'${version_type}', manifest['type'])
	command = command.replace(r'Windows 10', '"Windows 10"')

	if platform.system() == 'Windows':
		bat_path = path / ('mc-' + version_id + '.bat')
		with open(str(bat_path), 'w') as f:
			f.write(command)
	else:
		sh_path = path / ('mc-' + version_id + '.sh')
		with open(str(sh_path), 'w') as f:
			f.write('#!/bin/sh\n')
			f.write(command)
		st = os.stat(str(sh_path))
		os.chmod(str(sh_path), st.st_mode | stat.S_IEXEC)

def get_versions_manifest():
	url = 'https://launchermeta.mojang.com/mc/game/version_manifest.json'
	return request_json(url)

def get_version_manifest(version, versions_manifest=None):
	if versions_manifest is None:
		versions_manifest = get_versions_manifest()

	if version == 'release':
		version = versions_manifest['latest']['release']
	elif version == 'snapshot':
		version = versions_manifest['latest']['snapshot']

	version_info = None
	for info in versions_manifest['versions']:
		if info['id'] == version:
			version_info = info
			break
	if version_info is None:
		raise VersionException()

	return request_json(version_info['url'])

def request_json(url):
	return json.load(urllib.request.urlopen(url))

def load_json(path):
	with open(str(path)) as f:
		return json.load(f)

def download_file(url, path):
	if path.exists():
		return

	print('--> Downloading {}...'.format(url), flush=True)

	if not path.parent.exists():
		path.parent.mkdir(parents=True, exist_ok=True)

	urllib.request.urlretrieve(url, str(path))

def check_rules(rules):
	for rule in rules:
		if not check_rule(rule):
			return False
	return True

def check_rule(rule):
	match = False
	if 'os' in rule:
		if 'name' in rule['os']:
			current_os = platform.system()
			required_os = rule['os']['name']
			match = (current_os == 'Windows' and required_os == 'windows') or (current_os == 'Linux' and required_os == 'linux') or (current_os == 'Darwin' and required_os == 'osx')

	if rule['action'] == 'allow':
		return match
	else:
		return not match

def append_flat(l, val):
	if type(val) is list:
		l += val
	else:
		l.append(val)

class VersionException(Exception):
	pass

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='Download Minecraft client')
	parser.add_argument(
		'-v', '--version',
		type=str,
		default='release',
		help='game version, use "release", "snapshot" or specific version'
	)
	parser.add_argument('-n', '--name', type=str, default='Player', help='player name')
	parser.add_argument(
		'--list-versions',
		action='store_true',
		help='List available versions and exit'
	)

	args = parser.parse_args()

	if args.list_versions:
		list_versions()
		sys.exit(0)

	try:
		download(args.version, args.name)
	except VersionException:
		print('Unknown version: {}.'.format(args.version))
		print('Run "mcdl.py --list-versions" to see all available versions.')
		sys.exit(1)

