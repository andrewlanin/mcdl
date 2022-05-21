#!/usr/bin/env python3
import argparse, hashlib, json, os, pathlib, platform, urllib.request, uuid, stat, sys

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

	downloads = []
	class_path = []

	client_url = manifest['downloads']['client']['url']
	client_path = path / 'versions' / version_id / (version_id + '.jar')
	chient_sha1 = manifest['downloads']['client']['sha1']
	class_path.append(str(client_path))
	if not verify_file(client_path, chient_sha1):
		downloads.append({
			'url': client_url,
			'path': client_path,
			'sha1': chient_sha1
		})

	libs_path = path / 'libraries'
	for lib_info in manifest['libraries']:
		if 'rules' in lib_info:
			if not check_rules(lib_info['rules']):
				continue

		lib_url = lib_info['downloads']['artifact']['url']
		lib_path = libs_path / lib_info['downloads']['artifact']['path']
		lib_sha1 = lib_info['downloads']['artifact']['sha1']
		class_path.append(str(lib_path))
		if not verify_file(lib_path, lib_sha1):
			downloads.append({
				'url': lib_url,
				'path': lib_path,
				'sha1': lib_sha1
			})

	assets_path = path / 'assets'
	assets_version = manifest['assetIndex']['id']
	assets_index_path = assets_path / 'indexes' / (assets_version + '.json')
	download_file(manifest['assetIndex']['url'], assets_index_path)
	assets_manifest = load_json_file(assets_index_path)

	for asset in assets_manifest['objects'].values():
		asset_sha1 = asset['hash']
		asset_url = 'http://resources.download.minecraft.net/' + asset_sha1[:2] + '/' + asset_sha1
		asset_path = assets_path / 'objects' / asset_sha1[:2] / asset_sha1
		if not verify_file(asset_path, asset_sha1):
			downloads.append({
				'url': asset_url,
				'path': asset_path,
				'sha1': asset_sha1
			})

	download_files(downloads)

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
		raise VersionException(version)

	return request_json(version_info['url'])

def request_json(url):
	return json.load(urllib.request.urlopen(url))

def load_json_file(path):
	with open(str(path)) as f:
		return json.load(f)

def download_files(downloads):
	total = len(downloads)
	if total == 0:
		print('Everything is up-to-date')
		return

	for i, download in enumerate(downloads):
		idx = i + 1
		url = download['url']
		path = download['path']
		sha1 = download['sha1']

		retries = 5
		while retries > 0:
			print('[{}/{}] Downloading {}...'.format(idx, total, url), flush=True)
			download_file(url, path)
			if verify_file(path, sha1):
				break
			else:
				print('[{}/{}] Invalid hash, retrying...'.format(idx, total))
				retries -= 1

		if retries == 0:
			raise VerificationException(url, path, sha1, calc_file_sha1(path))

def download_file(url, path):
	if path.exists():
		return

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
