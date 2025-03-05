#!/usr/bin/env python3

import urllib.request
import configparser
import argparse
import pathlib
import json
import sys
import ipaddress
import base64
import gzip
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization


_version = '1.1'


def generate_publickey(privatekey: str) -> str:
    private_key_bytes = base64.b64decode(privatekey)
    private_key = X25519PrivateKey.from_private_bytes(private_key_bytes)
    public_key = private_key.public_key()
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    wgpublickey = base64.b64encode(public_key_bytes).decode('utf-8')
    return wgpublickey


def generate_privatekey() -> str:
    privatekey = X25519PrivateKey.generate()
    private_key_bytes = privatekey.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    wgprivatekey = base64.b64encode(private_key_bytes).decode('utf-8')
    return wgprivatekey


class Mullvad:
    def __init__(self, args):
        self._account_number = args.account_number
        self._output_dir = args.output_dir
        self._settings_file = args.settings_file
        self._wg_relay_port = args.wg_relay_port
        self._wg_relay_ipv6 = args.wg_relay_ipv6
        self._wg_dns = args.wg_dns
        self._wg_hijack_dns = args.wg_hijack_dns
        self._wg_multihop_server = args.wg_multihop_server
        self._webtoken = None
        self._filter = args.filter

        self._config = configparser.ConfigParser()
        self._settings_file = pathlib.Path(self._settings_file).expanduser()

    def run(self):
        multihop_server = False
        if self._wg_multihop_server:
            multihop_servers = self.filter(self.get_multihop_info(), self._wg_multihop_server)
            if len(multihop_servers) == 1:
                multihop_server = multihop_servers[0]
            elif len(multihop_servers) >= 1:
                print('Select one of the following multihop servers:')
                for server in multihop_servers:
                    print(f'{server["hostname"]}')
                sys.exit(1)
            else:
                print(f'No multihop-server matching hostname: {self._wg_multihop_server}')
                sys.exit(1)

        if self._settings_file.is_file():
            privatekey = self.get_privatekey()
        else:
            privatekey = generate_privatekey()
            self.save_privatekey(privatekey)

        publickey = generate_publickey(privatekey)
        device = self.get_device(publickey) or self.create_device(publickey)
        if device:
            self.create_wg_configs(device, privatekey, multihop_server)

    def get_privatekey(self) -> str:
        print(f'Reading settings from: {self._settings_file}')
        self._config.read(self._settings_file)
        try:
            return self._config.get('Interface', 'privatekey')
        except (configparser.NoOptionError, configparser.NoSectionError):
            print('Error: No private key found in settings file')
            print('Solution: add it or remove the file completely to generate a new device')
            sys.exit(1)

    def save_privatekey(self, privatekey) -> bool:
        self._settings_file.parent.mkdir(parents=True, exist_ok=True)
        self._settings_file.touch(mode=0o600, exist_ok=True)
        with self._settings_file.open('w') as _file:
            print(f'Writing settings to: {self._settings_file}')
            self._config.add_section('Interface')
            self._config.set('Interface', 'privatekey', privatekey)
            self._config.write(_file)
        return True

    def get_webtoken(self) -> str:
        if not self._webtoken:
            self.generate_webtoken()
        return self._webtoken

    def generate_webtoken(self) -> str:
        body = {
            'account_number': self._account_number,
        }
        req = urllib.request.Request('https://api.mullvad.net/auth/v1/webtoken')
        req.add_header('Content-Type', 'application/json')
        with urllib.request.urlopen(req, json.dumps(body).encode()) as response:
            data = json.load(response)
        self._webtoken = data['access_token']

    def api(self, url, body=None):
        webtoken = self.get_webtoken()
        req = urllib.request.Request(url)
        req.add_header('Authorization', f'Bearer {webtoken}')
        req.add_header('Accept-Encoding', 'gzip')

        if body:
            req.add_header('Content-Type', 'application/json')

        with urllib.request.urlopen(req, data=json.dumps(body).encode() if body else None) as response:
            return self.get_response(response)

    def get_response(self, response):
        if response.headers.get('Content-Encoding') == 'gzip':
            data = json.loads(gzip.decompress(response.read()))
        else:
            data = json.load(response)
        return data

    def get_device(self, publickey):
        print(f'Trying to find device: {publickey}')
        try:
            for device in self.api('https://api.mullvad.net/accounts/v1/devices'):
                if publickey == device['pubkey']:
                    _name = device['name']
                    _pubkey = device['pubkey']
                    print(f'Device found: ({_name}) {_pubkey}')
                    return device
            print(f'Device is not registered: {publickey}')
            return None
        except urllib.error.HTTPError as e:
            error_message = json.load(e)
            _code = error_message.get('code')
            _message = error_message.get('detail')
            if _message:
                print(_message)
            if _code == 'INVALID_ACCOUNT':
                print(f'Invalid account: {self._account_number}')
            sys.exit(1)

    def create_device(self, publickey):
        print(f'Trying to create device: {publickey}')
        body = {
            'pubkey': publickey,
            'hijack_dns': self._wg_hijack_dns,
        }
        try:
            response = self.api('https://api.mullvad.net/accounts/v1/devices', body)
            print(f'Device created: ({response["name"]}) {response["pubkey"]}')
            return response
        except urllib.error.HTTPError as e:
            error_message = json.load(e)
            _code = error_message.get('code')
            _message = error_message.get('detail')
            if _message:
                print(_message)
            if _code == 'PUBKEY_IN_USE':
                print(f'Error: Private key settings exits in {self._settings_file} but device has been removed')
                print('Solution 1: Wait for grace period to pass before using this key (5 min)')
                print('Solution 2: Remove setting file if you want to create a new device')
            sys.exit(1)

    def get_wireguard_info(self):
        try:
            req = urllib.request.Request('https://api.mullvad.net/public/relays/wireguard/v2/')
            req.add_header('Accept-Encoding', 'gzip')
            with urllib.request.urlopen(req) as response:
                data = self.get_response(response)
            return data['wireguard']
        except urllib.error.HTTPError as e:
            error_message = self.get_response(e)
            print(error_message)
            sys.exit(1)

    def get_multihop_info(self):
        try:
            req = urllib.request.Request('https://api.mullvad.net/www/relays/all')
            req.add_header('Accept-Encoding', 'gzip')
            with urllib.request.urlopen(req) as response:
                data = self.get_response(response)
            return [i for i in data if i['type'] == 'wireguard']
        except urllib.error.HTTPError as e:
            error_message = self.get_response(e)
            print(error_message)
            sys.exit(1)

    def filter(self, data: list, _filter) -> list:
        if _filter:
            return [d for d in data if d['hostname'].startswith(_filter)]
        return data

    def create_wg_configs(self, device, privatekey, multihop_server) -> None:
        wg = self.get_wireguard_info()
        output_dir = pathlib.Path(self._output_dir).expanduser()
        output_dir.mkdir(exist_ok=True, parents=True)
        config = configparser.ConfigParser()
        config.add_section('Interface')
        config.set('Interface', '#device', device['name'])
        config.set('Interface', 'privateKey', privatekey)
        config.set('Interface', 'address',  ','.join([device['ipv4_address'], device['ipv6_address']]))
        if self._wg_dns:
            config.set('Interface', 'dns', ','.join([str(x) for x in self._wg_dns]))
        else:
            config.set('Interface', 'dns', ','.join([wg['ipv4_gateway'], wg['ipv6_gateway']]))
        config.add_section('Peer')

        relays = self.filter(self.get_multihop_info(), self._filter)
        if not relays:
            print(f'No relays matching filter: {self._filter}')
            return

        print(f'Creating files in: {output_dir}')
        for relay in relays:
            self.create_wg_config(config, relay, multihop_server)

    def create_wg_config(self, config, relay, multihop_server=None) -> None:
        output_dir = pathlib.Path(self._output_dir).expanduser()
        _hostname = relay['hostname']
        if multihop_server:
            _servername = multihop_server['hostname']
            _filepath = pathlib.Path.joinpath(output_dir, f'{_hostname}-via-{_servername}.conf')
        else:
            _filepath = pathlib.Path.joinpath(output_dir, f'{_hostname}.conf')

        _filepath.touch(mode=0o600, exist_ok=True)

        if multihop_server:
            remote_server = multihop_server
            remote_port = relay['multihop_port']
        else:
            remote_server = relay
            remote_port = self._wg_relay_port

        if self._wg_relay_ipv6:
            wg_relay_address = remote_server['ipv6_addr_in']
        else:
            wg_relay_address = remote_server['ipv4_addr_in']

        with _filepath.open('w') as _file:
            config.set('Peer', '#owned', str(relay['owned']))
            config.set('Peer', '#provider', relay['provider'])
            config.set('Peer', 'publickey', relay['pubkey'])
            config.set('Peer', 'allowedips', '0.0.0.0/0,::/0')
            config.set('Peer', 'endpoint', f'{wg_relay_address}:{remote_port}')
            config.write(_file)


def validate_account(value: str) -> str:
    if not value.isdigit():
        raise argparse.ArgumentTypeError('The string must contain only numbers.')
    return value


def validate_port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as e:
        raise argparse.ArgumentTypeError(f'Port must be an integer, but got \'{value}\'.') from e

    if port < 1 or port > 65535:
        raise argparse.ArgumentTypeError('Port number must be between 1 and 65535.')
    return port


def main():
    parser = argparse.ArgumentParser(
            description=f'{__file__}',
            formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    required = parser.add_argument_group('required arguments')
    required.add_argument(
            '--account', dest='account_number', type=validate_account,
            action='store', required=True, help='mullvad account number')

    parser.add_argument(
        '--settings-file', dest='settings_file', action='store',
        default='~/.config/mullvad/wg0.conf', help='settings file to use')
    parser.add_argument(
        '--output-dir', dest='output_dir', action='store',
        default='~/.config/mullvad/wg0', help='directory to write settings')
    parser.add_argument(
        '--wg-relay-port', dest='wg_relay_port', action='store', type=validate_port,
        default=51820, help='use custom port for relays in WireGuard configs')
    parser.add_argument(
        '--dns', dest='wg_dns', action='store', nargs='+', type=ipaddress.ip_address,
        help='use custom dns server in WireGuard configs')
    parser.add_argument(
        '--hijack-dns', dest='wg_hijack_dns', help='activate hijack dns when creating device', action='store_true')
    parser.add_argument(
        '--ipv6', dest='wg_relay_ipv6', help='use ipv6 address for relays in WireGuard configs', action='store_true')
    parser.add_argument(
        '--multihop-server', dest='wg_multihop_server', action='store', default=None, help='use multihop server')
    parser.add_argument(
        '--filter', action='store', default=None,
        help='filter relay list before creating configuration files')
    parser.add_argument(
        '--version', help='show version information', action='version', version=f'%(prog)s-{_version}')

    args = parser.parse_args()

    try:
        mullvad = Mullvad(args)
        mullvad.run()
    except Exception as e:
        print('Error:', e)
        sys.exit(1)


if __name__ == '__main__':
    main()
