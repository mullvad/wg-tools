#!/usr/bin/env python3

import argparse
import base64
import configparser
import functools
import gzip
import ipaddress
import json
import pathlib
import sys
import urllib.request

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


_version = '1.1.3'


def generate_publickey(privatekey: str) -> str:
    private_key_bytes = base64.b64decode(privatekey)
    private_key = X25519PrivateKey.from_private_bytes(private_key_bytes)
    public_key = private_key.public_key()
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(public_key_bytes).decode('utf-8')


def generate_privatekey() -> str:
    private_key = X25519PrivateKey.generate()
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return base64.b64encode(private_key_bytes).decode('utf-8')


class MullvadApi:
    HOST = 'https://api.mullvad.net'

    def __init__(self, account_number):
        self.account_number = account_number

    def new_device(self, public_key, hijack_dns):
        body = {
            'pubkey': public_key,
            'hijack_dns': hijack_dns,
        }

        return self._api(f'{MullvadApi.HOST}/accounts/v1/devices', body)

    def list_devices(self):
        return self._api(f'{MullvadApi.HOST}/accounts/v1/devices')

    @functools.cached_property
    def web_token(self) -> str:
        body = {
            'account_number': self.account_number,
        }
        req = urllib.request.Request(f'{MullvadApi.HOST}/auth/v1/webtoken')
        req.add_header('Content-Type', 'application/json')
        with urllib.request.urlopen(req, json.dumps(body).encode()) as response:
            data = json.load(response)
        return data['access_token']

    def _api(self, url, body=None):
        req = urllib.request.Request(url)
        req.add_header('Authorization', f'Bearer {self.web_token}')
        req.add_header('Accept-Encoding', 'gzip')

        if body:
            req.add_header('Content-Type', 'application/json')

        with urllib.request.urlopen(req, data=json.dumps(body).encode() if body else None) as response:
            return self.get_response(response)

    @staticmethod
    def default_dns_servers() -> str:
        return '10.64.0.1,fc00:bbbb:bbbb:bb01::1'

    @functools.cache
    @staticmethod
    def all_wireguard_relays():
        req = urllib.request.Request(f'{MullvadApi.HOST}/www/relays/all')
        req.add_header('Accept-Encoding', 'gzip')
        with urllib.request.urlopen(req) as response:
            data = MullvadApi.get_response(response)
        return [i for i in data if i['type'] == 'wireguard']

    @staticmethod
    def wireguard_relays(**kwargs):
        relays = MullvadApi.all_wireguard_relays()

        location_prefix = kwargs.get('location_prefix', '')
        if location_prefix:
            relays = [r for r in relays if r['hostname'].startswith(location_prefix)]

        active = kwargs.get('active', False)
        if active:
            relays = [r for r in relays if r['active']]

        owned = kwargs.get('owned', False)
        if owned:
            relays = [r for r in relays if r['owned']]

        st_boot = kwargs.get('stboot', False)
        if st_boot:
            relays = [r for r in relays if r.get('stboot', False)]

        min_network_port_speed = kwargs.get('min_network_port_speed', 0)
        relays = [r for r in relays if r['network_port_speed'] >= min_network_port_speed]

        return relays

    @staticmethod
    def get_response(response):
        if response.headers.get('Content-Encoding') == 'gzip':
            return json.loads(gzip.decompress(response.read()))
        else:
            return json.load(response)


class MullvadConfig:
    def __init__(self, output_dir, wg_dns, wg_relay_port, wg_relay_ipv6):
        self.output_dir = output_dir
        self.wg_dns = wg_dns
        self.wg_relay_port = wg_relay_port
        self.wg_relay_ipv6 = wg_relay_ipv6

    def create_wg_configs(self, relays, device, privatekey, multihop_server) -> None:
        output_dir = pathlib.Path(self.output_dir).expanduser()
        output_dir.mkdir(exist_ok=True, parents=True)
        config = configparser.ConfigParser()
        config.add_section('Interface')
        config.set('Interface', '#device', device['name'])
        config.set('Interface', 'privateKey', privatekey)
        config.set('Interface', 'address', ','.join([device['ipv4_address'], device['ipv6_address']]))
        if self.wg_dns:
            config.set('Interface', 'dns', ','.join([str(x) for x in self.wg_dns]))
        else:
            config.set('Interface', 'dns', MullvadApi.default_dns_servers())
        config.add_section('Peer')

        print(f'Creating files in: {output_dir}')
        for relay in relays:
            self.create_wg_config(config, relay, multihop_server)

    def create_wg_config(self, config, relay, multihop_server=None) -> None:
        output_dir = pathlib.Path(self.output_dir).expanduser()
        hostname = relay['hostname']
        if multihop_server:
            server_name = multihop_server['hostname']
            file_path = pathlib.Path.joinpath(output_dir, f'{hostname}-via-{server_name}.conf')
        else:
            file_path = pathlib.Path.joinpath(output_dir, f'{hostname}.conf')

        file_path.touch(mode=0o600, exist_ok=True)

        if multihop_server:
            remote_server = multihop_server
            remote_port = relay['multihop_port']
        else:
            remote_server = relay
            remote_port = self.wg_relay_port

        if self.wg_relay_ipv6:
            wg_relay_address = remote_server['ipv6_addr_in']
        else:
            wg_relay_address = remote_server['ipv4_addr_in']

        with file_path.open('w') as _file:
            config.set('Peer', '#owned', str(relay['owned']))
            config.set('Peer', '#provider', relay['provider'])
            config.set('Peer', 'publickey', relay['pubkey'])
            config.set('Peer', 'allowedips', '0.0.0.0/0,::/0')
            config.set('Peer', 'endpoint', f'{wg_relay_address}:{remote_port}')
            config.write(_file)


class Mullvad:
    def __init__(self, args):
        self.mullvad_api = MullvadApi(args.account_number)
        self.mullvad_config = MullvadConfig(args.output_dir, args.wg_dns, args.wg_relay_port, args.wg_relay_ipv6)

        self._settings_file = args.settings_file
        self._wg_hijack_dns = args.wg_hijack_dns
        self._wg_multihop_server = args.wg_multihop_server
        self._wg_relays_filter = {
            'location_prefix': args.filter,
            'active': args.wg_active,
            'owned': args.wg_owned,
            'stboot': args.wg_stboot,
            'min_network_port_speed': args.wg_min_network_port_speed,
        }

        self._config = configparser.ConfigParser()
        self._settings_file = pathlib.Path(self._settings_file).expanduser()

    def run(self):
        private_key, public_key = self.get_key_pair()
        device = self.get_device(public_key) or self.create_device(public_key)
        if device:
            multihop_server = self.get_multihop_server()
            relays = self.get_relays()
            self.mullvad_config.create_wg_configs(relays, device, private_key, multihop_server)

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

    def get_device(self, publickey):
        print(f'Trying to find device: {publickey}')
        try:
            for device in self.mullvad_api.list_devices():
                if publickey == device['pubkey']:
                    name = device['name']
                    pubkey = device['pubkey']
                    print(f'Device found: ({name}) {pubkey}')
                    return device
            print(f'Device is not registered: {publickey}')
            return None
        except urllib.error.HTTPError as e:
            self.handle_mullvad_api_error(e)

    def create_device(self, publickey):
        print(f'Trying to create device: {publickey}')
        try:
            response = self.mullvad_api.new_device(publickey, self._wg_hijack_dns)
            print(f'Device created: ({response["name"]}) {response["pubkey"]}')
            return response
        except urllib.error.HTTPError as e:
            self.handle_mullvad_api_error(e)

    def get_key_pair(self):
        if self._settings_file.is_file():
            private_key = self.get_privatekey()
        else:
            private_key = generate_privatekey()
            self.save_privatekey(private_key)

        public_key = generate_publickey(private_key)
        return (private_key, public_key)

    def get_multihop_server(self):
        if not self._wg_multihop_server:
            return None

        multihop_servers = [r for r in MullvadApi.all_wireguard_relays() if r['hostname'] == self._wg_multihop_server]
        if len(multihop_servers) == 1:
            return multihop_servers[0]
        elif len(multihop_servers) >= 1:
            print('Select one of the following multihop servers:')
            for server in multihop_servers:
                print(f'{server["hostname"]}')
            sys.exit(1)
        else:
            print(f'No multihop-server matching hostname: {self._wg_multihop_server}')
            sys.exit(1)

    def get_relays(self):
        relays = MullvadApi.wireguard_relays(**self._wg_relays_filter)
        if not relays:
            print('No relays matching your settings.')
            sys.exit(1)
        return relays

    def handle_mullvad_api_error(self, err):
        error_message = MullvadApi.get_response(err)
        error_code = error_message.get('code')
        detail_message = error_message.get('detail')
        if detail_message:
            print(detail_message)
        if error_code == 'PUBKEY_IN_USE':
            print(f'Private key settings exits in {self._settings_file} but device has been removed')
            print('Solution 1: Wait for grace period to pass before using this key (5 min)')
            print('Solution 2: Remove setting file if you want to create a new device')
        elif error_code == 'INVALID_ACCOUNT':
            print(f'Invalid account number: {self.mullvad_api.account_number}')
        sys.exit(1)


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

    # WireGuard relay(s) selection related parameters
    parser.add_argument(
        '--filter', action='store', default=None,
        help='filter relay list before creating configuration files')
    parser.add_argument(
        '--active', dest='wg_active', help='only select active Mullvad WireGuard relay(s)',
        action='store_true')
    parser.add_argument(
        '--owned', dest='wg_owned', help='only select Mullvad owned WireGuard relay(s)', action='store_true')
    parser.add_argument(
        '--stboot', dest='wg_stboot',
        help='only select system transparency (stboot/diskless) enabled Mullvad WireGuard relay(s)',
        action='store_true')
    parser.add_argument(
        '--min-network-port-speed', dest='wg_min_network_port_speed',
        help='only select Mullvad WireGuard relays having network speed (in Gbps) >= this number',
        action='store', type=int, default=0)

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
