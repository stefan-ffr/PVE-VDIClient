#!/usr/bin/env python3
"""
Proxmox VDI Client - Native Desktop Application
A Flask + pywebview client for Proxmox VE Virtual Desktop Infrastructure.
Compatible with PVE 7, 8, and 9.
"""

import os
import sys
import json
import random
import subprocess
import argparse
import urllib3
from configparser import ConfigParser
from io import StringIO
from time import sleep
from threading import Thread

import webview

from flask import (
    Flask, render_template, request, redirect,
    url_for, jsonify, flash, send_file
)
import proxmoxer
import requests

app = Flask(__name__)
app.secret_key = os.urandom(32)


class G:
    """Global application state."""
    spiceproxy_conv = {}
    proxmox = None
    icon = None
    vvcmd = None
    inidebug = False
    addl_params = None
    imagefile = None
    kiosk = False
    viewer_kiosk = True
    fullscreen = True
    show_reset = False
    show_hibernate = False
    current_hostset = 'DEFAULT'
    title = 'VDI Login'
    hosts = {}
    theme = 'LightBlue'
    guest_type = 'both'
    width = None
    height = None
    authenticated = False


def loadconfig(config_location=None, config_type='file',
               config_username=None, config_password=None, ssl_verify=True):
    """Load configuration from file or HTTP source."""
    config = ConfigParser(delimiters='=')

    if config_type == 'file':
        if config_location:
            if not os.path.isfile(config_location):
                print(f'Error: Configuration file not found: {config_location}')
                return False
        else:
            if os.name == 'nt':
                config_list = [
                    f'{os.getenv("APPDATA")}\\VDIClient\\vdiclient.ini',
                    f'{os.getenv("PROGRAMFILES")}\\VDIClient\\vdiclient.ini',
                    f'{os.getenv("PROGRAMFILES(x86)")}\\VDIClient\\vdiclient.ini',
                    'C:\\Program Files\\VDIClient\\vdiclient.ini'
                ]
            elif os.name == 'posix':
                config_list = [
                    os.path.expanduser('~/.config/VDIClient/vdiclient.ini'),
                    '/etc/vdiclient/vdiclient.ini',
                    '/usr/local/etc/vdiclient/vdiclient.ini'
                ]
            else:
                config_list = []
            for location in config_list:
                if os.path.exists(location):
                    config_location = location
                    break
            if not config_location:
                print('Error: No configuration file found in any default location!')
                return False
        try:
            config.read(config_location)
        except Exception as e:
            print(f'Error: Unable to read configuration file: {e!r}')
            return False

    elif config_type == 'http':
        if not config_location:
            print('Error: --config_type http requires --config_location URL!')
            return False
        try:
            if config_username and config_password:
                r = requests.get(url=config_location,
                                 auth=(config_username, config_password),
                                 verify=ssl_verify)
            else:
                r = requests.get(url=config_location, verify=ssl_verify)
            config.read_string(r.text)
        except Exception as e:
            print(f'Error: Unable to read configuration from URL: {e}')
            return False

    if 'General' not in config:
        print('Error: No [General] section defined in configuration!')
        return False

    general = config['General']
    if 'title' in general:
        G.title = general['title']
    if 'theme' in general:
        G.theme = general['theme']
    if 'icon' in general:
        if os.path.exists(general['icon']):
            G.icon = general['icon']
    if 'logo' in general:
        if os.path.exists(general['logo']):
            G.imagefile = general['logo']
    if 'kiosk' in general:
        G.kiosk = general.getboolean('kiosk')
    if 'viewer_kiosk' in general:
        G.viewer_kiosk = general.getboolean('viewer_kiosk')
    if 'fullscreen' in general:
        G.fullscreen = general.getboolean('fullscreen')
    if 'inidebug' in general:
        G.inidebug = general.getboolean('inidebug')
    if 'guest_type' in general:
        G.guest_type = general['guest_type']
    if 'show_reset' in general:
        G.show_reset = general.getboolean('show_reset')
    if 'window_width' in general:
        G.width = general.getint('window_width')
    if 'window_height' in general:
        G.height = general.getint('window_height')

    if 'Authentication' in config:  # Legacy configuration
        G.hosts['DEFAULT'] = _default_hostset()
        if 'Hosts' not in config:
            print('Error: No [Hosts] section defined!')
            return False
        for key in config['Hosts']:
            G.hosts['DEFAULT']['hostpool'].append({
                'host': key,
                'port': int(config['Hosts'][key])
            })
        auth = config['Authentication']
        _parse_host_options(G.hosts['DEFAULT'], auth)
    else:  # New style multi-cluster config
        i = 0
        for section in config.sections():
            if section.startswith('Hosts.'):
                _, group = section.split('.', 1)
                if i == 0:
                    G.current_hostset = group
                G.hosts[group] = _default_hostset()
                try:
                    hostjson = json.loads(config[section]['hostpool'])
                except Exception as e:
                    print(f'Error: Could not parse hostpool in [{section}]: {e!r}')
                    return False
                for key, value in hostjson.items():
                    G.hosts[group]['hostpool'].append({
                        'host': key,
                        'port': int(value)
                    })
                _parse_host_options(G.hosts[group], config[section])
                i += 1

    if 'SpiceProxyRedirect' in config:
        for key in config['SpiceProxyRedirect']:
            G.spiceproxy_conv[key] = config['SpiceProxyRedirect'][key]
    if 'AdditionalParameters' in config:
        G.addl_params = {}
        for key in config['AdditionalParameters']:
            G.addl_params[key] = config['AdditionalParameters'][key]
    return True


def _default_hostset():
    """Return a default host configuration dictionary."""
    return {
        'hostpool': [],
        'backend': 'pve',
        'user': '',
        'token_name': None,
        'token_value': None,
        'totp': False,
        'verify_ssl': True,
        'pwresetcmd': None,
        'auto_vmid': None,
        'knock_seq': []
    }


def _parse_host_options(hostset, section):
    """Parse host options from a config section into a hostset dict."""
    if 'auth_backend' in section:
        hostset['backend'] = section['auth_backend']
    if 'user' in section:
        hostset['user'] = section['user']
    if 'token_name' in section:
        hostset['token_name'] = section['token_name']
    if 'token_value' in section:
        hostset['token_value'] = section['token_value']
    if 'auth_totp' in section:
        hostset['totp'] = section.getboolean('auth_totp')
    if 'tls_verify' in section:
        hostset['verify_ssl'] = section.getboolean('tls_verify')
    if 'pwresetcmd' in section:
        hostset['pwresetcmd'] = section['pwresetcmd']
    if 'auto_vmid' in section:
        hostset['auto_vmid'] = section.getint('auto_vmid')
    if 'knock_seq' in section:
        try:
            hostset['knock_seq'] = json.loads(section['knock_seq'])
        except Exception as e:
            print(f'Warning: Knock sequence not valid JSON, skipping: {e!r}')


def setcmd():
    """Find the virt-viewer / remote-viewer command."""
    try:
        if os.name == 'nt':
            import csv
            cmd1 = 'ftype VirtViewer.vvfile'
            result = subprocess.check_output(cmd1, shell=True)
            cmdresult = result.decode('utf-8')
            cmdparts = cmdresult.split('=')
            for row in csv.reader([cmdparts[1]], delimiter=' ', quotechar='"'):
                G.vvcmd = row[0]
                break
        elif os.name == 'posix':
            subprocess.check_output('which remote-viewer', shell=True)
            G.vvcmd = 'remote-viewer'
    except subprocess.CalledProcessError:
        if os.name == 'nt':
            print('Error: virt-viewer missing! Install from https://virt-manager.org/download/')
        elif os.name == 'posix':
            print('Error: virt-viewer missing! Install with: apt install virt-viewer')
        sys.exit(1)


def pveauth(username, passwd=None, totp=None):
    """Authenticate against Proxmox VE. Returns (connected, authenticated, error)."""
    hostset = G.hosts[G.current_hostset]
    random.shuffle(hostset['hostpool'])
    err = None

    # Suppress InsecureRequestWarning when SSL verification is disabled
    if not hostset['verify_ssl']:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    for hostinfo in hostset['hostpool']:
        host = hostinfo['host']
        port = hostinfo.get('port', 8006)
        try:
            if hostset['token_name'] and hostset['token_value']:
                G.proxmox = proxmoxer.ProxmoxAPI(
                    host,
                    user=f"{username}@{hostset['backend']}",
                    token_name=hostset['token_name'],
                    token_value=hostset['token_value'],
                    verify_ssl=hostset['verify_ssl'],
                    port=port
                )
            elif totp:
                G.proxmox = proxmoxer.ProxmoxAPI(
                    host,
                    user=f"{username}@{hostset['backend']}",
                    otp=totp,
                    password=passwd,
                    verify_ssl=hostset['verify_ssl'],
                    port=port
                )
            else:
                G.proxmox = proxmoxer.ProxmoxAPI(
                    host,
                    user=f"{username}@{hostset['backend']}",
                    password=passwd,
                    verify_ssl=hostset['verify_ssl'],
                    port=port
                )
            return True, True, None
        except proxmoxer.backends.https.AuthenticationError as e:
            return True, False, e
        except (requests.exceptions.ReadTimeout,
                requests.exceptions.ConnectTimeout,
                requests.exceptions.ConnectionError) as e:
            err = e
    return False, False, err


def getvms(listonly=False):
    """Get list of VMs from Proxmox cluster."""
    vms = []
    try:
        online_nodes = []
        for node in G.proxmox.cluster.resources.get(type='node'):
            if node.get('status') == 'online':
                online_nodes.append(node['node'])

        for vm in G.proxmox.cluster.resources.get(type='vm'):
            if vm['node'] not in online_nodes:
                continue
            if vm.get('template'):
                continue
            if G.guest_type == 'both' or G.guest_type == vm['type']:
                if listonly:
                    vms.append({
                        'vmid': vm['vmid'],
                        'name': vm['name'],
                        'node': vm['node']
                    })
                else:
                    vms.append(vm)
        return vms
    except proxmoxer.core.ResourceException as e:
        print(f'Error getting VMs: {e!r}')
        return []
    except requests.exceptions.ConnectionError as e:
        print(f'Connection error querying Proxmox: {e!r}')
        return []


def process_vms(vms):
    """Process raw VM data into a clean format for the frontend."""
    processed = []
    for vm in vms:
        if vm.get('status') == 'unknown':
            continue
        state = 'stopped'
        disabled = False
        if vm.get('status') == 'running':
            if 'lock' in vm:
                state = vm['lock']
                if state in ('suspending', 'suspended'):
                    disabled = True
                    if state == 'suspended':
                        state = 'starting'
            else:
                state = 'running'
        processed.append({
            'vmid': vm['vmid'],
            'name': vm['name'],
            'node': vm['node'],
            'type': vm['type'],
            'state': state,
            'disabled': disabled
        })
    return processed


def vmaction(vmnode, vmid, vmtype, action='connect'):
    """Perform a VM action: connect or reload (reset)."""
    try:
        if vmtype == 'qemu':
            vmstatus = G.proxmox.nodes(vmnode).qemu(str(vmid)).status.get('current')
        else:
            vmstatus = G.proxmox.nodes(vmnode).lxc(str(vmid)).status.get('current')
    except Exception as e:
        return {'success': False, 'error': f'Unable to get VM status: {e!r}'}

    if action == 'reload':
        # Stop the VM
        try:
            if vmtype == 'qemu':
                jobid = G.proxmox.nodes(vmnode).qemu(str(vmid)).status.stop.post(timeout=28)
            else:
                jobid = G.proxmox.nodes(vmnode).lxc(str(vmid)).status.stop.post(timeout=28)
        except proxmoxer.core.ResourceException as e:
            return {'success': False, 'error': f'Unable to stop VM: {e!r}'}

        # Wait for stop to complete
        stopped = False
        for _ in range(30):
            try:
                jobstatus = G.proxmox.nodes(vmnode).tasks(jobid).status.get()
            except Exception:
                jobstatus = {}
            if 'exitstatus' in jobstatus:
                if jobstatus['exitstatus'] != 'OK':
                    return {'success': False, 'error': 'Unable to stop VM'}
                stopped = True
                break
            sleep(1)
        if not stopped:
            return {'success': False, 'error': 'Timeout waiting for VM to stop'}

    # Refresh status
    try:
        if vmtype == 'qemu':
            vmstatus = G.proxmox.nodes(vmnode).qemu(str(vmid)).status.get('current')
        else:
            vmstatus = G.proxmox.nodes(vmnode).lxc(str(vmid)).status.get('current')
    except Exception as e:
        return {'success': False, 'error': f'Unable to get VM status: {e!r}'}

    # Start VM if not running
    if vmstatus['status'] != 'running':
        try:
            if vmtype == 'qemu':
                jobid = G.proxmox.nodes(vmnode).qemu(str(vmid)).status.start.post(timeout=28)
            else:
                jobid = G.proxmox.nodes(vmnode).lxc(str(vmid)).status.start.post(timeout=28)
        except proxmoxer.core.ResourceException as e:
            return {'success': False, 'error': f'Unable to start VM: {e!r}'}

        started = False
        for _ in range(30):
            try:
                jobstatus = G.proxmox.nodes(vmnode).tasks(jobid).status.get()
            except Exception:
                jobstatus = {}
            if 'exitstatus' in jobstatus:
                if jobstatus['exitstatus'] != 'OK':
                    return {'success': False, 'error': 'Unable to start VM'}
                started = True
                break
            sleep(1)
        if not started:
            return {'success': False, 'error': 'Timeout waiting for VM to start'}

    if action == 'reload':
        return {'success': True, 'message': f'{vmstatus["name"]} reset successfully'}

    # Connect via SPICE
    try:
        if vmtype == 'qemu':
            spiceconfig = G.proxmox.nodes(vmnode).qemu(str(vmid)).spiceproxy.post()
        else:
            spiceconfig = G.proxmox.nodes(vmnode).lxc(str(vmid)).spiceproxy.post()
    except proxmoxer.core.ResourceException as e:
        return {
            'success': False,
            'error': f'Unable to connect to VM {vmid}: {e!r}\nIs SPICE display configured?'
        }

    # Build virt-viewer configuration
    confignode = ConfigParser()
    confignode['virt-viewer'] = {}
    for key, value in spiceconfig.items():
        if key == 'proxy':
            val = value[7:].lower()
            if val in G.spiceproxy_conv:
                confignode['virt-viewer'][key] = f'http://{G.spiceproxy_conv[val]}'
            else:
                confignode['virt-viewer'][key] = f'{value}'
        else:
            confignode['virt-viewer'][key] = f'{value}'

    if G.addl_params:
        for key, value in G.addl_params.items():
            confignode['virt-viewer'][key] = f'{value}'

    inifile = StringIO('')
    confignode.write(inifile)
    inifile.seek(0)
    inistring = inifile.read()

    if G.inidebug:
        print(f'SPICE Config:\n{inistring}')

    # Launch virt-viewer
    pcmd = [G.vvcmd]
    if G.kiosk and G.viewer_kiosk:
        pcmd.extend(['--kiosk', '--kiosk-quit', 'on-disconnect'])
    elif G.fullscreen:
        pcmd.append('--full-screen')
    pcmd.append('-')

    process = subprocess.Popen(pcmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    try:
        process.communicate(input=inistring.encode('utf-8'), timeout=5)
    except subprocess.TimeoutExpired:
        pass

    return {'success': True, 'message': f'Connected to {vmstatus["name"]}'}


# ---------------------------------------------------------------------------
# Flask Routes
# ---------------------------------------------------------------------------

@app.route('/')
def index():
    if G.authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    groups = list(G.hosts.keys())
    hostset = G.hosts[G.current_hostset]

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        totp = request.form.get('totp', '').strip() or None

        connected, authenticated, error = pveauth(
            username, passwd=password, totp=totp
        )

        if not connected:
            flash(
                f'Unable to connect to any VDI server. '
                f'Are you connected to the network? Error: {error}',
                'error'
            )
        elif not authenticated:
            flash('Invalid username and/or password, please try again!', 'error')
        else:
            G.authenticated = True
            if hostset.get('auto_vmid'):
                vms = getvms()
                for vm in vms:
                    if vm['vmid'] == hostset['auto_vmid']:
                        vmaction(vm['node'], vm['vmid'], vm['type'])
                        return redirect(url_for('dashboard'))
                flash(
                    f"No VDI instance with ID {hostset['auto_vmid']} found!",
                    'warning'
                )
            return redirect(url_for('dashboard'))

    return render_template(
        'login.html',
        title=G.title,
        groups=groups,
        current_group=G.current_hostset,
        show_groups=len(groups) > 1,
        show_totp=hostset['totp'],
        show_pwreset=hostset.get('pwresetcmd') is not None,
        default_user=hostset['user'],
        has_token=bool(hostset.get('token_name') and hostset.get('token_value')),
        has_logo=G.imagefile is not None,
        kiosk=G.kiosk
    )


@app.route('/dashboard')
def dashboard():
    if not G.authenticated:
        return redirect(url_for('login'))
    vms = process_vms(getvms())
    return render_template(
        'dashboard.html',
        title=G.title,
        vms=vms,
        show_reset=G.show_reset,
        show_hibernate=G.show_hibernate,
        has_logo=G.imagefile is not None,
        kiosk=G.kiosk,
        vm_count=len(vms)
    )


@app.route('/api/vms')
def api_vms():
    if not G.authenticated:
        return jsonify({'error': 'Not authenticated'}), 401
    return jsonify(process_vms(getvms()))


@app.route('/vm/<int:vmid>/connect', methods=['POST'])
def connect_vm(vmid):
    if not G.authenticated:
        return jsonify({'error': 'Not authenticated'}), 401
    vms = getvms()
    for vm in vms:
        if vm['vmid'] == vmid:
            result = vmaction(vm['node'], vmid, vm['type'], action='connect')
            return jsonify(result)
    return jsonify({'success': False, 'error': f'VM {vmid} not found'}), 404


@app.route('/vm/<int:vmid>/reset', methods=['POST'])
def reset_vm(vmid):
    if not G.authenticated:
        return jsonify({'error': 'Not authenticated'}), 401
    vms = getvms()
    for vm in vms:
        if vm['vmid'] == vmid:
            result = vmaction(vm['node'], vmid, vm['type'], action='reload')
            return jsonify(result)
    return jsonify({'success': False, 'error': f'VM {vmid} not found'}), 404


@app.route('/switch-group')
def switch_group():
    group = request.args.get('group', G.current_hostset)
    if group in G.hosts:
        G.current_hostset = group
        G.authenticated = False
        G.proxmox = None
    return redirect(url_for('login'))


@app.route('/logout')
def logout():
    G.authenticated = False
    G.proxmox = None
    return redirect(url_for('login'))


@app.route('/logo')
def serve_logo():
    if G.imagefile and os.path.exists(G.imagefile):
        return send_file(os.path.abspath(G.imagefile))
    return '', 404


@app.route('/password-reset', methods=['POST'])
def password_reset():
    cmd = G.hosts[G.current_hostset].get('pwresetcmd')
    if cmd:
        try:
            subprocess.Popen(cmd, shell=True)
            flash('Password reset launched successfully.', 'success')
        except Exception as e:
            flash(f'Unable to open password reset: {e}', 'error')
    return redirect(url_for('login'))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description='Proxmox VDI Client')
    parser.add_argument('--config_type', choices=['file', 'http'], default='file',
                        help='Config source type (default: file)')
    parser.add_argument('--config_location', default=None,
                        help='Config file path or HTTP URL')
    parser.add_argument('--config_username', default=None,
                        help='HTTP basic auth username')
    parser.add_argument('--config_password', default=None,
                        help='HTTP basic auth password')
    parser.add_argument('--ignore_ssl', action='store_false', default=True,
                        help='Ignore SSL certificate errors for config download')
    parser.add_argument('--port', type=int, default=5000,
                        help='Web server port (default: 5000)')
    parser.add_argument('--host', default='127.0.0.1',
                        help='Web server bind address (default: 127.0.0.1)')
    args = parser.parse_args()

    setcmd()

    if not loadconfig(
        config_location=args.config_location,
        config_type=args.config_type,
        config_username=args.config_username,
        config_password=args.config_password,
        ssl_verify=args.ignore_ssl
    ):
        return 1

    # Auto-login with API token (single cluster only)
    hostset = G.hosts[G.current_hostset]
    if (hostset['user'] and hostset['token_name']
            and hostset['token_value'] and len(G.hosts) == 1):
        print('Auto-authenticating with API token...')
        connected, authenticated, error = pveauth(hostset['user'])
        if connected and authenticated:
            G.authenticated = True
            print('Authentication successful.')
        else:
            print(f'Auto-authentication failed: {error}')

    # Start Flask in background thread
    url = f'http://{args.host}:{args.port}'
    Thread(
        target=lambda: app.run(host=args.host, port=args.port, debug=False, threaded=True),
        daemon=True
    ).start()

    # Wait for Flask to be ready before opening the window
    import socket
    for _ in range(50):
        try:
            with socket.create_connection((args.host, args.port), timeout=0.1):
                break
        except OSError:
            sleep(0.1)

    # Launch native desktop window with pywebview
    window = webview.create_window(
        G.title,
        url,
        width=G.width or 900,
        height=G.height or 700
    )
    webview.start()
    return 0


if __name__ == '__main__':
    sys.exit(main())
