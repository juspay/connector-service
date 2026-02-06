#!/usr/bin/env python3

import subprocess
import shutil
import os
import sys
import yaml
from pathlib import Path

def check_docker():
    return shutil.which("docker") is not None or shutil.which("orbctl") is not None

def generate_api_key():
    return "searxng-key"

def create_settings_yml(api_key):
    settings = {
        'use_default_settings': True,
        'general': {
            'debug': False,
            'instance_name': 'GRACE Research SearxNG',
            'contact_url': False,
            'enable_metrics': False
        },
        'search': {
            'safe_search': 0,
            'default_lang': 'en',
            'formats': ['html', 'json', 'rss'],
            'default_https': True,
            'autocomplete': ''
        },
        'server': {
            'port': 8080,
            'bind_address': '0.0.0.0',
            'secret_key': api_key,
            'limiter': False,
            'public_instance': False,
            'method': 'GET',
            'http_protocol_version': '1.1'
        },
        'ui': {
            'static_use_hash': True,
            'default_theme': 'simple',
            'query_in_title': False,
            'infinite_scroll': False,
            'center_alignment': False
        },
        'outgoing': {
            'request_timeout': 5.0,
            'useragent_suffix': 'GRACEE',
            'max_request_timeout': 10.0
        },
        'enabled_plugins': [
            'HTTPS rewrite',
            'Self Information',
            'Tracker URL remover'
        ],
        'engines': [
            {
                'name': 'google',
                'engine': 'google',
                'shortcut': 'g',
                'use_mobile_ui': False
            },
            {
                'name': 'bing',
                'engine': 'bing',
                'shortcut': 'b'
            },
            {
                'name': 'duckduckgo',
                'engine': 'duckduckgo',
                'shortcut': 'ddg'
            }
        ],
        'disabled_engines': [
            'wikidata',
            'mediawiki',
            'openstreetmap',
            'brave',
            'startpage'
        ]
    }
    return yaml.dump(settings, default_flow_style=False)

def setup_docker():
    api_key = generate_api_key()
    settings_content = create_settings_yml(api_key)

    script_dir = Path(__file__).parent.absolute()
    grace_config_dir = script_dir / '../../.grace' / 'searxng-config'
    settings_file = grace_config_dir / 'settings.yml'
    
    grace_config_dir.mkdir(parents=True, exist_ok=True)
    settings_file.write_text(settings_content)
    
    try:
        subprocess.run(['docker', 'rm', '-f', 'grace-searxng'], capture_output=True)
        
        result = subprocess.run(['docker', 'pull', 'searxng/searxng'], capture_output=True, text=True)
        if result.returncode != 0:
            print("Failed to pull searxng/searxng, trying paulgoio/searxng...")
            subprocess.run(['docker', 'pull', 'paulgoio/searxng'], check=True, capture_output=True)
            image = 'paulgoio/searxng'
        else:
            image = 'searxng/searxng'
        
        result = subprocess.run([
            'docker', 'run', '-d', 
            '--name', 'grace-searxng',
            '-p', '32768:8080',
            '-v', f'{settings_file}:/etc/searxng/settings.yml:ro',
            image
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"SearXNG running on http://localhost:32768")
            print(f"API Endpoint: http://localhost:32768/search?q=monei&format=json")
        else:
            print(f"Docker run failed: {result.stderr}")
            setup_local()
        
    except subprocess.CalledProcessError as e:
        print(f"Docker setup failed")
        setup_local()

def setup_local():
    response = input("Install SearXNG locally [Not recommended, it may fail] ? (y/n): ")
    if response.lower() != 'y':
        print("SearXNG setup cancelled")
        return
    
    api_key = generate_api_key()
    script_dir = Path(__file__).parent.absolute()
    searxng_dir = script_dir / '../../.grace/searxng'
    
    if not searxng_dir.exists():
        subprocess.run(['git', 'clone', 'https://github.com/searxng/searxng.git', str(searxng_dir)], check=True)
    
    settings_content = create_settings_yml(api_key)
    settings_file = searxng_dir / 'searx' / 'settings.yml'
    settings_file.write_text(settings_content)
    
    os.chdir(str(searxng_dir))
    try:
        subprocess.run("uv pip install -r requirements.txt", shell=True, check=True)
    except subprocess.CalledProcessError:
        print("Failed to install requirements.")
        return
    subprocess.Popen([sys.executable, '-m', 'searx.webapp'], env={**os.environ, 'SEARXNG_SETTINGS_PATH': str(settings_file)})

    print(f"SearXNG running on http://localhost:32768")
    print(f"API Key: {api_key}")

def main():
    if check_docker():
        setup_docker()
    else:
        setup_local()

if __name__ == "__main__":
    main()
