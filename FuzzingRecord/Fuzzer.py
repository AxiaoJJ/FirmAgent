#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import requests
import logging
import re
import time
import random
from urllib.parse import urljoin
import argparse
from typing import List, Dict, Any


class APIFuzzer:
    def __init__(self, base_url: str, json_file: str, delay: float = 1.0):
        """
        Initialize API Fuzzer.
        :param base_url: Base API URL (e.g., http://192.168.0.1)
        :param json_file: Path to the JSON file containing API definitions
        :param delay: Delay between requests (seconds)
        """
        self.base_url = base_url.rstrip('/')
        self.json_file = json_file
        self.delay = delay
        self.target_host = target_host
        self.session = requests.Session()

        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('fuzzing_results.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

        # Fuzzing payloads
        self.payloads = {
            'buffer_overflow': 'A' * 60,
            'command_injection_1': '|ping -c 3 127.0.0.1',
            'command_injection_2': '; ping -c 3 127.0.0.1',
            'command_injection_3': '& ping -c 3 127.0.0.1',
            'command_injection_4': '`ping -c 3 127.0.0.1`',
            'command_injection_5': '$(ping -c 3 127.0.0.1)',
            'xss_payload': '<script>alert("XSS")</script>',
            'path_traversal': '../../../etc/passwd',
        }

    def load_api_definitions(self) -> List[Dict[str, Any]]:
        """Load API definitions from JSON file"""
        try:
            with open(self.json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            if isinstance(data, list):
                return data
            else:
                return [data]
        except Exception as e:
            self.logger.error(f"Failed to load JSON file: {e}")
            return []

    def extract_parameters(self, payload_str: str) -> List[str]:
        """Extract parameter names from request payload"""
        try:
            # Match parameters like "<String_value>"
            pattern = r'"([^"]+)"\s*:\s*<[^>]+>'
            matches = re.findall(pattern, payload_str)

            # Match boolean parameters (true/false)
            bool_pattern = r'"([^"]+)"\s*:\s*(true|false)'
            bool_matches = re.findall(bool_pattern, payload_str)

            all_params = matches + [match[0] for match in bool_matches]
            return list(set(all_params))
        except Exception as e:
            self.logger.error(f"Parameter extraction failed: {e}")
            return []

    def create_fuzz_payload(self, original_payload: str, param_name: str, params, paras, fuzz_value: str) -> str:
        """Create fuzzing payload"""
        try:
            return self.string_replace_payload(original_payload, param_name, params, paras, fuzz_value)
        except Exception as e:
            self.logger.error(f"Failed to create fuzz payload: {e}")
            return original_payload

    def string_replace_payload(self, original_payload: str, param_name: str, params, paras_dict, fuzz_value: str) -> str:
        """Replace parameter values in JSON string with fuzz value"""
        pattern1 = f'"{param_name}"\\s*:\\s*<String_value>'
        replacement1 = f'"{param_name}": "{fuzz_value}"'
        result = re.sub(pattern1, replacement1, original_payload)

        # Replace other placeholders with original values from paras_dict
        pattern = r'"([^"]+)"\s*:\s*<[^>]+>'

        def replace_func(match):
            key = match.group(1)
            if key != param_name and key in paras_dict:
                return f'"{key}": "{paras_dict[key]}"'
            else:
                return match.group(0)

        result = re.sub(pattern, replace_func, result)

        # Ensure balanced braces
        open_braces = result.count('{')
        close_braces = result.count('}')
        if open_braces > close_braces:
            result += '}' * (open_braces - close_braces)
        elif close_braces > open_braces:
            for _ in range(close_braces - open_braces):
                last_brace_pos = result.rfind('}')
                if last_brace_pos != -1:
                    result = result[:last_brace_pos] + result[last_brace_pos+1:]

        # Validate JSON
        try:
            json.loads(result)
            return result
        except json.JSONDecodeError:
            # Remove trailing commas
            result = re.sub(r',\s*}', '}', result)
            result = re.sub(r',\s*]', ']', result)
            return result

    def send_request(self, api_info: Dict[str, Any], payload: str) -> Dict[str, Any]:
        """Send HTTP request with fuzz payload"""
        url = urljoin(self.base_url, api_info['api_url'])
        method = api_info['http_method'].upper()
        # Supplementary authentication information
        headers = {
            "Host": self.target_host if self.target_host else self.base_url.replace("http://", "").replace("https://", ""),
            "Cache-Control": "max-age=0",
            "Accept-Language": "zh-CN",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.57 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Encoding": "gzip, deflate, br",
            "Content-Type": "application/json",
            "Connection": "keep-alive"
        }

        try:
            if method == 'GET':
                response = self.session.get(url, headers=headers, timeout=10)
            elif method == 'POST':
                response = self.session.post(url, data=payload, headers=headers, timeout=10, verify=False)
            elif method == 'PUT':
                response = self.session.put(url, data=payload, headers=headers, timeout=10, verify=False)
            elif method == 'DELETE':
                response = self.session.delete(url, headers=headers, timeout=10, verify=False)
            else:
                response = self.session.request(method, url, data=payload, headers=headers, timeout=10, verify=False)

            return {
                'status_code': response.status_code,
                'response_time': response.elapsed.total_seconds(),
                'content_length': len(response.content),
                'headers': dict(response.headers),
                'content': response.text[:1000]
            }

        except requests.exceptions.RequestException as e:
            return {
                'error': str(e),
                'status_code': None,
                'response_time': None
            }

    def analyze_response(self, response_data: Dict[str, Any], payload_type: str) -> Dict[str, Any]:
        """Analyze response for potential vulnerabilities"""
        analysis = {
            'potential_vulnerability': False,
            'vulnerability_type': None,
            'evidence': []
        }

        if 'error' in response_data:
            analysis['evidence'].append(f"Request error: {response_data['error']}")
            return analysis

        status_code = response_data.get('status_code')
        content = response_data.get('content', '').lower()
        response_time = response_data.get('response_time', 0)

        # Command Injection detection
        if payload_type.startswith('command_injection'):
            if response_time > 2:
                analysis['potential_vulnerability'] = True
                analysis['vulnerability_type'] = 'Command Injection (Time-based)'
                analysis['evidence'].append(f'Long response time: {response_time}s')
            for indicator in ['ping statistics', 'packets transmitted', 'rtt min/avg/max']:
                if indicator in content:
                    analysis['potential_vulnerability'] = True
                    analysis['vulnerability_type'] = 'Command Injection'
                    analysis['evidence'].append(f'Command output found: {indicator}')

        # Buffer overflow detection
        elif payload_type == 'buffer_overflow':
            if status_code == 500 or 'stack overflow' in content or 'buffer overflow' in content:
                analysis['potential_vulnerability'] = True
                analysis['vulnerability_type'] = 'Buffer Overflow'
                analysis['evidence'].append('Server error, possible overflow')

        # XSS detection
        elif payload_type == 'xss_payload':
            if '<script>' in content and 'alert(' in content:
                analysis['potential_vulnerability'] = True
                analysis['vulnerability_type'] = 'Cross-Site Scripting (XSS)'
                analysis['evidence'].append('XSS payload reflected')

        # Generic server errors
        if status_code in [500, 502, 503]:
            analysis['potential_vulnerability'] = True
            if not analysis['vulnerability_type']:
                analysis['vulnerability_type'] = 'Server Error'
            analysis['evidence'].append(f'Status code: {status_code}')

        return analysis

    def fuzz_api(self, api_info: Dict[str, Any], paras) -> None:
        """Fuzz a single API"""
        self.logger.info(f"Testing API: {api_info['api_url']}")

        params = self.extract_parameters(api_info['request_payload'])
        if not params:
            self.logger.warning(f"No parameters found: {api_info['api_url']}")
            return

        for param in params:
            pattern = rf'"{param}"\s*:\s*<([^>]+)>'
            match = re.search(pattern, api_info['request_payload'])
            if not match:
                continue
            param_type = match.group(1).strip().lower()
            if param_type not in ['string_value', 'string']:
                continue

            for payload_name, payload_value in self.payloads.items():
                fuzz_payload = self.create_fuzz_payload(api_info['request_payload'], param, params, paras, payload_value)
                self.logger.info(f"Fuzzing param '{param}' with '{payload_name}'")
                response_data = self.send_request(api_info, fuzz_payload)
                analysis = self.analyze_response(response_data, payload_name)

                result = {
                    'api_url': api_info['api_url'],
                    'param': param,
                    'payload_type': payload_name,
                    'payload': fuzz_payload,
                    'analysis': analysis
                }

                if analysis['potential_vulnerability']:
                    self.logger.warning(f"[!] Vulnerability found in {api_info['api_url']} param {param}: {analysis['vulnerability_type']}")
                    self.logger.warning(f"Evidence: {analysis['evidence']}")

                with open('detailed_results.json', 'a', encoding='utf-8') as f:
                    f.write(json.dumps(result, ensure_ascii=False, indent=2) + '\n')

                time.sleep(self.delay)

    def run_fuzzing(self) -> None:
        """Run fuzzing on all APIs"""
        apis = self.load_api_definitions()
        with open("para_results.json", "r") as file:
            paras = json.load(file)

        if not apis:
            self.logger.error("No API definitions found")
            return

        open('detailed_results.json', 'w').close()

        for i, api in enumerate(apis, 1):
            self.logger.info(f"Progress: {i}/{len(apis)}")
            try:
                self.fuzz_api(api, paras)
            except Exception as e:
                self.logger.error(f"Error fuzzing {api.get('api_url', 'unknown')}: {e}")

            time.sleep(random.uniform(0.5, 2.0))

        self.logger.info("Fuzzing completed!")


def main():
    parser = argparse.ArgumentParser(description="API Fuzzer Tool")
    parser.add_argument("--json-file", required=True, help="Path to the JSON file containing API definitions")
    parser.add_argument("--delay", type=float, default=0.5, help="Delay between requests in seconds")
    parser.add_argument("--host", required=True, help="Host header value (IP or domain)")
    args = parser.parse_args()

    fuzzer = APIFuzzer(f'http:{args.host}', args.json_file, args.delay, args.host)
    fuzzer.run_fuzzing()


if __name__ == '__main__':
    main()
