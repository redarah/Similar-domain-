from ail_typo_squatting import formatOutput, omission, subdomain, addDash
import math
import whois
import socket
import json
import win32com.client as win32
from os.path import abspath
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import pandas as pd
import os
import logging
import numpy as np
import dns.resolver


try:
    with open("clients.json", "r") as file:
        clients = json.load(file)

    # Logging configuration
    logging.basicConfig(filename='app.log', filemode='w', format='%(name)s - %(levelname)s - %(message)s', level=logging.ERROR)

    for client in clients:
        ############################################## Global Variable ##############################################
        NAME = client["name"]
        print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> Testing for:", NAME)
        DOMAINS = client["domain"]
        SENDER = client["email"]
        FILENAME_DB = f"{client['name']}_database.csv"
        FILENAME_TO_SEND = f"{client['name']}_to_send.csv"

        #################################################### Similar domain finder ####################################################
        def generate_domain_variations(name, fo):
            resultList = list()
            domainList = [name]
            limit = math.inf
            formatoutput = f"{fo}"
            pathOutput = "."

            for domain in domainList:
                resultList = omission(domain=domain, resultList=resultList, verbose=False, limit=limit, givevariations=False, keeporiginal=False)
                resultList = subdomain(domain=domain, resultList=resultList, verbose=False, limit=limit, givevariations=False, keeporiginal=False)
                resultList = addDash(domain=domain, resultList=resultList, verbose=False, limit=limit, givevariations=False, keeporiginal=False)

            return list(resultList)

        formats = ["text", "yara", "regex", "sigma"]
        all_variations = set()

        def generate_all_variations(name):
            variations = set()
            parts = name.split('.')
            tld = parts[-1]
            domain = ".".join(parts[:-1])

            for i in range(len(domain)):
                if domain[i].isalpha():
                    for digit in '0123456789':
                        new_name = domain[:i] + digit + domain[i+1:]
                        variations.add(new_name)
                new_name = domain[:i] + domain[i+1:]
                variations.add(new_name)

            alphabet = 'abcdefghijklmnopqrstuvwxyz'
            for i in range(len(domain) + 1):
                for char in alphabet:
                    new_name = domain[:i] + char + domain[i:]
                    variations.add(new_name)

            variations = {variation + ".com" for variation in variations}
            return list(variations)

        extensions = ['.org', '.info', '.net', '.ca', '.us', '.io', '.gov', '.com', '.co', '.ru', '.inc', '.nl', '.bb', '.link', '.tt', '.jm', '.cn', '.cw', '.uk', '.de', '.jp']

        def generate_variations_with_both_bases(name):
            parts = name.split('.')
            if len(parts) > 2:
                base_domain = ".".join(parts[:-1])
            else:
                base_domain, _ = name.split('.')

            variations_with_full_domain = [base_domain + ext for ext in extensions]
            base_name = base_domain.split('.')[0]
            variations_with_base_name = [base_name + ext for ext in extensions]

            return variations_with_full_domain + variations_with_base_name

        combined_results_all_domains = set()

        for DOMAIN in DOMAINS:
            for formatoutput in formats:
                all_variations.update(generate_domain_variations(DOMAIN, formatoutput))

            result_1 = list(all_variations)
            filtered_results2 = [domain for domain in generate_all_variations(DOMAIN)]

            first_domain = generate_variations_with_both_bases(DOMAIN)
            all_variations_with_extensions1 = [generate_variations_with_both_bases(domain) for domain in result_1]
            all_variations_with_extensions2 = [generate_variations_with_both_bases(domain) for domain in filtered_results2]

            all_variations_with_extensions1 = [item for sublist in all_variations_with_extensions1 for item in sublist]
            all_variations_with_extensions2 = [item for sublist in all_variations_with_extensions2 for item in sublist]

            combined_results = set(first_domain + result_1 + filtered_results2 + all_variations_with_extensions1 + all_variations_with_extensions2)
            combined_results = {domain for domain in combined_results if domain not in DOMAINS}

            combined_results_all_domains.update(combined_results)

        print("Total combinations that will be tested:", len(combined_results_all_domains))

        with open("Alldomain.txt", "w") as file:
            file.write(str(combined_results_all_domains))

        ######################################################### Whois #########################################################

        columns = ["Time for executions", "is_found", "registrar", "creation_date", "expiration_date", "updated_date", "name_servers", "emails", "name", "address", "city", "state", "registrant_postal_code", "country", "Last Time check"]
        df = pd.DataFrame(columns=columns)

        def is_port_open(domain, port):
            try:
                with socket.create_connection((domain, port), timeout=10):
                    return True
            except:
                return False

        def check_domain(domain):
            try:
                dns.resolver.resolve(domain, 'A')
                time.sleep(40)
                w = whois.whois(domain)

                creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                expiration_date = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
                updated_date = w.updated_date[0] if isinstance(w.updated_date, list) else w.updated_date

                port_80_open = is_port_open(domain, 80)
                port_443_open = is_port_open(domain, 443)

                result = {
                    "all domain": domain,
                    "is found": True,
                    "registrar": w.registrar,
                    "creation_date": creation_date,
                    "expiration_date": expiration_date,
                    "updated_date": updated_date,
                    "name_servers": ", ".join(w.name_servers) if w.name_servers else None,
                    "emails": ", ".join(w.emails) if w.emails else None,
                    "name": w.name,
                    "address": w.address,
                    "city": w.city,
                    "state": w.state,
                    "registrant_postal_code": w.zipcode,
                    "country": w.country,
                    "Last Time check": datetime.now().strftime('%d-%m-%Y')
                }

                if port_443_open or port_80_open:
                    return result
                return None

            except Exception as e:
                logging.error(f"Error: {e}")
                return None

        start_time = time.time()

        print(f"> Checking Domain {NAME}")
        results = []
        with ThreadPoolExecutor(max_workers=100) as executor:
            results = list(executor.map(check_domain, combined_results_all_domains))

        results = [result for result in results if result is not None]
        df = pd.DataFrame(results)

        end_time = time.time()
        total_time = end_time - start_time

        print(f"Total execution time: {total_time:.2f} seconds")

except Exception as problem:
    print(f"An error occurred: {problem}")
