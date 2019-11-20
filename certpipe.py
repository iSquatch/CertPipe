#!/bin/python
# -*- coding: utf-8 -*-

###########################################################################
#
# Copyright 2019 Devin Calado
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
###########################################################################

"""
  _____  _______  ______ _______  _____  _____  _____   ______
 |       |______ |_____/    |    |_____]   |   |_____] |______
 |_____  |______ |    \_    |    |       __|__ |       |______
                                                              
A CertStream monitoring tool. Monitor and alert on certificate 
transparency logs by looking for keyword matches.

View README.md for setup information.

BASIC USAGE:
    
    1. Install dependencies: pip install -r requirements.txt
    2. Edit config.py
    3. Run using:

        python certpipe.py

"""

import logging
import sys
from datetime import datetime 
import os
import re
import requests
import certstream
from slackclient import SlackClient
import config as cfg


# Global Variables
log_level = logging.INFO #logging.DEBUG
logger = logging.getLogger()
fuzzed_keywords = []


# Fuzzing code based on: https://github.com/elceef/dnstwist 
class DomainFuzz():
    def __init__(self, domain):
        self.domain = domain
        self.domains = []
        self.qwerty = {
        '1': '2q', '2': '3wq1', '3': '4ew2', '4': '5re3', '5': '6tr4', '6': '7yt5', '7': '8uy6', '8': '9iu7', '9': '0oi8', '0': 'po9',
        'q': '12wa', 'w': '3esaq2', 'e': '4rdsw3', 'r': '5tfde4', 't': '6ygfr5', 'y': '7uhgt6', 'u': '8ijhy7', 'i': '9okju8', 'o': '0plki9', 'p': 'lo0',
        'a': 'qwsz', 's': 'edxzaw', 'd': 'rfcxse', 'f': 'tgvcdr', 'g': 'yhbvft', 'h': 'ujnbgy', 'j': 'ikmnhu', 'k': 'olmji', 'l': 'kop',
        'z': 'asx', 'x': 'zsdc', 'c': 'xdfv', 'v': 'cfgb', 'b': 'vghn', 'n': 'bhjm', 'm': 'njk'
        }
        self.qwertz = {
        '1': '2q', '2': '3wq1', '3': '4ew2', '4': '5re3', '5': '6tr4', '6': '7zt5', '7': '8uz6', '8': '9iu7', '9': '0oi8', '0': 'po9',
        'q': '12wa', 'w': '3esaq2', 'e': '4rdsw3', 'r': '5tfde4', 't': '6zgfr5', 'z': '7uhgt6', 'u': '8ijhz7', 'i': '9okju8', 'o': '0plki9', 'p': 'lo0',
        'a': 'qwsy', 's': 'edxyaw', 'd': 'rfcxse', 'f': 'tgvcdr', 'g': 'zhbvft', 'h': 'ujnbgz', 'j': 'ikmnhu', 'k': 'olmji', 'l': 'kop',
        'y': 'asx', 'x': 'ysdc', 'c': 'xdfv', 'v': 'cfgb', 'b': 'vghn', 'n': 'bhjm', 'm': 'njk'
        }
        self.azerty = {
        '1': '2a', '2': '3za1', '3': '4ez2', '4': '5re3', '5': '6tr4', '6': '7yt5', '7': '8uy6', '8': '9iu7', '9': '0oi8', '0': 'po9',
        'a': '2zq1', 'z': '3esqa2', 'e': '4rdsz3', 'r': '5tfde4', 't': '6ygfr5', 'y': '7uhgt6', 'u': '8ijhy7', 'i': '9okju8', 'o': '0plki9', 'p': 'lo0m',
        'q': 'zswa', 's': 'edxwqz', 'd': 'rfcxse', 'f': 'tgvcdr', 'g': 'yhbvft', 'h': 'ujnbgy', 'j': 'iknhu', 'k': 'olji', 'l': 'kopm', 'm': 'lp',
        'w': 'sxq', 'x': 'wsdc', 'c': 'xdfv', 'v': 'cfgb', 'b': 'vghn', 'n': 'bhj'
        }
        self.keyboards = [ self.qwerty, self.qwertz, self.azerty ]

    def __validate_domain(self, domain):
        try:
            domain_idna = domain.encode('idna').decode()
        except UnicodeError:
            # '.tla'.encode('idna') raises UnicodeError: label empty or too long
            # This can be obtained when __omission takes a one-letter domain.
            return False
        if len(domain) == len(domain_idna) and domain != domain_idna:
            return False
        allowed = re.compile('(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}\.?$)', re.IGNORECASE)
        return allowed.match(domain_idna)

    def __bitsquatting(self):
        result = []
        masks = [1, 2, 4, 8, 16, 32, 64, 128]
        for i in range(0, len(self.domain)):
            c = self.domain[i]
            for j in range(0, len(masks)):
                b = chr(ord(c) ^ masks[j])
                o = ord(b)
                if (o >= 48 and o <= 57) or (o >= 97 and o <= 122) or o == 45:
                    result.append(self.domain[:i] + b + self.domain[i+1:])

        return result

    def __homoglyph(self):
        glyphs = {
        'a': [u'à', u'á', u'â', u'ã', u'ä', u'å', u'ɑ', u'ạ', u'ǎ', u'ă', u'ȧ', u'ą'],
        'b': ['d', 'lb', u'ʙ', u'ɓ', u'ḃ', u'ḅ', u'ḇ', u'ƅ'],
        'c': ['e', u'ƈ', u'ċ', u'ć', u'ç', u'č', u'ĉ'],
        'd': ['b', 'cl', 'dl', u'ɗ', u'đ', u'ď', u'ɖ', u'ḑ', u'ḋ', u'ḍ', u'ḏ', u'ḓ'],
        'e': ['c', u'é', u'è', u'ê', u'ë', u'ē', u'ĕ', u'ě', u'ė', u'ẹ', u'ę', u'ȩ', u'ɇ', u'ḛ'],
        'f': [u'ƒ', u'ḟ'],
        'g': ['q', u'ɢ', u'ɡ', u'ġ', u'ğ', u'ǵ', u'ģ', u'ĝ', u'ǧ', u'ǥ'],
        'h': ['lh', u'ĥ', u'ȟ', u'ħ', u'ɦ', u'ḧ', u'ḩ', u'ⱨ', u'ḣ', u'ḥ', u'ḫ', u'ẖ'],
        'i': ['1', 'l', u'í', u'ì', u'ï', u'ı', u'ɩ', u'ǐ', u'ĭ', u'ỉ', u'ị', u'ɨ', u'ȋ', u'ī'],
        'j': [u'ʝ', u'ɉ'],
        'k': ['lk', 'ik', 'lc', u'ḳ', u'ḵ', u'ⱪ', u'ķ'],
        'l': ['1', 'i', u'ɫ', u'ł'],
        'm': ['n', 'nn', 'rn', 'rr', u'ṁ', u'ṃ', u'ᴍ', u'ɱ', u'ḿ'],
        'n': ['m', 'r', u'ń', u'ṅ', u'ṇ', u'ṉ', u'ñ', u'ņ', u'ǹ', u'ň', u'ꞑ'],
        'o': ['0', u'ȯ', u'ọ', u'ỏ', u'ơ', u'ó', u'ö'],
        'p': [u'ƿ', u'ƥ', u'ṕ', u'ṗ'],
        'q': ['g', u'ʠ'],
        'r': [u'ʀ', u'ɼ', u'ɽ', u'ŕ', u'ŗ', u'ř', u'ɍ', u'ɾ', u'ȓ', u'ȑ', u'ṙ', u'ṛ', u'ṟ'],
        's': [u'ʂ', u'ś', u'ṣ', u'ṡ', u'ș', u'ŝ', u'š'],
        't': [u'ţ', u'ŧ', u'ṫ', u'ṭ', u'ț', u'ƫ'],
        'u': [u'ᴜ', u'ǔ', u'ŭ', u'ü', u'ʉ', u'ù', u'ú', u'û', u'ũ', u'ū', u'ų', u'ư', u'ů', u'ű', u'ȕ', u'ȗ', u'ụ'],
        'v': [u'ṿ', u'ⱱ', u'ᶌ', u'ṽ', u'ⱴ'],
        'w': ['vv', u'ŵ', u'ẁ', u'ẃ', u'ẅ', u'ⱳ', u'ẇ', u'ẉ', u'ẘ'],
        'y': [u'ʏ', u'ý', u'ÿ', u'ŷ', u'ƴ', u'ȳ', u'ɏ', u'ỿ', u'ẏ', u'ỵ'],
        'z': [u'ʐ', u'ż', u'ź', u'ᴢ', u'ƶ', u'ẓ', u'ẕ', u'ⱬ']
        }

        result_1pass = set()

        for ws in range(1, len(self.domain)):
            for i in range(0, (len(self.domain)-ws)+1):
                win = self.domain[i:i+ws]
                j = 0
                while j < ws:
                    c = win[j]
                    if c in glyphs:
                        win_copy = win
                        for g in glyphs[c]:
                            win = win.replace(c, g)
                            result_1pass.add(self.domain[:i] + win + self.domain[i+ws:])
                            win = win_copy
                    j += 1

        result_2pass = set()

        for domain in result_1pass:
            for ws in range(1, len(domain)):
                for i in range(0, (len(domain)-ws)+1):
                    win = domain[i:i+ws]
                    j = 0
                    while j < ws:
                        c = win[j]
                        if c in glyphs:
                            win_copy = win
                            for g in glyphs[c]:
                                win = win.replace(c, g)
                                result_2pass.add(domain[:i] + win + domain[i+ws:])
                                win = win_copy
                        j += 1

        return list(result_1pass | result_2pass)

    def __hyphenation(self):
        result = []

        for i in range(1, len(self.domain)):
            result.append(self.domain[:i] + '-' + self.domain[i:])

        return result

    def __insertion(self):
        result = []

        for i in range(1, len(self.domain)-1):
            for keys in self.keyboards:
                if self.domain[i] in keys:
                    for c in keys[self.domain[i]]:
                        result.append(self.domain[:i] + c + self.domain[i] + self.domain[i+1:])
                        result.append(self.domain[:i] + self.domain[i] + c + self.domain[i+1:])

        return list(set(result))

    def __omission(self):
        result = []

        for i in range(0, len(self.domain)):
            result.append(self.domain[:i] + self.domain[i+1:])

        n = re.sub(r'(.)\1+', r'\1', self.domain)

        if n not in result and n != self.domain:
            result.append(n)

        return list(set(result))

    def __repetition(self):
        result = []

        for i in range(0, len(self.domain)):
            if self.domain[i].isalpha():
                result.append(self.domain[:i] + self.domain[i] + self.domain[i] + self.domain[i+1:])

        return list(set(result))

    def __replacement(self):
        result = []

        for i in range(0, len(self.domain)):
            for keys in self.keyboards:
                if self.domain[i] in keys:
                    for c in keys[self.domain[i]]:
                        result.append(self.domain[:i] + c + self.domain[i+1:])

        return list(set(result))

    def __subdomain(self):
        result = []

        for i in range(1, len(self.domain)):
            if self.domain[i] not in ['-', '.'] and self.domain[i-1] not in ['-', '.']:
                result.append(self.domain[:i] + '.' + self.domain[i:])

        return result

    def __transposition(self):
        result = []

        for i in range(0, len(self.domain)-1):
            if self.domain[i+1] != self.domain[i]:
                result.append(self.domain[:i] + self.domain[i+1] + self.domain[i] + self.domain[i+2:])

        return result

    def __vowel_swap(self):
        vowels = 'aeiou'
        result = []

        for i in range(0, len(self.domain)):
            for vowel in vowels:
                if self.domain[i] in vowels:
                    result.append(self.domain[:i] + vowel + self.domain[i+1:])

        return list(set(result))

    def __addition(self):
        result = []

        for i in range(97, 123):
            result.append(self.domain + chr(i))

        return result

    def generate(self):
        self.domains.append({ 'fuzzer': 'Original*', 'domain-name': self.domain })

        for domain in self.__addition():
            self.domains.append({ 'fuzzer': 'Addition', 'domain-name': domain })
        for domain in self.__bitsquatting():
            self.domains.append({ 'fuzzer': 'Bitsquatting', 'domain-name': domain })
        for domain in self.__homoglyph():
            self.domains.append({ 'fuzzer': 'Homoglyph', 'domain-name': domain })
        for domain in self.__hyphenation():
            self.domains.append({ 'fuzzer': 'Hyphenation', 'domain-name': domain })
        for domain in self.__insertion():
            self.domains.append({ 'fuzzer': 'Insertion', 'domain-name': domain })
        for domain in self.__omission():
            self.domains.append({ 'fuzzer': 'Omission', 'domain-name': domain })
        for domain in self.__repetition():
            self.domains.append({ 'fuzzer': 'Repetition', 'domain-name': domain })
        for domain in self.__replacement():
            self.domains.append({ 'fuzzer': 'Replacement', 'domain-name': domain })
        for domain in self.__subdomain():
            self.domains.append({ 'fuzzer': 'Subdomain', 'domain-name': domain })
        for domain in self.__transposition():
            self.domains.append({ 'fuzzer': 'Transposition', 'domain-name': domain })
        for domain in self.__vowel_swap():
            self.domains.append({ 'fuzzer': 'Vowel-swap', 'domain-name': domain })


# Posts a message to a Slack Channel using the Slack API and an access token
def post_to_slack(msg):
    sc = SlackClient(cfg.slack_token)
    sc.api_call(
        "chat.postMessage",
        channel = cfg.slack_channel,
        text = "[INFO]: " + msg
    )
    logger.info("Message posted to Slack: {}".format(msg))


# Write matched domains to a local CSV file. CSV file hase 3 columns: timestamp, matched_keyword, domain
def write_to_csv_output(matched_keyword, domain):
    logger.info("Writing output to CSV file")
    
    # Create the file and add the first row header if it does not exist
    if not os.path.exists(cfg.output_csv_file):
        with open(cfg.output_csv_file, "w+") as output_file:
            output_file.write("timestamp, matched_keyword, domain\r\n")
            output_file.close()

    # Add a new row to the csv file and close it
    try:
        with open(cfg.output_csv_file, "a") as output_file:
            output_file.write(str(datetime.now()) + ", " + str(matched_keyword) + ", " + str(domain) + "\r\n")
            output_file.close()
    except IOError as e:
        print("File I/O error({0}): {1}".format(e.errno, e.strerror))
        

# Generate fuzzed keywords to look for lookalike domains/keywords
def fuzz_keywords(wordlist):
    fuzzed_list = []
    fuzzed_list.extend(wordlist)
    for keyword in cfg.keywords:
        domain_fuzz = DomainFuzz(keyword)
        domain_fuzz.generate()
        for domain in domain_fuzz.domains:
            fuzzed_list.append(domain['domain-name'])
    return fuzzed_list


# Check if a domain matches any of the keywords (or variations)
def check_match(domain):
    # Check if the domain contains any of the keywords to ignore (no match)
    for keyword in cfg.ignore_keywords:
        if keyword in domain:
            return False, ""

    # Check if the domains contains any of the 'no fuzz' keywords
    for keyword in cfg.no_fuzz_keywords:
        if keyword in domain:
            logger.info("Found match:{}".format(domain))
            return True, keyword

    # Check if the domain contains any of the fuzzed keywords
    for keyword in fuzzed_keywords:
        if keyword in domain:
            logger.info("Found match:{}".format(domain))
            return True, keyword

    return False, ""


# Called when data is pulled from CertStream
def certstream_callback(message, context):
    logger.debug("Message -> {}".format(message))

    if message['message_type'] == "heartbeat":
        return

    if message['message_type'] == "certificate_update":
        all_domains = message['data']['leaf_cert']['all_domains']
        
        if len(all_domains) == 0:
            return

        for domain in all_domains:
            is_match, matched_keyword = check_match(domain)
            
            if is_match:
                logger.info("Matched Keyword : " + matched_keyword + " : " + domain)
                print(matched_keyword + " : " + domain)

                if cfg.enable_slack:
                    post_to_slack("Matched Keyword: " +  matched_keyword + " : " + domain)

                if cfg.enable_csv_output:
                    write_to_csv_output(matched_keyword, domain)


# Called when the CertSream listener is opened
def on_open(instance):
    return


# Called when the CertStream listener encounters an error
def on_error(instance, exception):
    return


# Runs before starting CertStream
def initial_configuration():
    global fuzzed_keywords

    # Setup logging
    logging.basicConfig(format='[%(levelname)s:%(name)s] %(asctime)s - %(message)s', level=log_level)
    logger.disabled = not cfg.enable_logging
    logger.info("Logging level: {}".format("INFO" if 20 == log_level else "DEBUG" ))

    # Created fuzzed keywords
    logger.info("{} keywords in config file".format(len(cfg.keywords)))
    logger.info("{} 'No-fuzz' keywords in config file".format(len(cfg.no_fuzz_keywords)))
    logger.info("{} 'Ignore' keywords in config file".format(len(cfg.ignore_keywords)))
    logger.info("Keyword fuzzer starting...")
    fuzzed_keywords = fuzz_keywords(cfg.keywords)
    logger.info("Keyword fuzzer finished")
    logger.info("{} fuzzed keywords created".format(len(fuzzed_keywords)))


# Connects to the CertStream service and specifies callback functions
def start_certstream(): 
    logger.info("CertStream listener starting...")
    certstream.listen_for_events(message_callback=certstream_callback, on_open=on_open, on_error=on_error, url='wss://certstream.calidog.io/')


# Setup and run the application
initial_configuration()
start_certstream()

