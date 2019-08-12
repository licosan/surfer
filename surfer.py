# -*- coding: utf-8 -*-
import requests, re, copy
from bs4 import BeautifulSoup
from requests.auth import HTTPBasicAuth
from time import sleep

class surfer:

    def __init__(self, base_url='', cookies=True, allow_redirects=False, credentials=None, debug=False):
        self.base_url = base_url
        self.debug = debug
        self.cookies = cookies
        self.allow_redirects = allow_redirects
        self.credentials = credentials


    def surf(self, waves, entry_wave):
        self.cookiejar = None
        self.extracted_values = {}
        self.waves = waves
        self.next_wave = entry_wave
        while self.next_wave is not None :
            if ('delay' in self.waves[self.next_wave]) and (self.waves[self.next_wave]['delay']):
                sleep(self.waves[self.next_wave]['delay'])
            self._surf_wave()


    def _surf_wave(self):
        self.cur_wave = self.next_wave
        if self.debug: print('BASE=%s | WAVEURL=%s' %(self.base_url, self.waves[self.cur_wave]['sub_url']))
        if self.waves[self.cur_wave]['sub_url'].lower().startswith('http'):
            url = self.waves[self.cur_wave]['sub_url']
        else:
            url = self.base_url+self.waves[self.cur_wave]['sub_url']
        self._prepare_params()
        self._prepare_headers()
        req_meth_name = self.waves[self.cur_wave]['method'].lower()
        req_meth = requests.__dict__[req_meth_name]

        if self.debug: print('Surfing to %s\n    Method:%s\n    Headers:%s\n    Params:%s\n    Cookies:%s\n' %(url, req_meth_name, self.headers, self.params, self.cookiejar))
        if self.credentials:
            r = req_meth(   url, 
                            allow_redirects = self.allow_redirects,
                            headers = self.headers,
                            cookies=self.cookiejar,
                            params = self.params,
                            auth=(self.credentials['user'], self.credentials['pass'])
                        )
        else:
            r = req_meth(   url, 
                            allow_redirects = self.allow_redirects,
                            headers = self.headers,
                            cookies=self.cookiejar,
                            params = self.params
                        )

        if r.cookies:
            self.cookiejar = r.cookies
        if self.debug: print('Cookies after wave %s : %s' %(self.cur_wave, self.cookiejar))

        self.next_wave = self.waves[self.cur_wave]['next_wave']
        if r.status_code != 200:
            if self.debug: print('Error; http status=%s' %r.status_code)
            if callable(self.waves[self.cur_wave]['if_not_200']): 
                self.waves[self.cur_wave]['if_not_200'](r, self)
        else:
            if 'text' == self.waves[self.cur_wave]['parsing']:
                if self.debug: print('Parsing text...')
                data = r.text
                self.extracted_values = {}
                self._regexp_extract(data)
            elif 'json' == self.waves[self.cur_wave]['parsing']:
                if self.debug: print('Parsing json...')
                data = r.json()
                # ?? extracting in json has no sense to me !?
            elif 'html' == self.waves[self.cur_wave]['parsing']:
                self.extracted_values = {}
                self._regexp_extract(r.text)
                data = BeautifulSoup(r.text, features="html.parser")
                self._html_xtract(data)
            elif 'xml' == self.waves[self.cur_wave]['parsing']:
                self.extracted_values = {}
                self._regexp_extract(r.text)
                data = BeautifulSoup(r.text, 'xml') #features="xml.parser"
                self._xml_xtract(data)


            if callable(self.waves[self.cur_wave]['test_response']): 
                test_ok = self.waves[self.cur_wave]['test_response'](data, self)
            else:
                test_ok = True

            if self.debug: print('Tested content:%s' %(('ok' if test_ok else 'not ok!')))

            if test_ok and callable(self.waves[self.cur_wave]['if_test_ok']): 
                self.waves[self.cur_wave]['if_test_ok'](data, self)
            elif (not test_ok) and callable(self.waves[self.cur_wave]['if_test_fail']): 
                self.waves[self.cur_wave]['if_test_fail'](data, self)


    def _html_xtract(self, parsed_html):
        if 'extract' not in self.waves[self.cur_wave]: return
        for needle in self.waves[self.cur_wave]['extract']:        
            if 'bs4_selectors' not in needle: continue
            node = parsed_html
            for selector in needle['bs4_selectors']:
                res = node.select(selector)         
                if res: 
                    #if self.debug:  print('Selector %s match ! %s' %(selector, res))
                    node = res[0]
                    if self.debug: print('Selector %s found !' %(selector))
                else: 
                    if self.debug:  print('Selector %s NOT match !' %selector)
                    break
                    
            if res:                
                if ('bs4_getall' in needle) and needle['bs4_getall']:
                    nodes = res
                    extracts = []
                    for node in nodes:
                        if 'bs4_extractor' in needle and callable(needle['bs4_extractor']):
                            extracts.append(needle['bs4_extractor'](node))
                        else:
                            extracts.append(node.string)                    
                elif 'bs4_getone' in needle:
                    node = res[needle['bs4_getone']]
                    if 'bs4_extractor' in needle and callable(needle['bs4_extractor']):
                        extracts = needle['bs4_extractor'](node)
                    else:
                        extracts = node.string
                else:
                    node = res[0]
                    if 'bs4_extractor' in needle and callable(needle['bs4_extractor']):
                        extracts = needle['bs4_extractor'](node)
                    else:
                        extracts = node.string


                if self.debug: print('HTML Needle Found : %s' %extracts)    
                self.extracted_values[needle['name']] = extracts
            else:
                if self.debug: print('HTML Needle %s NOT Found!' %needle['name']) 
                if needle['name'] not in self.extracted_values: self.extracted_values[needle['name']] = None
        if self.debug: print('HTML Extracted: %s' %self.extracted_values)


    def _xml_xtract(self, parsed_xml):
        if 'extract' not in self.waves[self.cur_wave]: return
        for needle in self.waves[self.cur_wave]['extract']:        
            if 'bs4_selectors' not in needle: continue
            node = parsed_xml
            for selector in needle['bs4_selectors']:
                res = node.select(selector)         
                if res: 
                    #if self.debug:  print('Selector %s match ! %s' %(selector, res))
                    node = res[0]
                    if self.debug: print('Selector %s found !' %(selector))
                else: 
                    if self.debug:  print('Selector %s NOT match !' %selector)
                    break
                    
            if res:                
                if ('bs4_getall' in needle) and needle['bs4_getall']:
                    nodes = res
                    extracts = []
                    for node in nodes:
                        if 'bs4_extractor' in needle and callable(needle['bs4_extractor']):
                            extracts.append(needle['bs4_extractor'](node))
                        else:
                            extracts.append(node.string)                    
                elif 'bs4_getone' in needle:
                    node = res[needle['bs4_getone']]
                    if 'bs4_extractor' in needle and callable(needle['bs4_extractor']):
                        extracts = needle['bs4_extractor'](node)
                    else:
                        extracts = node.string
                else:
                    node = res[0]
                    if 'bs4_extractor' in needle and callable(needle['bs4_extractor']):
                        extracts = needle['bs4_extractor'](node)
                    else:
                        extracts = node.string


                if self.debug: print('XML Needle Found : %s' %extracts)    
                self.extracted_values[needle['name']] = extracts
            else:
                if self.debug: print('XML Needle %s NOT Found!' %needle['name']) 
                if needle['name'] not in self.extracted_values: self.extracted_values[needle['name']] = None
        if self.debug: print('XML Extracted: %s' %self.extracted_values)



    def _regexp_extract(self, content):
        if 'extract' not in self.waves[self.cur_wave]: return
        for needle in self.waves[self.cur_wave]['extract']:
            if 'regexp' not in needle: continue
            if self.debug: print('Searching for: %s' %needle)
            matches = re.findall(needle['regexp'], content, needle['regexp_flags'])
            if matches:
                if self.debug: print('TEXT Needle Found : %s' %matches)
                if isinstance(matches[0], tuple):
                    self.extracted_values[needle['name']] = matches[0][needle['regexp_group_index']]
                else:
                    self.extracted_values[needle['name']] = matches[0]
            else:
                if self.debug: print('TEXT Needle %s NOT found!' %needle['name'])
                if needle['name'] not in self.extracted_values: self.extracted_values[needle['name']] = None
        if self.debug: print('TEXT Extracted: %s' %self.extracted_values)


    def _prepare_params(self):
        self.params = copy.deepcopy(self.waves[self.cur_wave]['params'])
        for k, v in self.extracted_values.items():
            for par,parval in self.params.items():
                if isinstance(v, list) or isinstance(v, tuple): v = ' '.join(v)
                self.params[par]=parval.replace('%%{%s}'%k.encode('utf-8', 'ignore'), v.encode('utf-8', 'ignore'))
        # If replacement in keys is necessary do it here 


    def _prepare_headers(self):
        self.headers = copy.deepcopy(self.waves[self.cur_wave]['headers'])
        for k, v in self.extracted_values.items():
            if v == None: v=''
            for par,parval in self.headers.items():
                if isinstance(v, list) or isinstance(v, tuple): v = ' '.join(v)
                self.headers[par]=parval.replace('%%{%s}'%k.encode('utf-8', 'ignore'), v.encode('utf-8', 'ignore'))
        # If replacement in keys is necessary do it here 

