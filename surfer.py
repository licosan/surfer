# -*- coding: utf-8 -*-
import requests, re, copy
from bs4 import BeautifulSoup
from requests.auth import HTTPBasicAuth
from time import sleep
from pprint import pprint
import urllib3

class surfer:

    def __init__(self, base_url='', with_session=True, allow_redirects=False, credentials=None, debug=False):
        self.base_url = base_url
        self.debug = debug
        self.with_session = with_session
        if with_session: self.session = requests.Session()
        self.allow_redirects = allow_redirects
        self.credentials = credentials
        # By Nike, some fucked up servers have weak SSL, and you need to cope with it despite the error throuwn by default by the SSL lib...
        requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS = 'ALL:@SECLEVEL=1'
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def surf(self, waves, entry_wave):
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
        if self.waves[self.cur_wave]['sub_url'].lower().startswith('https://') or self.waves[self.cur_wave]['sub_url'].lower().startswith('http://'):
            url = self.waves[self.cur_wave]['sub_url']
        else:
            if self.waves[self.cur_wave]['sub_url'].startswith('/'):
                url = self.base_url+self.waves[self.cur_wave]['sub_url']
            else:
                url = self.base_url+'/'+self.waves[self.cur_wave]['sub_url']
        self._prepare_params()
        self._prepare_headers()

        req_meth_name = self.waves[self.cur_wave]['method'].lower()
        if req_meth_name not in ('get','put', 'post', 'delete', 'head', 'options', ): return
        if self.with_session :            
            req_meth = getattr(self.session, req_meth_name)
        else:
            req_meth = getattr(requests, req_meth_name)

        if self.debug: print('Surfing to %s\n    Method:%s\n    Headers:%s\n    Params:%s\n    Cookies:%s\n' %(url, req_meth_name, self.headers, self.params, self.session.cookies.items()))
        if self.credentials:
            try:
                if req_meth_name.lower() == 'post':
                    r = req_meth(   url,
                                    allow_redirects = self.allow_redirects,
                                    headers = self.headers,
                                    data = self.params,
                                    auth=(self.credentials['user'], self.credentials['pass']),
                                    timeout=(10, 20),
                                    verify=False,
                                )
                else:
                    r = req_meth(   url,
                                    allow_redirects = self.allow_redirects,
                                    headers = self.headers,
                                    params = self.params,
                                    auth=(self.credentials['user'], self.credentials['pass']),
                                    timeout=(10, 20),
                                    verify=False,
                                )
            except Exception as e:
                if ('if_not_accessible' in self.waves[self.cur_wave]) and callable(self.waves[self.cur_wave]['if_not_accessible']):
                    self.waves[self.cur_wave]['if_not_accessible'](e.message, self)
                    self.next_wave = self.waves[self.cur_wave]['next_wave']
                    return
                else:
                    raise e
        else:
            try:
                if req_meth_name.lower() == 'post':
                    r = req_meth(   url,
                                    allow_redirects = self.allow_redirects,
                                    headers = self.headers,
                                    data = self.params,
                                    timeout=(10, 20),
                                    verify=False,
                                )
                else:
                    r = req_meth(   url,
                                allow_redirects = self.allow_redirects,
                                headers = self.headers,
                                params = self.params,
                                timeout=(10, 20),
                                verify=False,
                            )

            except Exception as e:
                if ('if_not_accessible' in self.waves[self.cur_wave]) and callable(self.waves[self.cur_wave]['if_not_accessible']):
                    self.waves[self.cur_wave]['if_not_accessible'](e.message, self)
                    self.next_wave = self.waves[self.cur_wave]['next_wave']
                    return
                else:
                    raise e

        if self.debug: print('Cookies after wave %s : %s' %(self.cur_wave, self.session.cookies.items()))

        self.next_wave = self.waves[self.cur_wave]['next_wave']
        if r.status_code != 200:
            if self.debug: print('Error; http status=%s' %r.status_code)
            if callable(self.waves[self.cur_wave]['if_not_200']):
                self.waves[self.cur_wave]['if_not_200'](r, self)
        else:
            if 'text' == self.waves[self.cur_wave]['parsing']:
                if self.debug: print('Parsing TEXT...')
                data = r.text
                self.extracted_values = {}
                self._regexp_extract(data)
            elif 'json' == self.waves[self.cur_wave]['parsing']:
                if self.debug: print('Parsing JSON...')
                data = r.json()
                self.extracted_values = {'json_data' : data}
            elif 'html' == self.waves[self.cur_wave]['parsing']:
                if self.debug: print('Parsing HTML...');
                self.extracted_values = {}
                self._regexp_extract(r.text)
                data = BeautifulSoup(r.text, features="html.parser")
                self._html_xtract(data)
            elif 'xml' == self.waves[self.cur_wave]['parsing']:
                if self.debug: print('Parsing XML...')
                self.extracted_values = {}
                self._regexp_extract(r.text)
                data = BeautifulSoup(r.text, 'xml') #features="xml.parser"
                self._xml_xtract(data)
            else:
                if self.debug: print('WARNING: No parsing !!')
                data = r.content

            if callable(self.waves[self.cur_wave]['test_response']):
                test_ok = self.waves[self.cur_wave]['test_response'](data, self)
                if not test_ok and self.debug:  
                    with open('surfer_debug.log', 'w') as fil: fil.write(r.text.encode('utf-8', 'ignore'))
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
                            if self.debug:  print('[Getall] Adding node %s using external extractor...' %node)
                            extracts.append(needle['bs4_extractor'](node))
                        else:
                            if self.debug:  print('[Getall] Adding node %s as string...' %node)
                            extracts.append(node.string)

                elif 'bs4_getone' in needle:
                    node = res[needle['bs4_getone']]
                    if 'bs4_extractor' in needle and callable(needle['bs4_extractor']):
                        if self.debug:  print('[GetOne] Adding node %s using external extractor...' %node)
                        extracts = needle['bs4_extractor'](node)
                    else:
                        if self.debug:  print('[Getall] Adding node %s as string...' %node)
                        extracts = node.string

                else:
                    node = res[0]
                    if 'bs4_extractor' in needle and callable(needle['bs4_extractor']):
                        if self.debug:  print('[default] Adding node %s using external extractor...' %node)
                        extracts = needle['bs4_extractor'](node)
                    else:
                        if self.debug:
                            if node.string : print('[default] Adding node %s as string...%s' %(node, node.string.encode('utf-8', 'ignore')))
                            else:print('[default] Adding node %s [EMPTY]' %(node))
                        extracts = node.string

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
        if isinstance(self.params,dict) :
            for k, v in self.extracted_values.items():
                for par,parval in self.params.items():
                    if isinstance(v, list) or isinstance(v, tuple): v = ' '.join(v)
                    self.params[par]=parval.replace('%%{%s}'%k.encode('utf-8', 'ignore'), v.encode('utf-8', 'ignore'))
        elif isinstance(self.params,str) :
            for k, v in self.extracted_values.items():
                if isinstance(v, list) or isinstance(v, tuple): v = ' '.join(v)
                self.params=self.params.replace('%%{%s}'%k.encode('utf-8', 'ignore'), v.encode('utf-8', 'ignore'))

        # If replacement in keys is necessary do it here


    def _prepare_headers(self):
        self.headers = copy.deepcopy(self.waves[self.cur_wave]['headers'])
        for k, v in self.extracted_values.items():
            if v == None:
                v=''
            elif isinstance(v, list) or isinstance(v, tuple):
                v = ' '.join([x if x else '' for x in v])
            elif isinstance(v, bool):
                v = 'True' if v else 'False'


            for par,parval in self.headers.items():
                if isinstance(v, str) or isinstance(v, unicode):
                    self.headers[par]=parval.replace('%%{%s}'%k.encode('utf-8', 'ignore'), v)

        # If replacement in keys is necessary do it here
