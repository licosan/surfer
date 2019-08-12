# surfer
Grab anything from web pages. Say what you want, where it is, how to validate and extrat, surfer will do the rest !
Tired to write boiler-plate python code on top of *requests*, to automate some intricated web-scrapping ?
Just describe your surf session scenario, directly in python (in a dictionnary), pass it over to surfer and just get your formated results.

* For TEXT: Extract with regular expressions from the raw text
* For HTML: Find tags, attributes or text nodes using (beautifulsoup) parsed html.
* For XML: Find tags, attributes or text nodes using (beautifulsoup) parsed XML.


```python
def bad_http_response(result, surfer):
    print('Received a bad HTTP response %s at step "%s"' %(result.status_code, surfer.cur_wave))
    surfer.next_wave = None # stop it !

def test_fail(data, surfer):
    print('Content test failed step "%s"' %(surfer.cur_wave))
    print('DATA=%s' %data)
    surfer.next_wave = None # stop it !    

def process_results(data, surfer):
    print("EXTRACTED:")
    pprint(surfer.extracted_values)


if __name__ == '__main__':
    waves = { 0: {  'sub_url':          'https://www.ecb.europa.eu/stats/eurofxref/eurofxref-daily.xml',
                    'method':           'GET', # get / post / put / delete / head / options
                    'params':           {},
                    'headers':          {   'Accept':'application/json, text/javascript, */*; q=0.01',
                                            'Referer': 'https://www1.oanda.com/currency/converter/',
                                            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.92 Safari/537.36',
                                        },  
                    'parsing':          'xml',
                    'test_response':    lambda content, s: True,
                    'if_not_200':       bad_http_response,
                    'if_test_fail':     test_fail,
                    'if_test_ok':       process_results, #callback to position someth when ok (surfer goes on to next wave anyway unless you set next_wave to None)
                    'extract':          [{  'name': 'USD', #<cube currency="USD" rate="1.1182">
                                            'bs4_selectors': ['Cube[currency="USD"]'], 
                                            'bs4_extractor': lambda node: node['rate']
                                         }],
                    'next_wave':        None, # or None if finished
                }, 
            }
    s = surfer(base_url=base_url, cookies=True, allow_redirects=True, debug=ARGS.debug)
    s.surf(waves, 0)
```
