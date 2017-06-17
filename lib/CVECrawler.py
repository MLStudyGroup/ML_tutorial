import requests
import tempfile
import simplejson as json
from StringIO import StringIO
from zipfile import ZipFile

import numpy as np

class CVECrawler(object):
  
  @classmethod
  def download(cls, year):
    url = 'https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-{}.json.zip'.format(year)
    r = requests.get(url, stream=True)
    unzipdata = None
    with tempfile.TemporaryFile() as fp:
      for chunk in r.iter_content(chunk_size=1024):
        if chunk:
          fp.write(chunk)
      fp.seek(0)
      zip_io = StringIO()
      zipdata = fp.read()
      zip_io.write(zipdata)
      zipfile = ZipFile(zip_io)
      unzipfile = zipfile.namelist()[0]
      zipfile.extractall()
      with open(unzipfile) as unzip_fp:
        unzipdata = json.load(unzip_fp)
 
    print 'number of downloaded CVE :', unzipdata['CVE_data_numberOfCVEs']
    print 'refresh date : ', unzipdata['CVE_data_timestamp']       
    return cls.preprocess(unzipdata['CVE_Items'])   

  @classmethod
  def preprocess(cls, json_cve_items):
     cves = []
     for cve_item in json_cve_items:
       try:
         cve_id = cve_item['CVE_data_meta']['CVE_ID']
         cvss_v3 = cve_item['CVE_impact']['CVE_impact_cvssv3']['bm']['score']
         desc = cve_item['CVE_description']['CVE_description_data'][0]['value']
         cves.append([cve_id, cvss_v3, desc])
       except:
         pass
     return np.array(cves)

if __name__ == '__main__':
  cves = CVECrawler.download('2017')
  print cves.shape
      
