#!/usr/bin/env python

import os.path
import zipfile
import tempfile
import random
import string
import shutil
import json

from os.path  import basename

class Unpacker(object):

   #--------------------------------------------------------------------------
   # 
   #--------------------------------------------------------------------------
   def unzip(self, zip_src, unzip_dir):
       try:
           zip = zipfile.ZipFile(r'{0}'.format(zip_src))
           zip.extractall(r'{0}'.format(unzip_dir))
       except:
           return False

       return True

   #--------------------------------------------------------------------------
   # 
   #--------------------------------------------------------------------------
   def entropy(self, length):
       return ''.join(random.choice(string.lowercase) for i in range (length))


   #--------------------------------------------------------------------------
   # 
   #--------------------------------------------------------------------------
   def unpack_zipfile(self, zipfile):

        if not os.path.isfile(zipfile):
            raise Exception("Error: zipfile, not found!")

        # Create unique working direction into which the zip file is expanded

        self.unzip_dir = "{0}/{1}_{2}".format(tempfile.gettempdir(),
                                              os.path.splitext(basename(zipfile))[0],
                                              self.entropy(6))

        #print("unzip_dir: {0}".format(self.unzip_dir))

        if self.unzip(zipfile, self.unzip_dir) == False:
            raise Exception("unzip failed")

        # Check that "application.dat" exist in directory.

        with open("{0}/manifest.json".format(self.unzip_dir), 'r') as f:
            manifest = json.load(f)

        datfile = "{0}/{1}".format(self.unzip_dir, manifest['manifest']['application']['dat_file'])
        if not os.path.isfile(datfile):
            raise Exception("No DAT file found")

        # Check that "application.[bin]" exists in directory.

        binfile = "{0}/{1}".format(self.unzip_dir, manifest['manifest']['application']['bin_file'])
        if not os.path.isfile(binfile):
            raise Exception("No BIN file found")

        #print("bin: {0}".format(binfile))
        #print("dat: {0}".format(datfile))

        return binfile, datfile

   #--------------------------------------------------------------------------
   # 
   #--------------------------------------------------------------------------
   def delete(self):
       # delete self.unzip_dir and its contents
       shutil.rmtree(self.unzip_dir)


