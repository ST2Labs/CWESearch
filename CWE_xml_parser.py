# -*- coding: utf-8 -*-
#!/usr/bin/env python
"""
CWE_xml_parser.py

Copyright 2015 Julian J. Gonzalez
www.st2labs.com | @ST2Labs

This is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation version 2 of the License.

Thi is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along it; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
"""
import logging
import argparse
import re
import xml.etree.cElementTree as ET

logging.basicConfig(level=logging.DEBUG,
                    format='%(name)s: %(message)s',
                    )


def findWeaknes(CweId):

    logger = logging.getLogger('findWeaknes')
    try:
        filepath_ = 'db/cwec_v2.8.xml'
        tree = ET.ElementTree()
        dom = tree.parse(filepath_)
        w = dom.findall("Weaknesses/Weakness")
        for wi in w:
            id_ = str(wi.attrib['ID'])
            if str(CweId) in id_:
                desc = wi.find('Description/Description_Summary')
                return desc.text
    except Exception, e:
        logger.debug('%s', e)


def findDescription(CweId):

    logger = logging.getLogger('findDescription')

    try:
        filepath_ = 'db/cwec_v2.8.xml'
        tree = ET.ElementTree()
        dom = tree.parse(filepath_)
        w = dom.findall("Weaknesses/Weakness")
        c = dom.findall("Compound_Elements/Compound_Element")

        for wi in w:
            id_ = str(wi.attrib['ID'])
            if str(CweId) in id_:
                desc = wi.find('Description/Description_Summary')
                t = desc.text
                break
            else:
                t = None
        if t is None:
            for ci in c:
                id_ = str(ci.attrib['ID'])
                if str(CweId) in id_:
                    desc = ci.find('Description/Description_Summary')
                    t = desc.text
                    break
        t = ' '.join(t.split('\n'))
        t = ' '.join(t.split('\t'))
        re.sub('\s+', ' ', t)
        print repr(t)
        return t

    except Exception, e:
        logger.debug('%s', e)


if __name__ == "__main__":

    logger = logging.getLogger('Main')
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=
        """
            CWESearch  Engine v0.01
            XML Parser for CWE DataBase
        """)

    parser.add_argument('cwe',
                            help='CWE ID',
                            metavar='<cwe_id>')

    args = parser.parse_args()

    t = findDescription(args.cwe)
    logger.info('%s', t)
