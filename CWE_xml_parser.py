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


def split_len(seq, length):
    return [seq[i:i + length] for i in range(0, len(seq), length)]


def getTitle(Id):

    logger = logging.getLogger('findTitle')

    try:
        filepath_ = 'db/cwec_v2.8.xml'
        tree = ET.ElementTree()
        dom = tree.parse(filepath_)
        w = dom.findall("Weaknesses/Weakness")
        c = dom.findall("Compound_Elements/Compound_Element")

        for wi in w:
            id_ = str(wi.attrib['ID'])
            if str(Id) in id_:
                t = wi.attrib['Name']
                break
            else:
                t = None
        if t is None:
            for ci in c:
                id_ = str(ci.attrib['ID'])
                if str(Id) in id_:
                    t = ci.attrib['Name']
                    break
        t = ' '.join(t.split('\n'))
        t = ' '.join(t.split('\t'))
        t = re.sub('\s+', ' ', t)

        return t
    except Exception, e:
        logger.debug('%s', e)


def findText(Id, path):

    logger = logging.getLogger('findText')

    try:
        filepath_ = 'db/cwec_v2.8.xml'
        tree = ET.ElementTree()
        dom = tree.parse(filepath_)
        w = dom.findall("Weaknesses/Weakness")
        c = dom.findall("Compound_Elements/Compound_Element")

        for wi in w:
            id_ = str(wi.attrib['ID'])
            if str(Id) in id_:
                desc = wi.find(path)
                t = desc.text
                break
            else:
                t = None
        if t is None:
            for ci in c:
                id_ = str(ci.attrib['ID'])
                if str(Id) in id_:
                    desc = ci.find(path)
                    t = desc.text
                    break
        t = ' '.join(t.split('\n'))
        t = ' '.join(t.split('\t'))
        t = re.sub('\s+', ' ', t)

        return t

    except Exception, e:
        logger.debug('%s', e)


def findMappingId(Id, path, mapping):

    logger = logging.getLogger('findMappingId')

    try:
        filepath_ = 'db/cwec_v2.8.xml'
        tree = ET.ElementTree()
        dom = tree.parse(filepath_)
        w = dom.findall("Weaknesses/Weakness")
        c = dom.findall("Compound_Elements/Compound_Element")

        for wi in w:
            id_ = str(wi.attrib['ID'])
            if str(Id) in id_:
                d = wi.findall(path)
                for di in d:
                    map_ = di.attrib['Mapped_Taxonomy_Name']
                    if mapping in map_:
                        desc = di.find('Mapped_Node_ID')
                        t = desc.text
                break
            else:
                t = None
        if t is None:
            for ci in c:
                id_ = str(ci.attrib['ID'])
                if str(Id) in id_:
                    d = ci.findall(path)
                    for di in d:
                        map_ = di.attrib['Mapped_Taxonomy_Name']
                        if mapping in map_:
                            desc = di.find('Mapped_Node_ID')
                            t = desc.text
                    break
        t = ' '.join(t.split('\n'))
        t = ' '.join(t.split('\t'))
        t = re.sub('\s+', ' ', t)
        return t

    except Exception, e:
        logger.debug('%s', e)


def getWascID(id):
    path = 'Taxonomy_Mappings/Taxonomy_Mapping'
    return findMappingId(id, path, 'WASC')


def getCWESummary(id):
    path = 'Description/Description_Summary'
    return findText(id, path)


def getCWEDescExtend(id):
    path = 'Description/Extended_Description/Text'
    return findText(id, path)


def getCWEAttackConsequence(id):
    path = 'Common_Consequences/Common_Consequence/Consequence_Note/Text'
    return findText(id, path)


if __name__ == "__main__":

    logger = logging.getLogger('Main')
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=
        """
            CWESearch  Engine v1.0
        """)

    parser.add_argument('cwe',
                            help='CWE ID',
                            metavar='<cwe_id>')

    cpath = 'Common_Consequences/Common_Consequence/Consequence_Note/Text'

    args = parser.parse_args()
    id_cwe = args.cwe
    title = getTitle(id_cwe)
    summary = getCWESummary(id_cwe)
    extend = getCWEDescExtend(id_cwe)
    context = getCWEAttackConsequence(id_cwe)
    wasc_id = getWascID(id_cwe)

    logger.info('ID: %s', id_cwe)
    logger.info('WASC ID: %s', wasc_id)
    logger.info('Title: %s', title)
    logger.info('Description summary: %s', summary)
    logger.info('Description Extended: %s', extend)
    logger.info('Attack Consequence: %s', context)
