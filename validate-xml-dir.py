#!/usr/bin/env python3
import asyncio
import csv
import hashlib
import os
import shutil
import sys
from contextlib import suppress
from functools import partial
from glob import glob
from itertools import islice
from subprocess import Popen, PIPE
from xml.etree import ElementTree as ET


# configs
report_as_csv = False
ignore_missing_signature = (
    True if os.environ.get('ENFORCESIGNATURE') is None else False
)
term_columns, _ = shutil.get_terminal_size()
xsd_base_path = os.environ["XSD_DIRECTORY"]
xsd_paths = glob(xsd_base_path + '/**/*.xsd', recursive=True)


def strip_ns(root_node):
    namespace = ''
    for el in root_node.iter():
        if '}' in el.tag:
            namespace_, tag = el.tag.split('}', 1)
            namespace = namespace_.strip('{')
            el.tag = tag
    assert namespace
    return root_node, namespace


def get_xsd_type(xsd_path):
    root, _ = strip_ns(ET.parse(xsd_path).getroot())
    found = None
    version = root.attrib["targetNamespace"].split("/")[-1]
    assert version
    iterator = root.iter()
    while not found:
        try:
            el = next(iterator)
        except:  # noqa
            break
        name = el.attrib.get('name')
        if not name:
            continue
        if name.lower() == 'esocial':
            continue
        return name, version
    raise Exception("Couldn't resolve xsd name")


xsd_paths_registry = {
    get_xsd_type(xsd): xsd
    for xsd in xsd_paths
}


def fix_xml_text(text):
    return (text
            .replace('\n', '@')
            .replace('@/home', '\n/home')
            .replace('@', '\\\\n'))


def nth(iterable, n, default=None):
    "Returns the nth item or a default value"
    return next(islice(iterable, n, None), default)


def validate_xml(xml_path):
    root, namespace = strip_ns(ET.parse(xml_path).getroot())
    xml_type = get_xml_type(root)
    version = namespace.split('/')[-1]
    assert version
    xsd_path = xsd_paths_registry[xml_type, version]

    command = ['xmllint', '--schema', xsd_path, xml_path, '--noout']
    p = Popen(command, stdout=PIPE, stderr=PIPE)
    stdout, stderr = p.communicate()

    stderr = fix_xml_text(stderr.decode('utf-8'))

    return (p.returncode, stdout.decode('utf-8').split('\n'),
            stderr.split('\n'))


def filter_validation(retcode, stdout, stderr):
    # uncomment to ignore this function
    # return retcode, stdout, stderr  # debug
    new_stderr = stderr
    if ignore_missing_signature:
        new_stderr = [
            line for line in stderr
            if 'signature' not in line.lower()
            if line
        ]
    new_retcode = retcode
    if len(new_stderr) == 1:
        new_stderr = []
        new_retcode = 0 if not new_stderr else retcode
    if len(new_stderr) == 0 and len(stderr) > 0:
        new_retcode = -1  # means errors were filtered

    new_stdout = [l for l in stdout if stdout]

    new_stderr = [
        l.strip() for l in new_stderr
        if 'fails to validate' not in l
    ]

    return new_retcode, new_stdout, new_stderr


def get_xml_type(node):
    return nth(node.iter(), 1).tag


def get_xml_version(node):
    return node.attrib["xmlns"].split("/")[-1]


def file_hash(filename):
    h = hashlib.sha256()
    with open(filename, 'rb', buffering=0) as f:
        for b in iter(lambda: f.read(128*1024), b''):
            h.update(b)
    return h.hexdigest()


async def full_validate_xml(xml_file):
    try:
        retcode, stdout, stderr = filter_validation(*validate_xml(xml_file))
        root, namespace = strip_ns(ET.parse(xml_file).getroot())
    except ET.ParseError as e:
        return (e, xml_file)
    xml_type = get_xml_type(root)
    sha256 = file_hash(xml_file)
    return (
        xml_file,
        sha256,
        namespace,
        xml_type,
        retcode,
        stdout,
        stderr,
    )


def print_report(result):
    print('-' * term_columns)
    try:
        xml_file, sha256, namespace, xml_type, retcode, stdout, stderr = result
    except:
        error, xml_file = result
        print(f'File:\t\t\t{xml_file}')
        print(f'Error:\t\t\tCouldn\'t parse as a XML file')
    else:
        print(f'File:\t\t\t{xml_file}')
        print(f'SHA-256:\t\t{sha256}')
        print(f'Namespace:\t\t{namespace}')
        print(f'XML Type:\t\t{xml_type}')
        print(f'Validation:\t\t{retcode}')
        print(f'Errors ({len(stderr)}):')
        for err_line in stderr:
            print(f'- {err_line}')


def csv_report(result, writer):
    try:
        xml_file, sha256, namespace, xml_type, retcode, _, stderr = result
    except ValueError:
        error, xml_file = result
        sha256 = namespace = xml_type = retcode = ''
        stderr = ["Couldn't parse file as XML"]
    if not stderr:
        writer.writerow([
            xml_file, sha256, namespace, xml_type, retcode, "Valid XML file"
        ])
    for err_line in stderr:
        writer.writerow([
            xml_file, sha256, namespace, xml_type, retcode, err_line
        ])


if __name__ == '__main__':
    # cli
    args = sys.argv[1:]
    with suppress(ValueError):
        args.remove('--csv')
        report_as_csv = True
    xml_files = [f for f in args if os.path.exists(f)]
    not_found_files = [f for f in args if not os.path.exists(f)]
    for f in not_found_files:
        print(f'WARNING: File not found: {f}', file=sys.stderr)
    if not xml_files:
        sys.exit("ERROR: misisng file arguments")
    print(f'Preparing to validate {len(xml_files)} files')
    print('Ignoring missing signatures: ',
          'YES' if ignore_missing_signature else 'NO')

    # main loop
    to_do = [full_validate_xml(f) for f in xml_files]
    wait_coroutine = asyncio.wait(to_do)
    loop = asyncio.get_event_loop()
    res, _ = loop.run_until_complete(wait_coroutine)
    loop.close()

    # output
    handle_outcome = (partial(csv_report, writer=csv.writer(sys.stdout))
                      if report_as_csv else print_report)
    for outcome in res:
        handle_outcome(outcome.result())
