"""
Copyright 2020-2024, CCL Forensics

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""
import json
import sys
import pathlib
from ccl_chromium_reader import ccl_chromium_indexeddb
import re
from rich import print_json

def main(args):
    ldb_path = pathlib.Path(args[0])
    wrapper = ccl_chromium_indexeddb.WrappedIndexDB(ldb_path)

    def bad_deserializer_data_handler(key: ccl_chromium_indexeddb.IdbKey, buffer: bytes):
        print(f"Error reading IndexedDb record {key}", file=sys.stderr)

    for db_info in wrapper.database_ids:
        db = wrapper[db_info.dbid_no]
        print("------Database------")
        print(f"db_number={db.db_number}; name={db.name}; origin={db.origin}")
        # print(f'Object Stores: {len(db.object_store_names)} \n')
        print("\t---Object Stores---")
        for obj_store_name in db.object_store_names:
            obj_store = db[obj_store_name]
            print(f"\tobject_store_id={obj_store.object_store_id}; name={obj_store.name}")
            for rec in obj_store.iterate_records(
                    bad_deserializer_data_handler=bad_deserializer_data_handler):
                if rec is not None and rec.key.raw_key == b'\x01\x0e\x00s\x00t\x00o\x00r\x00e\x00-\x00s\x00n\x00a\x00p\x00s\x00h\x00o\x00t':
                    print("\tExample record:")
                    print(f"\tkey: {rec.key} AKA {rec.key.raw_key}")
                    raw_string = str(rec.value) + r"}}"
                    parsed_string = raw_string.replace("\'", "\"")
                    parsed_string = parsed_string.replace("<Undefined>", "\"<Undefined>\"")
                    parsed_string = parsed_string.replace("True", "\"True\"")
                    parsed_string = parsed_string.replace("False", "\"False\"")
                    parsed_string = re.sub('"selectors":.*],', '', parsed_string)
                    json_result = json.loads(parsed_string)
                    # print_json(data=json_result)
            print()
        print("DONE")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"USAGE: {pathlib.Path(sys.argv[0]).name} <ldb dir path>")
        exit(1)
    main(sys.argv[1:])
