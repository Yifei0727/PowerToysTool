#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import codecs
import csv

from power_fake_toys import generate_mst

if __name__ == '__main__':
    import sys
    import argparse
    import json

    opt_args = argparse.ArgumentParser()
    opt_args.add_argument("-o", "--out-file", type=str, help="output result as file, default stdout", default=None)
    opt_args.add_argument("--out-format", type=str, help="output format, csv or json, default csv",
                          choices=["csv", "json"],
                          default="csv")
    opt_args.add_argument("--key", type=str, required=True,
                          help="32H for SM4 and 3DES PINBlock, eg. 11111111111111111111111111111111")
    opt_args.add_argument("-n", "--num-records", type=int, help="generate how many records as output, default 1",
                          default=1)

    args = opt_args.parse_args()

    key = codecs.decode(args.key, "hex")

    if args.out_file:
        writer = open(args.out_file + '_%s.%s' % (args.key.upper(), args.out_format), mode="w")
    else:
        writer = sys.stdout

    if args.out_format == 'csv':
        csv_header = ['PAN', 'PSN', 'VER', 'EXPIRETIME', 'TIMESTAMP', 'ATC', 'MST']
        csv_writer = csv.writer(writer)
        csv_writer.writerow(csv_header)

    for i in range(args.num_records):
        one_rec = generate_mst(key)
        if args.out_format == 'csv':
            row = [one_rec[k] for k in csv_header]
            csv_writer.writerow(row)
        else:
            writer.write(json.dumps(one_rec))
            writer.write("\n")

    writer.close()
