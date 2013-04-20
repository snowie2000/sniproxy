#!/usr/bin/env python
# coding:utf-8
# Contributor:
#      Phus Lu        <phus.lu@gmail.com>

import sys
import os
import glob

sys.path += glob.glob('%s/*.egg' % os.path.dirname(os.path.abspath(__file__)))

import gevent
import gevent.server
import gevent.monkey
gevent.monkey.patch_all(dns=gevent.version_info[0] >= 1)


def main():
    print 'hello'

if __name__ == '__main__':
    main()
