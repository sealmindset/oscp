#!/usr/bin/env python

import math
import time
from multiprocessing import Queue
import multiprocessing

def factorize_naive(n):
    factors = []
    for div in range(2, int(n**.5)+1):
        while not n % div:
            factors.append(div)
            n //= div
    if n != 1:
        factors.append(n)
    return factors

nums = range(100000)
nprocs = 4

def worker(nums, out_q):
    """ The worker function, invoked in a process. 'nums' is a
        list of numbers to factor. The results are placed in
        a dictionary that's pushed to a queue.
    """
    outdict = {}
    for n in nums:
        outdict[n] = factorize_naive(n)
    out_q.put(outdict)

# Each process will get 'chunksize' nums and a queue to put his out
# dict into
out_q = Queue()
chunksize = int(math.ceil(len(nums) / float(nprocs)))
procs = []

for i in range(nprocs):
    p = multiprocessing.Process(
            target=worker,
            args=(nums[chunksize * i:chunksize * (i + 1)],
                  out_q))
    procs.append(p)
    p.start()

# Collect all results into a single result dict. We know how many dicts
# with results to expect.
resultdict = {}
for i in range(nprocs):
    resultdict.update(out_q.get())

time.sleep(5)

# Wait for all worker processes to finish
for p in procs:
    p.join()

print resultdict

time.sleep(15)
