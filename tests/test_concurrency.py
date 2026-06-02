"""Concurrency helper and the parallel crawler."""

import time

from ava.core.concurrency import parallel_collect
from ava.core.http_client import GlobalCapReached
from ava.crawler.static_crawler import Crawler
from tests.helpers import R


def test_parallel_collect_flattens_and_runs_concurrently(quiet_logger):
    def slow(x):
        time.sleep(0.05)
        return [x]

    t = time.time()
    out = parallel_collect(slow, range(8), concurrency=4, logger=quiet_logger)
    parallel = time.time() - t
    assert sorted(out) == list(range(8))
    # 8 * 0.05 = 0.4s serial; with 4 workers it should be well under that.
    assert parallel < 0.3


def test_parallel_collect_skips_cap_and_errors(quiet_logger):
    def fn(x):
        if x == 5:
            raise GlobalCapReached(100)
        if x == 7:
            raise ValueError("boom")
        return [x]

    out = sorted(parallel_collect(fn, range(10), concurrency=4, logger=quiet_logger))
    assert out == [0, 1, 2, 3, 4, 6, 8, 9]


def test_serial_path_equivalence(quiet_logger):
    out = parallel_collect(lambda x: [x * 2], range(5), concurrency=1, logger=quiet_logger)
    assert sorted(out) == [0, 2, 4, 6, 8]


def test_parallel_crawler_correctness(quiet_logger):
    pages = {
        "https://e.com/": '<a href="/a">a</a><a href="/b">b</a>'
                          '<form method="post" action="/login">'
                          '<input name="csrf" type="hidden"></form>',
        "https://e.com/a": '<a href="/c?id=1">c</a>',
        "https://e.com/b": "x",
        "https://e.com/c?id=1": "leaf",
    }

    class FC:
        def get(self, url, **kw):
            return R(url=url, status=200, headers={"content-type": "text/html"},
                     text=pages.get(url, "x"))

    eps = {e.url for e in Crawler(FC(), quiet_logger, max_depth=3, concurrency=4).crawl(
        "https://e.com/")}
    assert "https://e.com/c?id=1" in eps        # nested link followed
    assert "https://e.com/login" in eps          # form action recorded
