#!/usr/bin/env python3

import sys
import subprocess
import re

DETSIGN_BIN = sys.argv[1]
if not DETSIGN_BIN:
    raise ValueError(
        "Empty path to detsign binary (first commandline argument)"
    )

CURRENT_TEST_NUM = 0
CURRENT_TEST_NAME = ""
NUM_TESTS = 0
ALL_TESTS = []


def fail_test(msg):
    print(msg, file=sys.stderr)
    raise ValueError("TEST FAILED")


def match_any_line(regexp, lns):
    rex = re.compile(regexp)
    for ln in lns:
        match = rex.match(ln)
        if match:
            return match
    return None


def detsign_run(
    *args,
    stdin=None,
    match_stdout=None,
    match_stderr=None,
    match_returncode=None,
):
    run_args = dict()
    if stdin is not None:
        run_args["input"] = stdin.encode("utf-8")
    ret = subprocess.run(
        [DETSIGN_BIN] + list(args), capture_output=True, **run_args
    )
    failure_msg = None
    stdout_str = ret.stdout.decode("utf-8")
    stderr_str = ret.stderr.decode("utf-8")
    if match_returncode is not None:
        if ret.returncode != match_returncode:
            failure_msg = f"invalid return code: expected={match_returncode}, actual={ret.returncode}"

    if match_stdout is not None and failure_msg is None:
        if not match_any_line(match_stdout, stdout_str.splitlines()):
            failure_msg = f"STDOUT does not match pattern: {match_stdout}"

    if match_stderr is not None and failure_msg is None:
        if not match_any_line(match_stderr, stderr_str.splitlines()):
            failure_msg = f"STDERR does not match pattern: {match_stderr}"

    if failure_msg is not None:
        fail_test(
            "\n".join(
                [failure_msg, f"STDOUT: {stdout_str}", f"STDERR: {stderr_str}"]
            )
        )


def write_file(path, contents):
    with open(path, "w") as out:
        out.write(contents)


def read_file(path):
    with open(path) as inp:
        return "".join(inp.readlines())


def match_file_contents(path, contents):
    if read_file(path) != contents:
        fail_test(f"File contents of {path} does not match expected contents.")


def detsign_run_successfully(*args, **kwargs):
    detsign_run(*args, match_returncode=0, **kwargs)


def begin_test(nm):
    global CURRENT_TEST_NAME
    CURRENT_TEST_NAME = nm
    print(f"Running Test {CURRENT_TEST_NUM}/{NUM_TESTS}: {CURRENT_TEST_NAME}")


def run_tests():
    global NUM_TESTS
    NUM_TESTS = len(ALL_TESTS)
    nfailed = 0
    for i, test in enumerate(ALL_TESTS):
        global CURRENT_TEST_NUM
        CURRENT_TEST_NUM = 1 + i
        try:
            test()
        except:
            print("FAILED", file=sys.stderr)
            nfailed += 1
    if nfailed == 0:
        print("ALL TESTS SUCCESSFUL")
        sys.exit(0)
    else:
        print(f"{nfailed}/{NUM_TESTS} TESTS FAILED")
        sys.exit(1)


def def_test(fn):
    ALL_TESTS.append(fn)
    return fn


@def_test
def test_gen():
    begin_test("gen")
    detsign_run_successfully("gen", "-p", "foo.detsign.pub", stdin="foo\n")
    match_file_contents(
        "foo.detsign.pub", "jGdekNMskPgQXa-7rVwGFPhPsH_e0VdwHDbQKhIu5jc="
    )


@def_test
def test_gen_sign():
    begin_test("gen-sign")
    write_file("contents.txt", "CONTENTS")
    detsign_run_successfully(
        "gen-sign", "-p", "foo.detsign.pub", "contents.txt", stdin="foo\n"
    )
    match_file_contents(
        "contents.txt.detsign.sig",
        "vWhPEKVdVOsCO1OsynAtaOI6lUTLMm483tdqFNrY4RFsNjRtu3y5t_1C1J-ZPQvAOUcsvzRXwizmXRQO_lcuAA==",
    )


@def_test
def test_verify():
    begin_test("verify")
    detsign_run_successfully(
        "verify",
        "-p",
        "foo.detsign.pub",
        "contents.txt",
        match_stdout="contents.txt: Good Signature",
    )


@def_test
def test_gen_sign_fail_wrong_pubkey():
    begin_test("gen-sign with wrong pubkey")
    detsign_run(
        "gen-sign",
        "-p",
        "foo.detsign.pub",
        "contents.txt",
        stdin="foo2\n",
        match_returncode=1,
        match_stderr="Error: public keys don't match, wrong passphrase/subkeyid?",
    )


@def_test
def test_gen_verify_fail():
    begin_test("verify modified file")
    write_file("contents.txt", "CONTENTS2")
    detsign_run(
        "verify",
        "-p",
        "foo.detsign.pub",
        "contents.txt",
        match_returncode=1,
        match_stdout="contents.txt: Bad Signature",
    )


run_tests()
