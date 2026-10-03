#!/usr/bin/env python3
"""Host regressions using production functions with isolated mount/file doubles."""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def function(source, name):
    match = re.search(r'static (?:int|void)\n' + re.escape(name) + r'\(', source)
    if not match:
        return ''
    start = source.index('{', match.end())
    depth = 1
    end = start + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[match.start():end]


STUBS = r'''
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#define GC_SHADOWMOUNT_HOLD_FILE "/isolated/hold"
static int mounted, mount_error, wrong_hash, probes, holds, releases;
static int marker = 1, unmount_rc;
static const char good_sha[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static void gc_log(const char *format, ...) { (void)format; }
static int sha256_hex_valid(const char *s) { return s && strlen(s) == 64; }
static int ampr_folder_target_probe(const char *root, char *path, size_t size, char *sha) {
  (void)root; probes++;
  if(!mounted) return 0;
  snprintf(path, size, "/isolated/fakelib/libSceAmpr.sprx");
  strcpy(sha, good_sha); if(wrong_hash) sha[0] = 'b'; return 1;
}
static int shadowmount_runtime_hold(const char *id, int *held, char *err, size_t size) {
  (void)id; holds++;
  if(mount_error) { snprintf(err, size, "busy"); return -1; }
  *held = !mounted; mounted = 1; return 0;
}
static void shadowmount_runtime_release(const char *id, int *held) {
  (void)id; if(*held) { releases++; mounted = 0; *held = 0; }
}
static int read_link_file(const char *path, char *out, size_t size) {
  (void)path; if(!marker) return -1;
  snprintf(out, size, "PPSA01289"); return 0;
}
static int valid_title_id(const char *id) { return strcmp(id, "PPSA01289") == 0; }
static int shadowmount_on_demand_runtime(void) { return 1; }
static int gc_shadowmount_api_unmount_title(const char *id, char *detail, size_t size) {
  (void)id; (void)detail; (void)size; return unmount_rc;
}
static int fake_unlink(const char *path) { (void)path; marker = 0; return 0; }
#define unlink fake_unlink
'''

MAIN = r'''
int main(int argc, char **argv) {
  assert(argc == 2); char err[256] = {0};
  if(!strcmp(argv[1], "ampr-success")) {
    assert(update_ampr_verify_mounted_hash("PPSA01289", "/isolated/mount", good_sha, err, sizeof(err)) == 0);
    assert(holds == 1 && probes == 1 && releases == 1 && !mounted);
  } else if(!strcmp(argv[1], "ampr-hash-failure")) {
    wrong_hash = 1;
    assert(update_ampr_verify_mounted_hash("PPSA01289", "/isolated/mount", good_sha, err, sizeof(err)) == -1);
    assert(probes == 1 && releases == 1 && !mounted);
  } else if(!strcmp(argv[1], "ampr-mount-failure")) {
    mount_error = 1;
    assert(update_ampr_verify_mounted_hash("PPSA01289", "/isolated/mount", good_sha, err, sizeof(err)) == -1);
    assert(holds == 1 && probes == 0 && releases == 0);
  } else if(!strcmp(argv[1], "existing-mount")) {
    mounted = 1;
    assert(update_ampr_verify_mounted_hash("PPSA01289", "/isolated/mount", good_sha, err, sizeof(err)) == 0);
    assert(mounted && releases == 0);
  } else {
    unmount_rc = atoi(argv[1]); release_stale_shadowmount_runtime_hold();
    assert(marker == (unmount_rc != 0));
  }
  return 0;
}
'''


class RuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = (ROOT / 'src/gc_api.c').read_text()
        cls.temp = tempfile.TemporaryDirectory()
        base = Path(cls.temp.name)
        snippets = '\n'.join(function(source, name) for name in (
            'update_ampr_verify_mounted_hash_mounted',
            'update_ampr_verify_mounted_hash', 'release_stale_shadowmount_runtime_hold'))
        (base / 'test.c').write_text(STUBS + snippets + MAIN)
        cls.binary = base / 'test'
        subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra',
                        '-Werror', '-Wno-unused-function', str(base / 'test.c'),
                        '-o', str(cls.binary)], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_ampr_mounted_read_and_cleanup(self):
        for case in ('ampr-success', 'ampr-hash-failure', 'ampr-mount-failure', 'existing-mount'):
            with self.subTest(case=case):
                result = subprocess.run([str(self.binary), case], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_stale_marker_requires_success(self):
        # Success, PS5 EBUSY (16), another API error, and transport failure.
        for status in ('0', '16', '5', '-1'):
            with self.subTest(status=status):
                result = subprocess.run([str(self.binary), status], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
