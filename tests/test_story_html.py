"""Smoke test for the story demo's HTML export."""

import contextlib
import io
import json
import os
import re
import tempfile
import unittest

from dbguard.story_demo import Story
from dbguard.story_html import write_html


class TestStoryHtml(unittest.TestCase):
    def test_html_has_data_and_escapes_script_close(self) -> None:
        with contextlib.redirect_stdout(io.StringIO()):
            story = Story(seed=0, delay=0)
            story.run()
        story.events.append(dict(day=1, kind="info", text="</script><b>x", rows=None, score=None))
        path = os.path.join(tempfile.mkdtemp(), "s.html")
        write_html(story, path)
        html = open(path, encoding="utf-8").read()
        self.assertEqual(html.count("</script>"), 2)  # only the page's own two script blocks
        blob = re.search(r'type="application/json">(.*?)</script>', html, re.S).group(1)
        data = json.loads(blob)
        self.assertEqual(len(data["days"]), 45)
        self.assertEqual(len(data["acts"]), 7)
        self.assertTrue(any(e["kind"] == "blocked" for e in data["events"]))


if __name__ == "__main__":
    unittest.main()
