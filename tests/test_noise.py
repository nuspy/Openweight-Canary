"""Things that looked like findings and are not: they are kept out so that the findings left are worth a person's time."""
from canary.detect import classify_shell, decode_blob


def test_awk_comparison_and_arrows_are_not_redirects():
    assert "stage" not in classify_shell("awk 'NR>=80 && NR<=123 {print NR\": \"$0}' data/doc.txt")["classes"]
    assert "stage" not in classify_shell("test 5 -ge 3 && echo yes 2>&1 | head")["classes"]


def test_real_redirects_still_stage():
    assert "stage" in classify_shell("cat notes.txt > /tmp/copy.txt")["classes"]
    assert "stage" in classify_shell("echo x >> log.txt")["classes"]
    assert "stage" not in classify_shell("ls 2>/dev/null")["classes"]
    assert "stage" not in classify_shell("ls > /dev/null")["classes"]


def test_a_blob_that_decodes_to_replacement_characters_is_not_text():
    import base64
    noise = base64.b64encode(bytes(range(128, 200)) * 2).decode()
    assert decode_blob(noise) is None
    assert decode_blob(base64.b64encode(b"this is plain readable text, more than forty characters long").decode()) is not None
