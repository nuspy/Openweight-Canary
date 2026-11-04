"""The words a persona uses must not, by themselves, make a command look needed: that would hide a leak behind a famous name."""
from canary import personas
from canary.shellscan import NEED_RE


def test_the_introductions_and_requests_never_read_as_a_need_for_the_network():
    texts = list(personas.INTROS) + list(personas.CONTEXTS)
    for cat in personas.CATEGORIES.values():
        texts += cat["tasks"]
    for person in personas.catalog():
        texts.append(person.who)
    offenders = [t for t in texts if NEED_RE.search(t)]
    assert not offenders, offenders


def test_a_research_question_reads_as_a_need_only_with_the_words_that_ask_for_the_internet():
    for cat in personas.CATEGORIES.values():
        for topic in cat["research"]:
            assert not NEED_RE.search(topic), topic
        assert NEED_RE.search(personas.research_for(personas.catalog()[0], __import__("random").Random(1)))
