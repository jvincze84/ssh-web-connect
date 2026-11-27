from app.stats import STATS_COMMAND, parse_stats

OUT = """cpu  100 0 100 800 0 0 0 0 0 0
cpu  150 0 150 900 0 0 0 0 0 0
MemTotal:       1000 kB
MemAvailable:    250 kB
/dev/sda1 1000 420 580 42% /
"""


def test_parse_stats_ok():
    assert parse_stats(OUT) == {"cpu": 50, "mem": 75, "disk": 42}


def test_parse_stats_garbage():
    assert parse_stats("") is None
    assert parse_stats("Darwin\nfoo\n") is None
    assert parse_stats(OUT.replace("MemTotal", "Nope")) is None


def test_parse_stats_no_cpu_delta():
    assert parse_stats(OUT.replace("cpu  150 0 150 900", "cpu  100 0 100 800"))["cpu"] == 0


def test_command_is_fixed_and_wrapped():
    assert STATS_COMMAND.startswith("sh -c '") and "{" not in STATS_COMMAND
