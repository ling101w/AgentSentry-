from __future__ import annotations

from agentsentry.models import Event


def test_list_run_events_is_not_capped_by_global_recent_window(store):
    store.create_run("target-run", "target", None, "full")
    store.add_event(Event(run_id="target-run", type="first", payload={"index": 1}))
    store.add_event(Event(run_id="target-run", type="second", payload={"index": 2}))

    for index in range(230):
        run_id = f"noise-run-{index}"
        store.create_run(run_id, "noise", None, "full")
        store.add_event(Event(run_id=run_id, type="noise", payload={"index": index}))

    global_recent = store.list_events(limit=200)["events"]
    assert not any(event["run_id"] == "target-run" for event in global_recent)

    target_events = store.list_run_events("target-run")
    assert [event["type"] for event in target_events] == ["first", "second"]
    assert target_events[0]["rowid"] < target_events[1]["rowid"]


def test_list_run_events_after_rowid_returns_incremental_events(store):
    store.create_run("run-1", "target", None, "full")
    first = Event(run_id="run-1", type="first", payload={})
    second = Event(run_id="run-1", type="second", payload={})
    store.add_event(first)
    store.add_event(second)

    events = store.list_run_events("run-1")
    assert [event["id"] for event in events] == [first.id, second.id]

    after_first = store.list_run_events("run-1", after_rowid=events[0]["rowid"])
    assert [event["id"] for event in after_first] == [second.id]
