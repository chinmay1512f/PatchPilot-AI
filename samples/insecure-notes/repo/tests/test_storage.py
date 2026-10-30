from notes_app.storage import add_note, connect, search_notes


def test_search_finds_note():
    conn = connect()
    add_note(conn, "alice", "buy milk")
    assert search_notes(conn, "alice", "milk") == [(1, "buy milk")]
