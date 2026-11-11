import asyncio

from test_messenger_api import client_for, run
from test_star_gifts import ADMIN, env, headers  # noqa: F401  (env is a pytest fixture)


def test_replies_are_validated_and_returned(env) -> None:
    path, app = env

    async def scenario() -> None:
        async with await client_for(app) as client:
            first = (await client.post("/api/messages", headers=headers(101), json={"recipient_id": 102, "body": "hi"})).json()
            reply = await client.post(
                "/api/messages", headers=headers(102),
                json={"recipient_id": 101, "body": "hello", "reply_to_id": first["id"]},
            )
            assert reply.status_code == 201 and reply.json()["reply_to_id"] == first["id"]
            listed = (await client.get("/api/messages?with=102", headers=headers(101))).json()["messages"]
            assert listed[-1]["reply_to_id"] == first["id"] and listed[0]["reply_to_id"] is None
            assert listed[-1]["reply_to_body"] == "hi"
            assert listed[-1]["reply_to_sender_id"] == 101

            # A message of another conversation cannot be replied to.
            other = (await client.post("/api/messages", headers=headers(101), json={"recipient_id": ADMIN, "body": "x"})).json()
            bad = await client.post(
                "/api/messages", headers=headers(101),
                json={"recipient_id": 102, "body": "no", "reply_to_id": other["id"]},
            )
            assert bad.status_code == 404
            assert (await client.post(
                "/api/messages", headers=headers(101), json={"recipient_id": 102, "body": "no", "reply_to_id": "x"}
            )).status_code == 400

    run(scenario())


def test_edit_and_delete_private_messages_with_events(env) -> None:
    path, app = env

    async def scenario() -> None:
        async with await client_for(app) as client:
            cursor = (await client.get("/api/events", headers=headers(102))).json()["latest_id"]
            sent = (await client.post("/api/messages", headers=headers(101), json={"recipient_id": 102, "body": "typo"})).json()
            mid = sent["id"]

            assert (await client.patch(f"/api/messages/{mid}", headers=headers(102), json={"body": "x"})).status_code == 403
            assert (await client.patch(f"/api/messages/{mid}", headers=headers(101), json={"body": "  "})).status_code == 400
            edited = await client.patch(f"/api/messages/{mid}", headers=headers(101), json={"body": "fixed"})
            assert edited.status_code == 200
            put_edited = await client.put(f"/api/messages/{mid}", headers=headers(101), json={"body": "fixed via PUT"})
            assert put_edited.status_code == 200
            listed = (await client.get("/api/messages?with=101", headers=headers(102))).json()["messages"]
            assert listed[-1]["body"] == "fixed via PUT" and listed[-1]["edited_at"]

            events = (await client.get(f"/api/events?after_id={cursor}", headers=headers(102))).json()
            assert [(e["kind"], e["message_id"], e["scope"]) for e in events["events"]] == [
                ("edit", mid, "dm"), ("edit", mid, "dm")
            ]
            # The author does not get an event for their own action.
            assert (await client.get(f"/api/events?after_id={cursor}", headers=headers(101))).json()["events"] == []
            # Someone outside the conversation sees nothing.
            assert (await client.get(f"/api/events?after_id={cursor}", headers=headers(ADMIN))).json()["events"] == []

            assert (await client.delete(f"/api/messages/{mid}", headers=headers(102))).status_code == 403
            assert (await client.delete(f"/api/messages/{mid}", headers=headers(101))).status_code == 200
            assert (await client.delete(f"/api/messages/{mid}", headers=headers(101))).status_code == 404
            assert (await client.get("/api/messages?with=101", headers=headers(102))).json()["messages"] == []
            events = (await client.get(f"/api/events?after_id={events['latest_id']}", headers=headers(102))).json()
            assert [(e["kind"], e["message_id"]) for e in events["events"]] == [("delete", mid)]

    run(scenario())


def test_group_edit_delete_and_admin_rights(env) -> None:
    path, app = env

    async def scenario() -> None:
        async with await client_for(app) as client:
            group = (await client.post("/api/groups", headers=headers(101), json={"title": "Team"})).json()
            gid = group["id"]
            assert (await client.post(f"/api/groups/{gid}/members", headers=headers(101), json={"telegram_id": 102})).status_code in (200, 201)
            m1 = (await client.post(f"/api/groups/{gid}/messages", headers=headers(102), json={"body": "from member"})).json()
            m2 = (await client.post(f"/api/groups/{gid}/messages", headers=headers(101), json={"body": "from owner", "reply_to_id": m1["id"]})).json()
            assert m2["reply_to_id"] == m1["id"]
            assert (await client.post(f"/api/groups/{gid}/messages", headers=headers(101), json={"body": "x", "reply_to_id": 99999})).status_code == 404

            # Only the author edits.
            assert (await client.patch(f"/api/groups/{gid}/messages/{m1['id']}", headers=headers(101), json={"body": "hack"})).status_code == 403
            assert (await client.patch(f"/api/groups/{gid}/messages/{m1['id']}", headers=headers(102), json={"body": "edited"})).status_code == 200
            assert (await client.put(f"/api/groups/{gid}/messages/{m1['id']}", headers=headers(102), json={"body": "edited via PUT"})).status_code == 200
            # A member cannot delete the owner's message, the owner can delete anybody's.
            assert (await client.delete(f"/api/groups/{gid}/messages/{m2['id']}", headers=headers(102))).status_code == 403
            assert (await client.delete(f"/api/groups/{gid}/messages/{m1['id']}", headers=headers(101))).status_code == 200
            # Outsiders are refused.
            assert (await client.delete(f"/api/groups/{gid}/messages/{m2['id']}", headers=headers(ADMIN))).status_code == 403

            remaining = (await client.get(f"/api/groups/{gid}/messages", headers=headers(102))).json()["messages"]
            assert [m["id"] for m in remaining] == [m2["id"]]
            assert remaining[0]["reply_to_body"] == "from member"
            assert remaining[0]["reply_to_sender_id"] == 102

    run(scenario())


def test_channel_posts_can_be_edited_and_deleted_by_the_owner_only(env) -> None:
    path, app = env

    async def scenario() -> None:
        async with await client_for(app) as client:
            channel = (await client.post("/api/channels", headers=headers(101), json={"title": "News", "username": "news_ch"})).json()
            cid = channel["id"]
            post = (await client.post(f"/api/channels/{cid}/messages", headers=headers(101), json={"body": "first"})).json()
            assert (await client.patch(f"/api/channels/{cid}/messages/{post['id']}", headers=headers(102), json={"body": "x"})).status_code == 403
            assert (await client.patch(f"/api/channels/{cid}/messages/{post['id']}", headers=headers(101), json={"body": "second"})).status_code == 200
            assert (await client.put(f"/api/channels/{cid}/messages/{post['id']}", headers=headers(101), json={"body": "second via PUT"})).status_code == 200
            listed = (await client.get(f"/api/channels/{cid}/messages", headers=headers(102))).json()["messages"]
            assert listed[0]["body"] == "second via PUT" and listed[0]["edited_at"]
            assert (await client.delete(f"/api/channels/{cid}/messages/{post['id']}", headers=headers(102))).status_code == 403
            assert (await client.delete(f"/api/channels/{cid}/messages/{post['id']}", headers=headers(101))).status_code == 200
            assert (await client.get(f"/api/channels/{cid}/messages", headers=headers(102))).json()["messages"] == []

    run(scenario())


def test_read_markers_and_unread_counters(env) -> None:
    path, app = env

    async def scenario() -> None:
        async with await client_for(app) as client:
            ids = []
            for text in ("a", "b", "c"):
                ids.append((await client.post("/api/messages", headers=headers(101), json={"recipient_id": 102, "body": text})).json()["id"])

            conv = (await client.get("/api/conversations", headers=headers(102))).json()["conversations"][0]
            assert conv["unread_count"] == 3 and conv["my_read_id"] == 0
            # The sender has nothing unread and sees that nothing was read yet.
            mine = (await client.get("/api/conversations", headers=headers(101))).json()["conversations"][0]
            assert mine["unread_count"] == 0 and mine["peer_read_id"] == 0

            cursor = (await client.get("/api/events", headers=headers(101))).json()["latest_id"]
            read = await client.put("/api/read", headers=headers(102), json={"scope": "dm", "peer_id": 101, "last_read_id": ids[1]})
            assert read.status_code == 200 and read.json()["last_read_id"] == ids[1]
            conv = (await client.get("/api/conversations", headers=headers(102))).json()["conversations"][0]
            assert conv["unread_count"] == 1
            mine = (await client.get("/api/conversations", headers=headers(101))).json()["conversations"][0]
            assert mine["peer_read_id"] == ids[1]
            history = (await client.get("/api/messages?with=102", headers=headers(101))).json()
            assert history["peer_read_id"] == ids[1]

            # The sender is told that the messages were read; the marker never moves back.
            events = (await client.get(f"/api/events?after_id={cursor}", headers=headers(101))).json()["events"]
            assert [(e["kind"], e["message_id"]) for e in events] == [("read", ids[1])]
            back = await client.put("/api/read", headers=headers(102), json={"scope": "dm", "peer_id": 101, "last_read_id": 1})
            assert back.json()["last_read_id"] == ids[1]

            assert (await client.put("/api/read", headers=headers(102), json={"scope": "x", "peer_id": 1, "last_read_id": 1})).status_code == 400
            assert (await client.put("/api/read", headers=headers(102), json={"scope": "dm", "peer_id": 424242, "last_read_id": 1})).status_code == 404

    run(scenario())


def test_group_and_channel_unread_counters(env) -> None:
    path, app = env

    async def scenario() -> None:
        async with await client_for(app) as client:
            gid = (await client.post("/api/groups", headers=headers(101), json={"title": "G"})).json()["id"]
            await client.post(f"/api/groups/{gid}/members", headers=headers(101), json={"telegram_id": 102})
            g1 = (await client.post(f"/api/groups/{gid}/messages", headers=headers(101), json={"body": "1"})).json()["id"]
            await client.post(f"/api/groups/{gid}/messages", headers=headers(101), json={"body": "2"})
            await client.post(f"/api/groups/{gid}/messages", headers=headers(102), json={"body": "own"})
            group = next(g for g in (await client.get("/api/groups", headers=headers(102))).json()["groups"] if g["id"] == gid)
            assert group["unread_count"] == 2  # own messages do not count
            await client.put("/api/read", headers=headers(102), json={"scope": "group", "peer_id": gid, "last_read_id": g1})
            group = next(g for g in (await client.get("/api/groups", headers=headers(102))).json()["groups"] if g["id"] == gid)
            assert group["unread_count"] == 1 and group["last_read_id"] == g1
            # A non-member cannot set a marker for the group.
            assert (await client.put("/api/read", headers=headers(ADMIN), json={"scope": "group", "peer_id": gid, "last_read_id": 1})).status_code == 403

            cid = (await client.post("/api/channels", headers=headers(101), json={"title": "C", "username": "c_chan"})).json()["id"]
            await client.post(f"/api/channels/{cid}/messages", headers=headers(101), json={"body": "p1"})
            p2 = (await client.post(f"/api/channels/{cid}/messages", headers=headers(101), json={"body": "p2"})).json()["id"]
            channel = next(c for c in (await client.get("/api/channels", headers=headers(102))).json()["channels"] if c["id"] == cid)
            assert channel["unread_count"] == 2
            await client.put("/api/read", headers=headers(102), json={"scope": "channel", "peer_id": cid, "last_read_id": p2})
            channel = next(c for c in (await client.get("/api/channels", headers=headers(102))).json()["channels"] if c["id"] == cid)
            assert channel["unread_count"] == 0

    run(scenario())


def test_existing_messages_count_as_read_after_the_upgrade(tmp_path, monkeypatch) -> None:
    """A database from before read marks must not show every old message as unread."""
    import sqlite3

    import db_split
    from cryptography.fernet import Fernet

    import bot as bot_module
    from messenger_api import init_messenger_storage

    path = tmp_path / "w.sqlite3"
    monkeypatch.setattr(bot_module, "DATABASE_PATH", path)
    store = bot_module.Store(path)
    store.configure_otp_encryption(Fernet.generate_key().decode("ascii"))
    run(store.init())
    run(bot_module.init_admin_storage())
    run(init_messenger_storage(path))
    conn = db_split.sqlite_connect(path)
    conn.execute("INSERT INTO messages(sender_telegram_id,recipient_telegram_id,body,created_at) VALUES(1,2,'old',1)")
    conn.execute("INSERT INTO messages(sender_telegram_id,recipient_telegram_id,body,created_at) VALUES(1,2,'older',2)")
    conn.execute("PRAGMA messenger.user_version=0")  # as if the database predates read marks
    conn.execute("DELETE FROM read_markers")
    conn.commit()
    conn.close()

    run(init_messenger_storage(path))
    conn = db_split.sqlite_connect(path)
    marks = conn.execute("SELECT telegram_id,scope,peer_id,last_read_id FROM read_markers").fetchall()
    conn.close()
    assert marks == [(2, "dm", 1, 2)]

    # Running it again must not hide messages that arrive later.
    conn = db_split.sqlite_connect(path)
    conn.execute("INSERT INTO messages(sender_telegram_id,recipient_telegram_id,body,created_at) VALUES(1,2,'new',3)")
    conn.execute("DELETE FROM read_markers")
    conn.commit()
    conn.close()
    run(init_messenger_storage(path))
    conn = db_split.sqlite_connect(path)
    assert conn.execute("SELECT COUNT(*) FROM read_markers").fetchone()[0] == 0
    conn.close()


def test_group_message_can_be_deleted_knowing_only_its_id(env) -> None:
    path, app = env

    async def scenario() -> None:
        async with await client_for(app) as client:
            gid = (await client.post("/api/groups", headers=headers(101), json={"title": "ById"})).json()["id"]
            await client.post(f"/api/groups/{gid}/members", headers=headers(101), json={"telegram_id": 102})
            mid = (await client.post(f"/api/groups/{gid}/messages", headers=headers(102), json={"body": "bye"})).json()["id"]
            assert (await client.delete(f"/api/group-messages/{mid}", headers=headers(ADMIN))).status_code == 403
            assert (await client.delete(f"/api/group-messages/{mid}", headers=headers(102))).status_code == 200
            assert (await client.delete(f"/api/group-messages/{mid}", headers=headers(102))).status_code == 404

    run(scenario())


def test_direct_message_search_is_scoped_to_conversation(env) -> None:
    _path, app = env

    async def scenario() -> None:
        async with await client_for(app) as client:
            await client.post("/api/messages", headers=headers(101), json={
                "recipient_id": 102, "body": "Searchable hello world",
            })
            await client.post("/api/messages", headers=headers(102), json={
                "recipient_id": 101, "body": "Another HELLO from peer",
            })
            await client.post("/api/messages", headers=headers(101), json={
                "recipient_id": ADMIN, "body": "HELLO in another conversation",
            })

            found = await client.get(
                "/api/messages/search?with=102&q=hello",
                headers=headers(101),
            )
            assert found.status_code == 200
            payload = found.json()
            assert payload["count"] == 2
            assert [item["body"] for item in payload["messages"]] == [
                "Searchable hello world",
                "Another HELLO from peer",
            ]
            assert payload["has_more"] is False

            none = await client.get(
                "/api/messages/search?with=102&q=another%20conversation",
                headers=headers(101),
            )
            assert none.status_code == 200 and none.json()["count"] == 0

            invalid = await client.get(
                "/api/messages/search?with=102&q=%20%20",
                headers=headers(101),
            )
            assert invalid.status_code == 400

            missing_auth = await client.get("/api/messages/search?with=102&q=hello")
            assert missing_auth.status_code == 401

    run(scenario())



def test_group_and_channel_message_search_enforces_access(env) -> None:
    _path, app = env

    async def scenario() -> None:
        async with await client_for(app) as client:
            group = (await client.post(
                "/api/groups", headers=headers(101), json={"title": "Search Group"},
            )).json()
            group_id = group["id"]
            await client.post(
                f"/api/groups/{group_id}/members",
                headers=headers(101),
                json={"telegram_id": 102},
            )
            await client.post(
                f"/api/groups/{group_id}/messages",
                headers=headers(102),
                json={"body": "Group search marker"},
            )
            group_found = await client.get(
                f"/api/groups/{group_id}/messages/search?q=search",
                headers=headers(101),
            )
            assert group_found.status_code == 200
            assert group_found.json()["count"] == 1
            denied_group = await client.get(
                f"/api/groups/{group_id}/messages/search?q=search",
                headers=headers(ADMIN),
            )
            assert denied_group.status_code == 403

            channel = (await client.post(
                "/api/channels",
                headers=headers(101),
                json={"title": "Search Channel", "username": "search_channel"},
            )).json()
            channel_id = channel["id"]
            await client.post(
                f"/api/channels/{channel_id}/messages",
                headers=headers(101),
                json={"body": "Channel search marker"},
            )
            channel_found = await client.get(
                f"/api/channels/{channel_id}/messages/search?q=marker",
                headers=headers(102),
            )
            assert channel_found.status_code == 200
            assert channel_found.json()["count"] == 1

    run(scenario())



def test_contacts_can_be_added_listed_and_removed(env) -> None:
    _path, app = env

    async def scenario() -> None:
        async with await client_for(app) as client:
            auth = headers(101)
            initial = await client.get("/api/contacts", headers=auth)
            assert initial.status_code == 200
            assert initial.json()["count"] == 0

            added = await client.post(
                "/api/contacts", headers=auth, json={"user_id": 102},
            )
            assert added.status_code == 201
            assert added.json()["status"] == "added"
            assert added.json()["contact"]["id"] == 102

            duplicate = await client.post(
                "/api/contacts", headers=auth, json={"user_id": 102},
            )
            assert duplicate.status_code == 201
            assert duplicate.json()["status"] == "already_exists"

            contacts = await client.get("/api/contacts", headers=auth)
            assert contacts.json()["count"] == 1
            assert contacts.json()["contacts"][0]["id"] == 102

            assert (await client.post(
                "/api/contacts", headers=auth, json={"user_id": 101},
            )).status_code == 400
            assert (await client.post(
                "/api/contacts", headers=auth, json={"user_id": "102"},
            )).status_code == 400
            assert (await client.post(
                "/api/contacts", headers=auth, json={"user_id": 999999},
            )).status_code == 404

            removed = await client.delete("/api/contacts/102", headers=auth)
            assert removed.status_code == 200
            assert removed.json()["status"] == "removed"
            assert (await client.get("/api/contacts", headers=auth)).json()["count"] == 0
            assert (await client.delete("/api/contacts/102", headers=auth)).status_code == 404
            assert (await client.get("/api/contacts")).status_code == 401

    run(scenario())



def test_direct_messages_can_be_forwarded_with_original_attribution(env) -> None:
    _path, app = env

    async def scenario() -> None:
        async with await client_for(app) as client:
            original = await client.post(
                "/api/messages",
                headers=headers(101),
                json={"recipient_id": 102, "body": "Forward this message"},
            )
            assert original.status_code == 201
            original_id = original.json()["id"]

            key = "wg-forward-message-00001"
            forwarded = await client.post(
                f"/api/messages/{original_id}/forward",
                headers={**headers(102), "Idempotency-Key": key},
                json={"recipient_id": ADMIN},
            )
            assert forwarded.status_code == 201
            result = forwarded.json()
            assert result["status"] == "forwarded"
            assert result["body"] == "Forward this message"
            assert result["forwarded_from_telegram_id"] == 101
            assert result["forwarded_from_message_id"] == original_id

            retry = await client.post(
                f"/api/messages/{original_id}/forward",
                headers={**headers(102), "Idempotency-Key": key},
                json={"recipient_id": ADMIN},
            )
            assert retry.status_code == 201
            assert retry.json()["id"] == result["id"]

            history = await client.get(
                f"/api/messages?with=102",
                headers=headers(ADMIN),
            )
            forwarded_rows = [
                item for item in history.json()["messages"]
                if item["id"] == result["id"]
            ]
            assert len(forwarded_rows) == 1
            assert forwarded_rows[0]["forwarded_from_telegram_id"] == 101
            assert forwarded_rows[0]["forwarded_from_message_id"] == original_id
            assert forwarded_rows[0]["forwarded_from_display_name"]

            denied = await client.post(
                f"/api/messages/{original_id}/forward",
                headers=headers(ADMIN),
                json={"recipient_id": 101},
            )
            assert denied.status_code == 404

            missing_target = await client.post(
                f"/api/messages/{original_id}/forward",
                headers=headers(102),
                json={"recipient_id": 999999},
            )
            assert missing_target.status_code == 404

    run(scenario())



def test_user_blocklist_prevents_direct_messages_both_directions(env) -> None:
    _path, app = env

    async def scenario() -> None:
        async with await client_for(app) as client:
            auth_a = headers(101)
            auth_b = headers(102)

            invalid_self = await client.post("/api/blocks", headers=auth_a, json={"user_id": 101})
            assert invalid_self.status_code == 400
            invalid_id = await client.post("/api/blocks", headers=auth_a, json={"user_id": "102"})
            assert invalid_id.status_code == 400

            blocked = await client.post("/api/blocks", headers=auth_a, json={"user_id": 102})
            assert blocked.status_code == 201
            assert blocked.json()["status"] == "blocked"
            assert blocked.json()["user"]["id"] == 102

            duplicate = await client.post("/api/blocks", headers=auth_a, json={"user_id": 102})
            assert duplicate.status_code == 201
            assert duplicate.json()["status"] == "already_blocked"

            listed = await client.get("/api/blocks", headers=auth_a)
            assert listed.status_code == 200
            assert listed.json()["count"] == 1
            assert listed.json()["blocked_users"][0]["id"] == 102

            outbound = await client.post(
                "/api/messages", headers=auth_a,
                json={"recipient_id": 102, "body": "This should be denied"},
            )
            assert outbound.status_code == 403

            inbound = await client.post(
                "/api/messages", headers=auth_b,
                json={"recipient_id": 101, "body": "This should also be denied"},
            )
            assert inbound.status_code == 403

            forwarded_source = await client.post(
                "/api/messages", headers=auth_b,
                json={"recipient_id": ADMIN, "body": "Forward source"},
            )
            assert forwarded_source.status_code == 201
            forwarding = await client.post(
                f"/api/messages/{forwarded_source.json()['id']}/forward",
                headers=auth_b,
                json={"recipient_id": 101},
            )
            assert forwarding.status_code == 403

            unblocked = await client.delete("/api/blocks/102", headers=auth_a)
            assert unblocked.status_code == 200
            assert unblocked.json()["status"] == "unblocked"
            assert (await client.get("/api/blocks", headers=auth_a)).json()["count"] == 0

            allowed_after_unblock = await client.post(
                "/api/messages", headers=auth_b,
                json={"recipient_id": 101, "body": "Now it is allowed"},
            )
            assert allowed_after_unblock.status_code == 201
            assert (await client.delete("/api/blocks/102", headers=auth_a)).status_code == 404
            assert (await client.get("/api/blocks")).status_code == 401

    run(scenario())
