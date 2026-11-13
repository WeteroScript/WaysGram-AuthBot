from __future__ import annotations

from io import BytesIO

from PIL import Image

from test_messenger_api import add_account, add_session, api_env, client_for, run


def test_direct_message_media_album_is_atomic_grouped_and_private(api_env) -> None:
    path, _auth_store, _fake_bot, app = api_env
    add_account(api_env, 89501, "album_sender")
    add_account(api_env, 89502, "album_recipient")
    add_account(api_env, 89503, "album_intruder")
    add_session(path, 89501, "album-sender-session")
    add_session(path, 89502, "album-recipient-session")
    add_session(path, 89503, "album-intruder-session")

    image_bytes = BytesIO()
    Image.new("RGB", (3, 2), (80, 120, 180)).save(image_bytes, format="PNG")
    image_payload = image_bytes.getvalue()

    async def scenario() -> None:
        async with await client_for(app) as client:
            sender = {"Authorization": "Bearer album-sender-session"}
            recipient = {"Authorization": "Bearer album-recipient-session"}
            intruder = {"Authorization": "Bearer album-intruder-session"}

            media_ids = []
            for index in range(2):
                uploaded = await client.post(
                    "/api/media/images",
                    headers={**sender, "Content-Type": "image/png"},
                    content=image_payload,
                )
                assert uploaded.status_code == 201
                media_ids.append(uploaded.json()["id"])

            payload = {
                "recipient_id": 89502,
                "body": "Фото с поездки",
                "media_ids": media_ids,
            }
            sent = await client.post(
                "/api/messages/album",
                headers={**sender, "Idempotency-Key": "album-idempotency-key-0001"},
                json=payload,
            )
            assert sent.status_code == 201
            album = sent.json()
            assert album["status"] == "sent"
            assert album["count"] == 2
            assert len(album["messages"]) == 2
            album_id = album["album_id"]
            assert len(album_id) == 32
            assert [item["media_album_index"] for item in album["messages"]] == [0, 1]
            assert all(item["media_album_id"] == album_id for item in album["messages"])
            assert all(item["media_album_count"] == 2 for item in album["messages"])
            assert album["messages"][0]["body"] == "Фото с поездки"
            assert album["messages"][1]["body"] == ""

            repeated = await client.post(
                "/api/messages/album",
                headers={**sender, "Idempotency-Key": "album-idempotency-key-0001"},
                json=payload,
            )
            assert repeated.status_code == 201
            assert repeated.json()["album_id"] == album_id
            assert [item["id"] for item in repeated.json()["messages"]] == [
                item["id"] for item in album["messages"]
            ]

            history = await client.get("/api/messages?with=89501", headers=recipient)
            assert history.status_code == 200
            received = [
                item for item in history.json()["messages"]
                if item.get("media_album_id") == album_id
            ]
            assert len(received) == 2
            assert [item["media_album_index"] for item in received] == [0, 1]

            for media_id in media_ids:
                allowed = await client.get(f"/api/media/{media_id}", headers=recipient)
                denied = await client.get(f"/api/media/{media_id}", headers=intruder)
                assert allowed.status_code == 200
                assert denied.status_code == 404

    run(scenario())
