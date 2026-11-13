#!/usr/bin/env bash
# Seeds a mimi-hubd with the state a visiting implementation needs to test against it, through the hub's own
# routes, and checks the result on the wire lane.
#
#   HUB=https://mimi.example.com:8443 CERT=client-cert.pem KEY=client-key.pem \
#   PEER_USER=mimi://other.example/u/alice examples/seed_table.sh seed
#
#   ... examples/seed_table.sh check
#
# `seed` leaves, on the hub at $HUB:
#   - a user with $COUNT KeyPackages, published under its name and again under its whole URI, since a peer may put
#     either in the path of keyMaterial (a second run adds $COUNT more under each);
#   - a second user with none, for the exhausted answer;
#   - a consent grant from each of the two to $PEER_USER;
#   - a room whose first participant is $PEER_USER.
# and then runs `check`. Run it against a room name the hub has not seen: the hub appends participants, and no route
# lists a room, so $PEER_USER is first only in a room that had nobody.
#
# `check` changes nothing. It asks whether $PEER_USER may send in the room, asks keyMaterial for the user with no
# KeyPackages as $PEER_USER (exhausted means the consent grant is there; denied means it is not), and asks
# identifierQuery for $HANDLE. The last two go over the wire lane, as a peer provider asks them.
#
# One thing no route does: enroll a handle for identifierQuery. That is `mimi-hubd enroll <handle>`, run on the hub's
# host. `check` says whether $HANDLE is enrolled.
#
# Environment:
#   HUB           the hub's mTLS listener, scheme and port included (required)
#   CERT, KEY     a client certificate the hub trusts, and its key (required)
#   PEER_USER     the visiting user's URI (required)
#   CACERT        the CA of the hub's server certificate, when the system store does not hold it
#   WITH_KEYS     name of the user that gets KeyPackages (default erin)
#   WITHOUT_KEYS  name of the user that gets none (default grace)
#   ROOM          name of the room (default table)
#   HANDLE        the handle `check` asks identifierQuery for (default: $WITH_KEYS)
#   COUNT         KeyPackages published under each of the two keys (default 20; a hub keeps the newest 64 a key)
#   WORK          directory for the generated files (default: a new temporary one, left in place)
#
# Needs bash, curl and cargo. The KeyPackages come from `examples/seed_fixtures.rs`; their private keys are never
# written anywhere, so nobody can open a Welcome made for the seeded users.
set -euo pipefail

mode=${1:-}
: "${HUB:?set HUB to the mTLS listener of the hub, e.g. https://mimi.example.com:8443}"
: "${CERT:?set CERT to a client certificate the hub trusts}"
: "${KEY:?set KEY to the key of that certificate}"
: "${PEER_USER:?set PEER_USER to the visiting user, e.g. mimi://other.example/u/alice}"
WITH_KEYS=${WITH_KEYS:-erin}
WITHOUT_KEYS=${WITHOUT_KEYS:-grace}
ROOM=${ROOM:-table}
HANDLE=${HANDLE:-$WITH_KEYS}
COUNT=${COUNT:-20}

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
WORK=${WORK:-$(mktemp -d)}
mkdir -p "$WORK"

fail() {
    echo "seed_table: $*" >&2
    exit 1
}

fixtures() {
    cargo run --quiet --manifest-path "$repo/Cargo.toml" --example seed_fixtures -- "$@"
}

# curl against the hub with the client certificate. Prints the status; the body goes to $WORK/answer.
hub() {
    local ca=()
    if [ -n "${CACERT:-}" ]; then
        ca=(--cacert "$CACERT")
    fi
    curl -sS "${ca[@]}" --cert "$CERT" --key "$KEY" -o "$WORK/answer" -w '%{http_code}' "$@"
}

urlencode() {
    local text=$1 out='' char i
    for ((i = 0; i < ${#text}; i++)); do
        char=${text:i:1}
        case $char in
            [A-Za-z0-9._~-]) out+=$char ;;
            *)
                printf -v char '%%%02X' "'$char"
                out+=$char
                ;;
        esac
    done
    printf '%s' "$out"
}

expect() {
    local want=$1 got=$2 what=$3
    if [ "$got" != "$want" ]; then
        fail "$what: the hub answered $got, expected $want"
    fi
}

# What the hub's keyMaterial answers $PEER_USER about `target_uri`, asked under the path key `key`: one word.
key_material_answer() {
    local key=$1 target_uri=$2 status
    fixtures keymaterial-request "$WORK/keymaterial-request.bin" "$PEER_USER" "$target_uri"
    status=$(hub -X POST -H 'Content-Type: application/mimi-protocol' \
        --data-binary "@$WORK/keymaterial-request.bin" "$HUB/mimi/pl/keyMaterial/$(urlencode "$key")")
    expect 200 "$status" "keyMaterial for $key"
    fixtures keymaterial-answer "$WORK/answer"
}

publish_key_packages() {
    local key=$1 dir=$2 file status
    for file in "$dir"/kp-*.bin; do
        status=$(hub -X POST -H 'Content-Type: application/octet-stream' --data-binary "@$file" \
            "$HUB/mimi/v1/keyMaterial/ingest?user=$(urlencode "$key")")
        expect 204 "$status" "publishing a KeyPackage for $key"
    done
}

grant_consent() {
    local target_uri=$1 status
    status=$(hub -X POST -H 'Content-Type: application/json' \
        --data "{\"operation\":2,\"requester_uri\":\"$PEER_USER\",\"target_uri\":\"$target_uri\"}" \
        "$HUB/mimi/v1/updateConsent")
    expect 201 "$status" "consent from $target_uri to $PEER_USER"
}

seed() {
    local status answer
    # One more under the name than under the URI: the claim at the end takes it.
    fixtures keypackages "$WORK/by-name" "$with_uri" "$((COUNT + 1))"
    fixtures keypackages "$WORK/by-uri" "$with_uri" "$COUNT"
    publish_key_packages "$WITH_KEYS" "$WORK/by-name"
    publish_key_packages "$with_uri" "$WORK/by-uri"
    echo "published: $COUNT KeyPackages for $with_uri under each of '$WITH_KEYS' and '$with_uri', and one to claim"

    grant_consent "$with_uri"
    grant_consent "$without_uri"
    echo "sent: consent grants from $with_uri and $without_uri to $PEER_USER"

    status=$(hub -X POST \
        "$HUB/mimi/v1/addParticipant?room=$(urlencode "$room_uri")&member=$(urlencode "$PEER_USER")")
    expect 201 "$status" "adding $PEER_USER to $room_uri"
    echo "added: $PEER_USER to $room_uri"

    # The whole path once, as a peer walks it: the grant lets $PEER_USER claim a KeyPackage on the wire lane.
    answer=$(key_material_answer "$WITH_KEYS" "$with_uri")
    if [ "$answer" != success ]; then
        fail "keyMaterial for $WITH_KEYS answered $PEER_USER '$answer', expected success"
    fi
    echo "claimed: one KeyPackage of $with_uri as $PEER_USER on the wire lane; this run leaves $COUNT of its own under each key"
}

check() {
    local status key answer failed=0
    status=$(hub -X POST \
        "$HUB/mimi/v1/authorizeSender?room=$(urlencode "$room_uri")&sender=$(urlencode "$PEER_USER")")
    if [ "$status" = 200 ]; then
        echo "room: $PEER_USER is a participant of $room_uri"
    else
        echo "room: $PEER_USER is NOT a participant of $room_uri (the hub answered $status)"
        failed=1
    fi

    for key in "$WITHOUT_KEYS" "$without_uri"; do
        answer=$(key_material_answer "$key" "$without_uri")
        if [ "$answer" = exhausted ]; then
            echo "consent: keyMaterial/$key answers $PEER_USER exhausted (granted, no KeyPackage)"
        else
            echo "consent: keyMaterial/$key answers $PEER_USER '$answer', expected exhausted"
            failed=1
        fi
    done

    fixtures identifier-request "$WORK/identifier-request.bin" "$HANDLE"
    status=$(hub -X POST -H 'Content-Type: application/mimi-protocol' \
        --data-binary "@$WORK/identifier-request.bin" "$HUB/mimi/pl/identifierQuery/$(urlencode "$provider")")
    if [ "$status" = 200 ]; then
        echo "handle: '$HANDLE' is enrolled"
    else
        echo "handle: '$HANDLE' is NOT enrolled (the hub answered $status). No route enrolls one: on the hub's host,"
        echo "        run: mimi-hubd enroll $HANDLE"
        failed=1
    fi
    return "$failed"
}

status=$(hub "$HUB/.well-known/mimi-protocol-directory")
expect 200 "$status" "the hub's directory"
provider=$(sed -n 's/.*"provider"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$WORK/answer")
[ -n "$provider" ] || fail "the hub's directory names no provider"
with_uri="mimi://$provider/u/$WITH_KEYS"
without_uri="mimi://$provider/u/$WITHOUT_KEYS"
room_uri="mimi://$provider/r/$ROOM"
echo "hub: $HUB is provider $provider; generated files are in $WORK"

case $mode in
    seed)
        seed
        check || echo "seed_table: seeded; the lines marked NOT above are still to do"
        ;;
    check)
        check || fail "not everything is in place"
        ;;
    *)
        fail "usage: seed_table.sh seed|check (see the header of this file)"
        ;;
esac
