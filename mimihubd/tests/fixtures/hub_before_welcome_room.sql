-- A hub.db as the store wrote it before a queued Welcome carried the room it joins: every table the store makes,
-- with two Welcomes and a message queued for bob. Made by opening that revision's store and queueing through it,
-- then sqlite3 .dump; user_version is set here because .dump leaves it out.
PRAGMA user_version = 2;
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE keypackages (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT NOT NULL,
    kp_bytes    BLOB NOT NULL,
    not_after   INTEGER NOT NULL,
    last_resort INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE notify_seen (
    hash    BLOB PRIMARY KEY,
    seen_at INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE kpref_client (
    kpref     BLOB PRIMARY KEY,
    username  TEXT NOT NULL,
    not_after INTEGER NOT NULL
);
CREATE TABLE kpref_provider (
    kpref     BLOB PRIMARY KEY,
    provider  TEXT NOT NULL,
    not_after INTEGER NOT NULL
);
CREATE TABLE enrolled (
    username TEXT PRIMARY KEY
);
CREATE TABLE consent (
    requester TEXT NOT NULL,
    target    TEXT NOT NULL,
    room_key  TEXT NOT NULL,          -- '' = global scope
    state     TEXT NOT NULL,          -- 'requested' | 'granted' | 'revoked'
    ts        INTEGER NOT NULL,
    PRIMARY KEY (requester, target, room_key)
);
CREATE TABLE room_metadata (
    room_uri TEXT PRIMARY KEY,
    metadata BLOB NOT NULL,
    ts       INTEGER NOT NULL
);
CREATE TABLE room_policy (
    room_uri    TEXT PRIMARY KEY,
    policy_json TEXT NOT NULL,
    ts          INTEGER NOT NULL
);
CREATE TABLE member_role (
    room_uri   TEXT NOT NULL,
    member_uri TEXT NOT NULL,
    role_index INTEGER NOT NULL,
    PRIMARY KEY (room_uri, member_uri)
);
CREATE TABLE welcomes (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient TEXT NOT NULL,
    bytes     BLOB NOT NULL,
    ts        INTEGER NOT NULL
);
INSERT INTO welcomes VALUES(1,'bob',X'6f6c642d77656c636f6d652d31',1764000000);
INSERT INTO welcomes VALUES(2,'bob',X'6f6c642d77656c636f6d652d32',1764000001);
CREATE TABLE messages (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient TEXT NOT NULL,
    bytes     BLOB NOT NULL,
    ts        INTEGER NOT NULL
);
INSERT INTO messages VALUES(1,'bob',X'6f6c642d6d657373616765',1764000002);
CREATE TABLE room_participants (
    room_uri   TEXT NOT NULL,
    member_uri TEXT NOT NULL,
    authority  TEXT NOT NULL,
    ts         INTEGER NOT NULL,
    -- Position in the room's participants vector (protocol §7.5): the order participants joined in. A
    -- ParticipantListUpdate names participants by this position, so it is stored, never derived from the URI.
    seq        INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (room_uri, member_uri)
);
CREATE TABLE abuse_reports (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    room_uri            TEXT NOT NULL,
    reporting_user      TEXT NOT NULL,
    alleged_abuser_uri  TEXT NOT NULL,
    reason_code         INTEGER NOT NULL,
    note                TEXT NOT NULL,
    ts                  INTEGER NOT NULL
);
CREATE TABLE pending_proposals (
    room_uri  TEXT NOT NULL,
    epoch     INTEGER NOT NULL,
    reference BLOB NOT NULL,
    message   BLOB NOT NULL,
    ts        INTEGER NOT NULL,
    PRIMARY KEY (room_uri, reference)
);
CREATE TABLE room_epoch (
    room_uri TEXT PRIMARY KEY,
    epoch    INTEGER NOT NULL
);
CREATE TABLE room_tree (
    room_uri     TEXT PRIMARY KEY,
    group_id     BLOB NOT NULL,
    seeded_by    TEXT NOT NULL,
    seeded_epoch INTEGER NOT NULL
);
CREATE TABLE mls_public_group (
    group_id BLOB NOT NULL,
    label    TEXT NOT NULL,
    value    BLOB NOT NULL,
    PRIMARY KEY (group_id, label)
);
CREATE TABLE mls_public_proposal (
    group_id     BLOB NOT NULL,
    proposal_ref BLOB NOT NULL,
    proposal     BLOB NOT NULL,
    seq          INTEGER NOT NULL,
    PRIMARY KEY (group_id, proposal_ref)
);
CREATE TABLE outbox (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    room_uri        TEXT NOT NULL,
    domain          TEXT NOT NULL,
    body            BLOB NOT NULL,
    enqueued_at_ms  INTEGER NOT NULL,
    attempts        INTEGER NOT NULL DEFAULT 0,
    next_attempt_ms INTEGER NOT NULL,
    last_outcome    TEXT
);
CREATE TABLE followed_member (
    room_uri   TEXT NOT NULL,
    member_uri TEXT NOT NULL,
    since      INTEGER NOT NULL,
    PRIMARY KEY (room_uri, member_uri)
);
CREATE TABLE followed_seen (
    room_uri TEXT NOT NULL,
    digest   BLOB NOT NULL,
    seen_at  INTEGER NOT NULL,
    PRIMARY KEY (room_uri, digest)
);
CREATE TABLE room_operational_policy (
    room_uri TEXT PRIMARY KEY,
    data     BLOB NOT NULL
);
CREATE TABLE room_group_info (
    room_uri   TEXT PRIMARY KEY,
    epoch      INTEGER NOT NULL,
    group_info BLOB NOT NULL
);
DELETE FROM sqlite_sequence;
INSERT INTO sqlite_sequence VALUES('welcomes',2);
INSERT INTO sqlite_sequence VALUES('messages',1);
CREATE INDEX idx_kp_user ON keypackages(username, not_after);
CREATE INDEX idx_consent_pair ON consent(requester, target);
CREATE INDEX idx_welcome_rcpt ON welcomes(recipient, id);
CREATE INDEX idx_msg_rcpt ON messages(recipient, id);
CREATE INDEX idx_room ON room_participants(room_uri);
CREATE INDEX idx_abuse_room ON abuse_reports(room_uri);
CREATE INDEX outbox_queue ON outbox (room_uri, domain, id);
COMMIT;
