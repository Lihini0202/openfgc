-- Nominee Service Database Schema (MySQL)

-- One owner-to-nominee grant. The unique key is the PAIR, not the owner:
-- an owner may nominate any number of people, but each of them only once.
CREATE TABLE IF NOT EXISTS NOMINATION (
  NOMINATION_ID         CHAR(36) NOT NULL,
  OWNER_ID              VARCHAR(255) NOT NULL,
  NOMINEE_ID            VARCHAR(255) NOT NULL,
  NOMINEE_EMAIL         VARCHAR(255) NOT NULL,
  NOMINEE_NIC           VARCHAR(64) DEFAULT NULL,
  CURRENT_STATUS        VARCHAR(32) NOT NULL,
  NOMINATED_TIME        BIGINT NOT NULL,
  ACCEPTED_TIME         BIGINT DEFAULT NULL,
  ACTIVATED_BY          VARCHAR(255) DEFAULT NULL,
  ACTIVATED_TIME        BIGINT DEFAULT NULL,
  ACTIVATION_TICKET     VARCHAR(255) DEFAULT NULL,
  DEACTIVATED_BY        VARCHAR(255) DEFAULT NULL,
  DEACTIVATED_TIME      BIGINT DEFAULT NULL,
  DEACTIVATION_REASON   TEXT DEFAULT NULL,
  ORG_ID                VARCHAR(255) NOT NULL DEFAULT 'DEFAULT_ORG',
  PRIMARY KEY (NOMINATION_ID, ORG_ID),
  UNIQUE KEY uk_owner_nominee (OWNER_ID, NOMINEE_ID, ORG_ID),
  INDEX idx_owner_id (OWNER_ID),
  INDEX idx_nominee_id (NOMINEE_ID),
  INDEX idx_current_status (CURRENT_STATUS),
  INDEX idx_nominee_status (NOMINEE_ID, CURRENT_STATUS, ORG_ID),
  INDEX idx_org_id (ORG_ID)
) ENGINE=INNODB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- What the owner granted this nominee. One row per permission.
CREATE TABLE IF NOT EXISTS NOMINATION_PERMISSION (
  NOMINATION_ID     CHAR(36) NOT NULL,
  PERMISSION        VARCHAR(32) NOT NULL,
  ORG_ID            VARCHAR(255) NOT NULL DEFAULT 'DEFAULT_ORG',
  PRIMARY KEY (NOMINATION_ID, PERMISSION, ORG_ID),
  INDEX idx_permission (PERMISSION),
  CONSTRAINT FK_NOMINATION_PERMISSION
    FOREIGN KEY (NOMINATION_ID, ORG_ID)
    REFERENCES NOMINATION (NOMINATION_ID, ORG_ID)
    ON DELETE CASCADE
) ENGINE=INNODB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Lifecycle of a nomination: created, accepted, activated, deactivated, removed.
-- Low volume and kept permanently. Hash-chained: HASH covers this row's own
-- fields plus PREVIOUS_HASH, so altering or removing a row invalidates every
-- row after it. SEQUENCE is global across this table and NOMINEE_SESSION,
-- which together form one chain.
CREATE TABLE IF NOT EXISTS NOMINATION_EVENT (
  EVENT_ID          CHAR(36) NOT NULL,
  NOMINATION_ID     CHAR(36) DEFAULT NULL,
  OWNER_ID          VARCHAR(255) NOT NULL,
  NOMINEE_ID        VARCHAR(255) NOT NULL,
  EVENT_TYPE        VARCHAR(32) NOT NULL,
  ACTOR_ID          VARCHAR(255) NOT NULL,
  DETAIL            TEXT DEFAULT NULL,
  OCCURRED_TIME     BIGINT NOT NULL,
  CHAIN_SEQUENCE    BIGINT NOT NULL,
  PREVIOUS_HASH     CHAR(64) NOT NULL,
  HASH              CHAR(64) NOT NULL,
  ORG_ID            VARCHAR(255) NOT NULL DEFAULT 'DEFAULT_ORG',
  PRIMARY KEY (EVENT_ID, ORG_ID),
  UNIQUE KEY uk_nomination_event_sequence (CHAIN_SEQUENCE, ORG_ID),
  INDEX idx_nomination_id (NOMINATION_ID),
  INDEX idx_event_pair (OWNER_ID, NOMINEE_ID, OCCURRED_TIME),
  INDEX idx_event_type (EVENT_TYPE),
  INDEX idx_occurred_time (OCCURRED_TIME)
) ENGINE=INNODB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- One acting session, or one refusal to start one. GRANTED_SCOPES records what
-- the impersonation token actually carried, which is the ceiling every action in
-- the session was bounded by.
CREATE TABLE IF NOT EXISTS NOMINEE_SESSION (
  SESSION_ID        CHAR(36) NOT NULL,
  NOMINATION_ID     CHAR(36) DEFAULT NULL,
  OWNER_ID          VARCHAR(255) NOT NULL,
  NOMINEE_ID        VARCHAR(255) NOT NULL,
  GRANTED_SCOPES    TEXT DEFAULT NULL,
  OUTCOME           VARCHAR(16) NOT NULL,
  DENIED_REASON     VARCHAR(255) DEFAULT NULL,
  STARTED_TIME      BIGINT NOT NULL,
  ENDED_TIME        BIGINT DEFAULT NULL,
  END_REASON        VARCHAR(32) DEFAULT NULL,
  CHAIN_SEQUENCE    BIGINT NOT NULL,
  PREVIOUS_HASH     CHAR(64) NOT NULL,
  HASH              CHAR(64) NOT NULL,
  ORG_ID            VARCHAR(255) NOT NULL DEFAULT 'DEFAULT_ORG',
  PRIMARY KEY (SESSION_ID, ORG_ID),
  UNIQUE KEY uk_nominee_session_sequence (CHAIN_SEQUENCE, ORG_ID),
  INDEX idx_session_pair (OWNER_ID, NOMINEE_ID, STARTED_TIME),
  INDEX idx_session_nomination (NOMINATION_ID),
  INDEX idx_session_outcome (OUTCOME),
  INDEX idx_started_time (STARTED_TIME)
) ENGINE=INNODB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Every action attempted within a session, allowed or refused. This is the only
-- record of a nominee READING an owner's data, and the only record of a refusal:
-- neither ever reaches the Consent Server.
--
-- CHAIN_SEQUENCE restarts at zero for each session, so appends contend only
-- within one nominee's session rather than across the whole service.
CREATE TABLE IF NOT EXISTS NOMINEE_SESSION_EVENT (
  EVENT_ID          CHAR(36) NOT NULL,
  SESSION_ID        CHAR(36) NOT NULL,
  ACTION            VARCHAR(32) NOT NULL,
  RESOURCE_TYPE     VARCHAR(32) DEFAULT NULL,
  RESOURCE_ID       VARCHAR(255) DEFAULT NULL,
  DECISION          VARCHAR(16) NOT NULL,
  DENIED_REASON     VARCHAR(255) DEFAULT NULL,
  OCCURRED_TIME     BIGINT NOT NULL,
  CHAIN_SEQUENCE    BIGINT NOT NULL,
  PREVIOUS_HASH     CHAR(64) NOT NULL,
  HASH              CHAR(64) NOT NULL,
  ORG_ID            VARCHAR(255) NOT NULL DEFAULT 'DEFAULT_ORG',
  PRIMARY KEY (EVENT_ID, ORG_ID),
  UNIQUE KEY uk_session_event_sequence (SESSION_ID, CHAIN_SEQUENCE, ORG_ID),
  INDEX idx_session_time (SESSION_ID, OCCURRED_TIME),
  INDEX idx_resource (RESOURCE_TYPE, RESOURCE_ID, OCCURRED_TIME),
  INDEX idx_decision (DECISION),
  INDEX idx_event_occurred_time (OCCURRED_TIME),
  CONSTRAINT FK_NOMINEE_SESSION_EVENT
    FOREIGN KEY (SESSION_ID, ORG_ID)
    REFERENCES NOMINEE_SESSION (SESSION_ID, ORG_ID)
    ON DELETE CASCADE
) ENGINE=INNODB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
