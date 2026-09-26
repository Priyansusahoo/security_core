CREATE TABLE IF NOT EXISTS mfa_challenges (
    challenge_token VARCHAR(64) PRIMARY KEY,
    target VARCHAR(255) NOT NULL,
    channel VARCHAR(30) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);

-- Index for target lookup and scheduled housecleaning
CREATE INDEX idx_mfa_challenges_target ON mfa_challenges (target);
CREATE INDEX idx_mfa_challenges_expires_at ON mfa_challenges (expires_at);