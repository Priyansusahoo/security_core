CREATE TABLE IF NOT EXISTS otp_sessions (
    id BIGSERIAL PRIMARY KEY,
    target VARCHAR(255) NOT NULL,
    hashed_otp VARCHAR(255) NOT NULL,
    purpose VARCHAR(50) NOT NULL,
    channel VARCHAR(30) NOT NULL,
    attempts_remaining INT NOT NULL DEFAULT 3,
    consumed BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);

-- Index for high-performance lookup of active unconsumed OTPs
CREATE INDEX idx_otp_target_purpose_active ON otp_sessions (target, purpose, consumed, expires_at);