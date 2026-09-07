-- Zero-Trust Signaling Handshake Policies
-- This ensures that only the exact target device can read the WebRTC SDP offer/answer.
-- Peer discovery is completely opaque to third-party observers.

CREATE TABLE signaling_channel (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sender_id UUID NOT NULL REFERENCES auth.users(id),
    target_id UUID NOT NULL REFERENCES auth.users(id),
    type TEXT NOT NULL CHECK (type IN ('offer', 'answer', 'ice')),
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Enable Row Level Security
ALTER TABLE signaling_channel ENABLE ROW LEVEL SECURITY;

-- Strict Handshake Policy: A device can ONLY read messages specifically targeted to its verified UID.
CREATE POLICY "Strict Handshake Select" 
ON signaling_channel 
FOR SELECT 
USING (auth.uid() = target_id);

-- A device can ONLY insert messages if it correctly identifies as the sender.
CREATE POLICY "Strict Handshake Insert" 
ON signaling_channel 
FOR INSERT 
WITH CHECK (auth.uid() = sender_id);
