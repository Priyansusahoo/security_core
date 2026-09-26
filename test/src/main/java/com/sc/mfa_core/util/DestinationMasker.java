package com.sc.mfa_core.util;

import com.sc.otp_core.domain.OtpChannel;

/**
 * Strategy interface responsible for obfuscating sensitive recipient destinations
 * (e.g. emails, phone numbers) for secure display on client user interfaces.
 */
public interface DestinationMasker {
    /**
     * Obfuscates the given destination based on the specified delivery channel.
     *
     * @param destination The raw recipient identifier (e.g., email address or phone number)
     * @param channel     The delivery channel used for dispatching the challenge
     * @return The masked destination string safe for public display (e.g. "j***e@example.com")
     */
    String mask(String destination, OtpChannel channel);
}
