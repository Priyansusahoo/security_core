package com.sc.security_core.config;

import ch.qos.logback.classic.pattern.ClassicConverter;
import ch.qos.logback.classic.spi.ILoggingEvent;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class LogMaskingConverter extends ClassicConverter {

	private static final Pattern SENSITIVE_REGEX = Pattern.compile("(?i)(password|bearer|token|secret)\\s*[:= ]\\s*([^\\s,}\\]]+)");

	@Override
	public String convert(ILoggingEvent event) {
		String message = event.getFormattedMessage();
		Matcher matcher = SENSITIVE_REGEX.matcher(message);

		if (matcher.find()) {
			return matcher.replaceAll("$1=***");
		}
		return message;
	}
}
