# Detection Logic – Authentication Monitoring

## Purpose
The purpose of this detection logic is to identify repeated failed authentication attempts that may indicate brute-force or credential-stuffing activity.

## Detection Criteria
- Multiple failed login attempts
- Occurring within a short time window
- Originating from the same user account or source

## Logic Overview
1. Parse authentication log entries
2. Identify failure events
3. Track repeated failures per source
4. Flag activity exceeding a defined threshold
5. Record event for investigation

## Analyst Value
This detection mirrors common SOC alert logic used to identify early-stage account compromise attempts.
