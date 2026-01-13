# Testing Time Drift Detection

This guide explains how to test the time drift detection feature, including how to manually simulate time drift and verify the shutdown mechanism works.

## Prerequisites

1. Operator running with time drift detection enabled
2. Access to the operator's HTTP endpoints
3. Ability to view logs (journalctl, CloudWatch, etc.)

## Configuration for Testing

Add to your config to enable and configure for testing:

```json
{
  "time_drift_shutdown_enabled": true,
  "time_drift_check_interval_minutes": 1,
  "time_drift_threshold_seconds": 5
}
```

**Note**: Use small values for testing:
- `time_drift_check_interval_minutes: 1` - Check every minute (faster testing)
- `time_drift_threshold_seconds: 5` - Trigger shutdown if drift > 5 seconds (easy to test)

## Method 1: Test Mode (Recommended for Testing)

The operator provides test endpoints that allow you to simulate time drift without actually changing the system clock.

### Step 1: Enable Test Mode with Simulated Drift

Inject a fake reference time that creates drift:

```bash
# Simulate 60 seconds of drift (enclave is 60 seconds behind)
curl -X POST http://localhost:8080/ops/time-drift/test-mode \
  -H "Content-Type: application/json" \
  -d '{
    "action": "set",
    "offset_seconds": 60
  }'
```

Response:
```json
{
  "status": "test_mode_enabled",
  "current_time": "2024-01-15T10:30:00Z",
  "test_reference_time": "2024-01-15T10:31:00Z",
  "drift_seconds": 60
}
```

### Step 2: Trigger Time Drift Check

Manually trigger the check:

```bash
curl http://localhost:8080/ops/time-drift/check
```

Response:
```json
{
  "status": "check_triggered",
  "message": "Time drift check has been triggered. Check logs for results."
}
```

### Step 3: Check Logs

Check the operator logs to see the result:

```bash
# On EC2 instance
journalctl -u uid2operator.service -f | grep -i "time drift"

# Or in CloudWatch
# Look for log entries containing "Time drift"
```

**Expected Output** (if drift > threshold):
```
ERROR: Time drift detected: 60 seconds (threshold: 5 seconds). 
Enclave time is significantly out of sync. Shutting down operator to trigger instance replacement.
```

**Expected Output** (if drift < threshold):
```
TEST MODE: Time drift check passed: drift=2s (threshold: 5s)
```

### Step 4: Verify Shutdown (if drift exceeded threshold)

If drift exceeded the threshold, the operator should shut down:

```bash
# Check if operator process is still running
ps aux | grep java | grep uid2operator

# Check systemd service status
systemctl status uid2operator.service

# Check logs for shutdown
journalctl -u uid2operator.service --since "1 minute ago" | tail -20
```

### Step 5: Clear Test Mode

After testing, clear test mode to return to normal operation:

```bash
curl -X POST http://localhost:8080/ops/time-drift/test-mode \
  -H "Content-Type: application/json" \
  -d '{
    "action": "clear"
  }'
```

## Method 2: Using Specific Reference Time

You can also set a specific reference time:

```bash
# Set reference time to 1 hour in the future
curl -X POST http://localhost:8080/ops/time-drift/test-mode \
  -H "Content-Type: application/json" \
  -d '{
    "action": "set",
    "reference_time": "2024-01-15T11:30:00Z"
  }'
```

## Method 3: Real Time Drift Test (Advanced)

For testing with actual time drift (requires system access):

### Option A: Lower Threshold Temporarily

1. Set a very low threshold (e.g., 1 second)
2. Wait for natural drift to accumulate
3. Monitor logs

### Option B: Use NTP to Create Drift (Not Recommended)

**WARNING**: This can affect system time. Only use in isolated test environments.

```bash
# On EC2 host (NOT in enclave - you can't change enclave time directly)
# Stop NTP service temporarily
sudo systemctl stop chronyd

# Manually set incorrect time (e.g., 5 minutes fast)
sudo date -s "+5 minutes"

# Restart operator to pick up new time
sudo systemctl restart uid2operator.service

# Monitor for drift detection
journalctl -u uid2operator.service -f
```

## Testing Scenarios

### Scenario 1: Small Drift (Should Pass)

```bash
# Set 2 seconds drift (below 5 second threshold)
curl -X POST http://localhost:8080/ops/time-drift/test-mode \
  -H "Content-Type: application/json" \
  -d '{"action": "set", "offset_seconds": 2}'

# Trigger check
curl http://localhost:8080/ops/time-drift/check

# Expected: Log shows "Time drift check passed"
```

### Scenario 2: Large Drift (Should Trigger Shutdown)

```bash
# Set 60 seconds drift (above 5 second threshold)
curl -X POST http://localhost:8080/ops/time-drift/test-mode \
  -H "Content-Type: application/json" \
  -d '{"action": "set", "offset_seconds": 60}'

# Trigger check
curl http://localhost:8080/ops/time-drift/check

# Expected: Log shows "Time drift detected" and operator shuts down
```

### Scenario 3: Periodic Check

1. Enable test mode with drift
2. Wait for automatic periodic check (based on `time_drift_check_interval_minutes`)
3. Monitor logs to see automatic detection

## Monitoring Test Results

### Check Logs

```bash
# Real-time log monitoring
journalctl -u uid2operator.service -f

# Search for time drift messages
journalctl -u uid2operator.service | grep -i "time drift"

# Check recent errors
journalctl -u uid2operator.service --since "10 minutes ago" --priority err
```

### Expected Log Messages

**Normal Operation:**
```
DEBUG: Time drift check: reference=2024-01-15T10:30:00Z, enclave=2024-01-15T10:30:01Z, drift=1s
DEBUG: Time drift check passed: drift=1s (threshold: 5s)
```

**Test Mode:**
```
WARN: TEST MODE: Time drift check using injected reference time
WARN: Time drift check: reference=2024-01-15T10:31:00Z, enclave=2024-01-15T10:30:00Z, drift=60s
```

**Drift Detected:**
```
ERROR: Time drift detected: 60 seconds (threshold: 5 seconds). 
Enclave time is significantly out of sync. Shutting down operator to trigger instance replacement.
```

**Shutdown Triggered:**
```
# Process exits with status 1
# Systemd detects process exit
# Auto Scaling Group health checks fail
# Instance gets replaced
```

## Verification Checklist

- [ ] Test mode can be enabled via API
- [ ] Time drift check can be triggered manually
- [ ] Logs show correct drift calculation
- [ ] Small drift (< threshold) passes check
- [ ] Large drift (> threshold) triggers shutdown
- [ ] Operator process exits when shutdown triggered
- [ ] Test mode can be cleared
- [ ] Normal operation resumes after clearing test mode

## Troubleshooting

### Test endpoint returns 503
- **Cause**: Shutdown handler not initialized
- **Fix**: Ensure operator has fully started and time drift is enabled in config

### Test mode not working
- **Cause**: Test mode reference time not set
- **Fix**: Verify the POST request succeeded and check response

### Shutdown not triggering
- **Cause**: Drift below threshold, or shutdown disabled
- **Fix**: 
  - Increase `offset_seconds` in test mode
  - Verify `time_drift_shutdown_enabled: true` in config
  - Check threshold value

### Can't access test endpoints
- **Cause**: Endpoints not exposed or network issues
- **Fix**: 
  - Verify operator is running and accessible
  - Check firewall/security group rules
  - Ensure you're using correct port (default: 8080)

## Production Testing

For production testing:

1. **Use a test/staging environment** - Never test shutdown in production
2. **Set appropriate thresholds** - Use realistic values (30-60 seconds)
3. **Monitor Auto Scaling Group** - Verify instance replacement works
4. **Test during low traffic** - Minimize impact
5. **Have rollback plan** - Be ready to disable feature if needed

## Disabling After Testing

To disable time drift detection:

```json
{
  "time_drift_shutdown_enabled": false
}
```

Or remove the configuration properties entirely.
