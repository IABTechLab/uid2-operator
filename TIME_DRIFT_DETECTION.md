# Time Drift Detection and Automatic Instance Termination

## Overview

This feature automatically detects time drift in the Nitro Enclave and triggers instance termination to allow Auto Scaling Group to replace the instance with a fresh one that has correct time synchronization.

## How It Works

1. **Periodic Time Drift Check**: The operator periodically (default: every 15 minutes) checks the enclave's clock against an external time reference (worldtimeapi.org).

2. **Drift Detection**: If the time drift exceeds the configured threshold (default: 30 seconds), the operator logs an error and triggers shutdown.

3. **Automatic Recovery**: When the operator shuts down, the EC2 instance terminates (if configured) or the Auto Scaling Group detects the unhealthy instance and replaces it with a new one.

4. **Fresh Start**: The new EC2 instance syncs with NTP at boot, and the new enclave gets fresh, correct time from the host.

## Configuration

Add the following configuration properties to your operator config JSON:

```json
{
  "time_drift_shutdown_enabled": true,
  "time_drift_check_interval_minutes": 15,
  "time_drift_threshold_seconds": 30
}
```

### Configuration Properties

- **`time_drift_shutdown_enabled`** (boolean, default: `false`)
  - Enable or disable time drift detection and automatic shutdown
  - Set to `true` to enable the feature

- **`time_drift_check_interval_minutes`** (integer, default: `15`)
  - How often to check for time drift (in minutes)
  - Recommended: 15-30 minutes

- **`time_drift_threshold_seconds`** (integer, default: `30`)
  - Maximum allowed time drift before triggering shutdown (in seconds)
  - Recommended: 30-60 seconds for production

## Example Configuration

For AWS private operator deployment, add to your Secrets Manager config:

```json
{
  "api_token": "your-token",
  "service_instances": "6",
  "time_drift_shutdown_enabled": true,
  "time_drift_check_interval_minutes": 15,
  "time_drift_threshold_seconds": 30,
  ...
}
```

## How Termination Works

When time drift is detected:

1. The operator logs an error:
   ```
   ERROR: Time drift detected: 120 seconds (threshold: 30 seconds). 
   Enclave time is significantly out of sync. Shutting down operator to trigger instance replacement.
   ```

2. The operator calls `ShutdownService.Shutdown(1)`, which exits the JVM.

3. The systemd service (`uid2operator.service`) detects the process exit.

4. **Option A**: If you have a systemd service configured to restart on failure, it will restart the enclave (but this won't fix time drift).

5. **Option B** (Recommended): Configure the Auto Scaling Group health checks to detect the unhealthy instance and terminate it:
   - Use ALB target health checks pointing to `/ops/healthcheck`
   - When the operator is down, health checks fail
   - Auto Scaling Group terminates the unhealthy instance
   - Auto Scaling Group launches a new instance with correct time

## Testing

To test the time drift detection:

1. **Enable the feature** in your config:
   ```json
   {
     "time_drift_shutdown_enabled": true,
     "time_drift_check_interval_minutes": 1,
     "time_drift_threshold_seconds": 5
   }
   ```

2. **Manually set incorrect time** (for testing only):
   - This is difficult in an enclave, but you can test by temporarily modifying the clock

3. **Monitor logs** for time drift checks:
   ```bash
   journalctl -u uid2operator.service -f | grep -i "time drift"
   ```

4. **Verify shutdown** occurs when drift exceeds threshold

## Monitoring

Monitor the following in your logs:

- `Time drift check: reference=..., enclave=..., drift=...s` - Debug logs showing drift measurements
- `Time drift check passed: drift=...s` - Normal operation
- `Time drift detected: ... seconds` - Warning that drift was detected
- `Shutting down operator to trigger instance replacement` - Shutdown triggered

## Important Notes

1. **Network Access Required**: The time drift check requires outbound HTTPS access to `worldtimeapi.org`. Ensure your enclave has network connectivity.

2. **False Positives**: Network latency or temporary service unavailability may cause false positives. The feature is designed to be conservative - it only shuts down when drift is significant and persistent.

3. **Auto Scaling Group Configuration**: Ensure your Auto Scaling Group is configured to:
   - Use health checks (ALB target health)
   - Replace unhealthy instances automatically
   - Have proper scaling policies

4. **Graceful Shutdown**: The shutdown is immediate (System.exit), so ensure your Auto Scaling Group can handle instance replacements gracefully.

## Troubleshooting

### Time drift check not running
- Verify `time_drift_shutdown_enabled` is set to `true`
- Check logs for "Time drift shutdown is disabled" message
- Verify Vertx is available (should be initialized during startup)

### Time drift check failing
- Check network connectivity to `worldtimeapi.org`
- Verify HTTPS/SSL is working from the enclave
- Check logs for "Time drift check request failed" messages

### Shutdown not triggering instance replacement
- Verify Auto Scaling Group health checks are configured
- Check that ALB target health is monitoring `/ops/healthcheck`
- Ensure Auto Scaling Group has proper termination and replacement policies
