"""GPIO relay driver for Raspberry Pi deployments."""

from __future__ import annotations

import time

from .. import store
from .relay import RelayPulse, RelayPulseResult


class GpioRelayDriver:
    """Momentary GPIO relay pulses using gpiozero.

    `pulse.channel` is interpreted as a BCM GPIO number. The relay board must be
    wired active-high with normally-open contacts so de-energized means no open
    command.
    """

    name = "gpiozero"

    def pulse(self, pulse: RelayPulse) -> RelayPulseResult:
        from gpiozero import OutputDevice  # type: ignore[import-not-found]

        started_at = store.utc_now()
        device = OutputDevice(pulse.channel, active_high=True, initial_value=False)
        try:
            device.on()
            time.sleep(pulse.duration_ms / 1000)
        finally:
            device.off()
            device.close()
        return RelayPulseResult(
            channel=pulse.channel,
            duration_ms=pulse.duration_ms,
            started_at=started_at,
            ended_at=store.utc_now(),
            driver=self.name,
        )

