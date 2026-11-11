/*
 * Copyright (c) 2010-2026 Contributors to the openHAB project
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0
 *
 * SPDX-License-Identifier: EPL-2.0
 */
package org.openhab.binding.thermoworks.internal.handler;

import static org.openhab.binding.thermoworks.internal.ThermoworksBindingConstants.*;

import java.time.ZonedDateTime;
import java.time.format.DateTimeParseException;
import java.util.List;

import javax.measure.Unit;
import javax.measure.quantity.Temperature;

import org.eclipse.jdt.annotation.NonNullByDefault;
import org.eclipse.jdt.annotation.Nullable;
import org.openhab.binding.thermoworks.internal.dto.ThermoworksDeviceDTO;
import org.openhab.binding.thermoworks.internal.dto.ThermoworksProbeDTO;
import org.openhab.core.library.types.DateTimeType;
import org.openhab.core.library.types.DecimalType;
import org.openhab.core.library.types.OnOffType;
import org.openhab.core.library.types.QuantityType;
import org.openhab.core.library.types.StringType;
import org.openhab.core.library.unit.ImperialUnits;
import org.openhab.core.library.unit.SIUnits;
import org.openhab.core.thing.Bridge;
import org.openhab.core.thing.ChannelUID;
import org.openhab.core.thing.Thing;
import org.openhab.core.thing.ThingStatus;
import org.openhab.core.thing.binding.BaseThingHandler;
import org.openhab.core.types.Command;
import org.openhab.core.types.UnDefType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * ThermoworksDeviceHandler
 *
 * @author Mark Hilbush - Initial contribution
 */
@NonNullByDefault
public class ThermoworksDeviceHandler extends BaseThingHandler {

    // Returned for a channel if there is no probe connected
    private static final String NO_PROBE = "NO PROBE";

    // The channel of an RFX Meat probe that is the lowest temperature across all 4 sensors
    private static final String COMPUTED = "computed";

    private static final int CHANNELS_1 = 1;
    private static final int CHANNELS_2 = 2;
    private static final int CHANNELS_4 = 4;

    private final Logger logger = LoggerFactory.getLogger(ThermoworksDeviceHandler.class);

    public ThermoworksDeviceHandler(Thing thing) {
        super(thing);
    }

    @Override
    public void initialize() {
        updateStatus(ThingStatus.ONLINE);
    }

    @Override
    public void handleCommand(ChannelUID channelUID, Command command) {
        // ThermoWorks Developer Cloud API is currently read-only for device telemetry
    }

    public void handlePayloadUpdate(ThermoworksDeviceDTO deviceDto) {
        logger.debug("Handling payload update for device {}", deviceDto.getSerialNumber());

        ThermoworksBridgeHandler bridgeHandler = getBridgeHandler();
        if (bridgeHandler == null) {
            logger.warn("No bridge handler found for device: {}", deviceDto.getSerialNumber());
            return;
        }

        String serialNumber = deviceDto.getSerialNumber();
        if (serialNumber == null || serialNumber.isEmpty()) {
            logger.warn("Device serial number is null or empty, cannot update device state");
            return;
        }

        Boolean isOnline = deviceDto.getIsOnline();

        Integer batteryLevel = deviceDto.getBatteryLevel();
        updateState(CHANNEL_BATTERYLEVEL, batteryLevel != null ? new DecimalType(batteryLevel) : UnDefType.UNDEF);

        String batteryState = deviceDto.getBatteryState();
        updateState(CHANNEL_BATTERY_STATE, batteryState != null ? new StringType(batteryState) : UnDefType.UNDEF);

        Integer rssi = deviceDto.getRssi();
        updateState(CHANNEL_RSSI, rssi != null ? new DecimalType(rssi) : UnDefType.UNDEF);

        updateState(CHANNEL_ONLINE, deviceDto.getIsOnline() ? OnOffType.ON : OnOffType.OFF);

        String lastUpdated = deviceDto.getLastUpdated();
        if (lastUpdated != null) {
            try {
                updateState(CHANNEL_LAST_UPDATED, new DateTimeType(ZonedDateTime.parse(lastUpdated)));
            } catch (DateTimeParseException e) {
                logger.info("Failed to parse lastUpdated timestamp for device {}: {}", serialNumber, lastUpdated);
                updateState(CHANNEL_LAST_UPDATED, UnDefType.UNDEF);
            }
        }

        // Process the specific channels for an RFX Gateway device
        if (getThing().getThingTypeUID().equals(THING_TYPE_RFX_GATEWAY)) {
            logger.debug("Processing probe for RFX Gateway device {}", serialNumber);
            updateProbesState(serialNumber, isOnline, deviceDto, CHANNELS_1);
        }

        // Process the probes for an RFX Meat device, the "computed" probe is the
        // lowest temperature accross all 4 temerature sensors
        if (getThing().getThingTypeUID().equals(THING_TYPE_RFX_MEAT_PROBE)) {
            logger.debug("Processing probes for RFX Meat device {}", serialNumber);
            List<ThermoworksProbeDTO> probes = deviceDto.getProbes();
            if (probes != null) {
                for (int i = 0; i < probes.size(); i++) {
                    ThermoworksProbeDTO probe = probes.get(i);
                    if (COMPUTED.equals(probe.getType())) {
                        updateProbeState(serialNumber, isOnline, probe, CHANNELS_1);
                    }
                }
            }
        }

        // Process the probes for a Smoke device
        if (getThing().getThingTypeUID().equals(THING_TYPE_SMOKE)) {
            logger.debug("Processing probes for Smoke device {}", serialNumber);
            updateProbesState(serialNumber, isOnline, deviceDto, CHANNELS_2);
        }

        // Process the probes for a Signals device
        if (getThing().getThingTypeUID().equals(THING_TYPE_SIGNALS)) {
            logger.debug("Processing probes for Signals device {}", serialNumber);
            updateProbesState(serialNumber, isOnline, deviceDto, CHANNELS_4);
        }

        // Process the probes for a Generic device
        if (getThing().getThingTypeUID().equals(THING_TYPE_GENERIC)) {
            logger.debug("Processing probes for Generic/Unknown device {}", serialNumber);
            updateProbesState(serialNumber, isOnline, deviceDto, CHANNELS_1);
        }
    }

    private void updateProbesState(String serialNumber, Boolean isOnline, ThermoworksDeviceDTO deviceDto,
            int expectedProbeCount) {
        List<ThermoworksProbeDTO> probes = deviceDto.getProbes();
        if (probes != null && probes.size() == expectedProbeCount) {
            for (int i = 0; i < probes.size(); i++) {
                updateProbeState(serialNumber, isOnline, probes.get(i), i + 1);
            }
        }
    }

    private void updateProbeState(String serialNumber, Boolean isOnline, ThermoworksProbeDTO probe, int probeIndex) {
        String temperatureChannelId = CHANNEL_PROBE_PREFIX + probeIndex + CHANNEL_PROBE_TEMP_SUFFIX;
        String labelChannelId = CHANNEL_PROBE_PREFIX + probeIndex + CHANNEL_PROBE_LABEL_SUFFIX;
        String alarmChannelId = CHANNEL_PROBE_PREFIX + probeIndex + CHANNEL_PROBE_ALARM_SUFFIX;

        Unit<Temperature> tempUnit;
        if (probe.getStatus() == null || NO_PROBE.equals(probe.getStatus())) {
            logger.debug("No probe detected on channel {} for device: {}", probeIndex, serialNumber);
            updateState(temperatureChannelId, UnDefType.UNDEF);
            updateState(labelChannelId, UnDefType.UNDEF);
            updateState(alarmChannelId, UnDefType.UNDEF);
            return;
        } else {
            Double tempValue = probe.getCurrentTemperature();
            tempUnit = convertTemperatureUnit(probe.getTemperatureUnit());
            if (tempValue == null || tempUnit == null) {
                updateState(temperatureChannelId, UnDefType.UNDEF);
                updateState(labelChannelId, UnDefType.UNDEF);
                updateState(alarmChannelId, UnDefType.UNDEF);
                return;
            }
            logger.debug("Updating states for probe {} of device {} with temperature {} {}", probeIndex, serialNumber,
                    tempValue, tempUnit);
            updateState(temperatureChannelId, isOnline ? new QuantityType<>(tempValue, tempUnit) : UnDefType.UNDEF);
            updateState(labelChannelId,
                    probe.getLabel() != null && isOnline ? new StringType(probe.getLabel()) : UnDefType.UNDEF);
            updateState(alarmChannelId, probe.getIsAlarmTriggered() && isOnline ? OnOffType.ON : OnOffType.OFF);
        }

        // Note high and low alarm temperatures are Integers
        Integer tempValue;
        tempValue = probe.getAlarmHighTemperature();
        updateState(CHANNEL_PROBE_PREFIX + probeIndex + CHANNEL_PROBE_ALARM_HIGH_TEMP_SUFFIX,
                tempValue != null ? new QuantityType<>(tempValue, tempUnit) : UnDefType.UNDEF);
        updateState(CHANNEL_PROBE_PREFIX + probeIndex + CHANNEL_PROBE_ALARM_HIGH_ENABLED_SUFFIX,
                probe.getIsAlarmHighEnabled() ? OnOffType.ON : OnOffType.OFF);
        updateState(CHANNEL_PROBE_PREFIX + probeIndex + CHANNEL_PROBE_ALARM_HIGH_ALARM_SUFFIX,
                probe.getIsAlarmHighTriggered() ? OnOffType.ON : OnOffType.OFF);

        tempValue = probe.getAlarmLowTemperature();
        updateState(CHANNEL_PROBE_PREFIX + probeIndex + CHANNEL_PROBE_ALARM_LOW_TEMP_SUFFIX,
                tempValue != null ? new QuantityType<>(tempValue, tempUnit) : UnDefType.UNDEF);
        updateState(CHANNEL_PROBE_PREFIX + probeIndex + CHANNEL_PROBE_ALARM_LOW_ENABLED_SUFFIX,
                probe.getIsAlarmLowEnabled() ? OnOffType.ON : OnOffType.OFF);
        updateState(CHANNEL_PROBE_PREFIX + probeIndex + CHANNEL_PROBE_ALARM_LOW_ALARM_SUFFIX,
                probe.getIsAlarmLowTriggered() ? OnOffType.ON : OnOffType.OFF);
    }

    // private State getRfxGatewayAmbientTemp(String serialNumber, Boolean isOnline, ThermoworksDeviceDTO deviceDto) {
    // if (!isOnline || deviceDto.getProbes() == null || deviceDto.getProbes().isEmpty()) {
    // return UnDefType.UNDEF;
    // } else {
    // String status = deviceDto.getProbes().get(0).getStatus();
    // if (status == null || NO_PROBE.equals(status)) {
    // logger.debug("No probe detected for RFX Gateway device: {}", serialNumber);
    // return UnDefType.UNDEF;
    // } else {
    // Double ambientTemp = deviceDto.getProbes().get(0).getCurrentTemperature();
    // Unit<Temperature> tempUnit = convertTemperatureUnit(deviceDto.getProbes().get(0).getTemperatureUnit());
    // if (ambientTemp == null || tempUnit == null) {
    // return UnDefType.UNDEF;
    // }
    // return new QuantityType<>(ambientTemp, tempUnit);
    // }
    // }
    // }

    private @Nullable Unit<Temperature> convertTemperatureUnit(@Nullable String tempUnit) {
        if (tempUnit == null) {
            return null;
        }
        if ("C".equals(tempUnit)) {
            return SIUnits.CELSIUS;
        } else if ("F".equals(tempUnit)) {
            return ImperialUnits.FAHRENHEIT;
        } else {
            return null;
        }
    }

    private @Nullable ThermoworksBridgeHandler getBridgeHandler() {
        Bridge bridge = getBridge();
        if (bridge == null) {
            logger.info("No bridge found for device {}", getThing().getUID());
            return null;
        }
        return (ThermoworksBridgeHandler) bridge.getHandler();
    }
}
