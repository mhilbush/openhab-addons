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

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static org.openhab.binding.thermoworks.internal.ThermoworksBindingConstants.*;

import org.eclipse.jdt.annotation.NonNullByDefault;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.openhab.binding.thermoworks.internal.dto.ThermoworksDeviceDTO;
import org.openhab.binding.thermoworks.internal.dto.ThermoworksProbeDTO;
import org.openhab.core.library.types.DecimalType;
import org.openhab.core.library.types.OnOffType;
import org.openhab.core.library.types.QuantityType;
import org.openhab.core.library.types.StringType;
import org.openhab.core.library.unit.ImperialUnits;
import org.openhab.core.library.unit.Units;
import org.openhab.core.thing.ChannelUID;
import org.openhab.core.thing.Thing;
import org.openhab.core.thing.ThingUID;
import org.openhab.core.thing.binding.ThingHandlerCallback;
import org.openhab.core.thing.binding.builder.ThingBuilder;

/**
 * a
 * ThermoworksDeviceHandlerTest
 *
 * @author Mark Hilbush - Initial contribution
 */
@ExtendWith(MockitoExtension.class)
@NonNullByDefault
public class ThermoworksDeviceHandlerTest {

    private static final String SERIAL_NUMBER = "042855493222";

    @Test
    public void testCommonChannels() {
        ThingUID bridgeUID = new ThingUID(THING_TYPE_CLOUD_BRIDGE, "myaccount");
        ThingUID thingUID = new ThingUID(THING_TYPE_SIGNALS, bridgeUID, SERIAL_NUMBER);
        Thing thing = ThingBuilder.create(THING_TYPE_SIGNALS, thingUID).withBridge(bridgeUID).build();
        ThingHandlerCallback callback = mock(ThingHandlerCallback.class);
        ThermoworksDeviceHandler handler = spy(new ThermoworksDeviceHandler(thing));
        // ThermoworksDeviceHandler deviceHandler = mock(ThermoworksDeviceHandler.class);
        ThermoworksBridgeHandler bridgeHandler = mock(ThermoworksBridgeHandler.class);
        doReturn(bridgeHandler).when(handler).getBridgeHandler();
        handler.setCallback(callback);

        ThermoworksDeviceDTO deviceDto = new ThermoworksDeviceDTO();
        deviceDto.setSerialNumber(SERIAL_NUMBER);
        deviceDto.setBatteryLevel(66);
        deviceDto.setBatteryState("charging");
        deviceDto.setRssi(-60);
        deviceDto.setIsOnline(Boolean.TRUE);
        deviceDto.setLastUpdated("2026-11-12T19:07:33.027Z");

        handler.handlePayloadUpdate(deviceDto);

        verify(callback).stateUpdated(eq(new ChannelUID(thingUID, CHANNEL_BATTERYLEVEL)), eq(new DecimalType(66)));
        verify(callback).stateUpdated(eq(new ChannelUID(thingUID, CHANNEL_BATTERY_STATE)),
                eq(new StringType("charging")));
        verify(callback).stateUpdated(eq(new ChannelUID(thingUID, CHANNEL_RSSI)),
                eq(new QuantityType<>(-60, Units.DECIBEL_MILLIWATTS)));
        verify(callback).stateUpdated(eq(new ChannelUID(thingUID, CHANNEL_ONLINE)), eq(OnOffType.ON));
    }

    @Test
    public void testProbeChannels() {
        ThingUID bridgeUID = new ThingUID(THING_TYPE_CLOUD_BRIDGE, "myaccount");
        ThingUID thingUID = new ThingUID(THING_TYPE_SIGNALS, bridgeUID, SERIAL_NUMBER);
        Thing thing = ThingBuilder.create(THING_TYPE_SIGNALS, thingUID).withBridge(bridgeUID).build();
        ThingHandlerCallback callback = mock(ThingHandlerCallback.class);
        ThermoworksDeviceHandler handler = spy(new ThermoworksDeviceHandler(thing));
        // ThermoworksDeviceHandler deviceHandler = mock(ThermoworksDeviceHandler.class);
        ThermoworksBridgeHandler bridgeHandler = mock(ThermoworksBridgeHandler.class);
        // doReturn(bridgeHandler).when(handler).getBridgeHandler();
        handler.setCallback(callback);

        ThermoworksDeviceDTO device = new ThermoworksDeviceDTO();
        device.setSerialNumber(SERIAL_NUMBER);
        device.setBatteryLevel(66);
        device.setBatteryState("charging");
        device.setRssi(-60);
        device.setIsOnline(Boolean.TRUE);
        device.setLastUpdated("2026-11-12T19:07:33.027Z");

        ThermoworksProbeDTO probe = new ThermoworksProbeDTO();
        probe.setStatus("NORMAL");
        probe.setLabel("Brisket");
        probe.setCurrentTemperature(194.8);
        probe.setTemperatureUnit("F");
        probe.setIsAlarmTriggered(true);
        probe.setMinimumTemperature(40.6);
        probe.setMaximumTemperature(201.3);

        handler.updateProbeState(SERIAL_NUMBER, true, probe, 1);

        verify(callback).stateUpdated(eq(new ChannelUID(thingUID, "probe1" + CHANNEL_PROBE_TEMP_SUFFIX)),
                eq(new QuantityType<>(194.8, ImperialUnits.FAHRENHEIT)));
        verify(callback).stateUpdated(eq(new ChannelUID(thingUID, "probe1" + CHANNEL_PROBE_LABEL_SUFFIX)),
                eq(new StringType("Brisket")));
        verify(callback).stateUpdated(eq(new ChannelUID(thingUID, "probe1" + CHANNEL_PROBE_ALARM_SUFFIX)),
                eq(OnOffType.ON));
        verify(callback).stateUpdated(eq(new ChannelUID(thingUID, "probe1" + CHANNEL_PROBE_MIN_TEMP_SUFFIX)),
                eq(new QuantityType<>(40.6, ImperialUnits.FAHRENHEIT)));
        verify(callback).stateUpdated(eq(new ChannelUID(thingUID, "probe1" + CHANNEL_PROBE_MAX_TEMP_SUFFIX)),
                eq(new QuantityType<>(201.3, ImperialUnits.FAHRENHEIT)));
    }
}
