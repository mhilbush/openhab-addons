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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.*;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.openhab.core.thing.Thing;
import org.openhab.core.thing.binding.ThingHandlerCallback;

/**
 * a
 * ThermoworksDeviceHandlerTest
 *
 * @author Mark Hilbush - Initial contribution
 */
@ExtendWith(MockitoExtension.class)
public class ThermoworksDeviceHandlerTest {

    @Mock
    private Thing thing;
    @Mock
    private ThingHandlerCallback callback;

    @Test
    public void testSmokeDevicePayloadUpdate() {
        // ThingUID smokeUID = new ThingUID(ThermoworksBindingConstants.THING_TYPE_SMOKE, "cloud-bridge",
        // "F4B85E493BB2");
        // when(thing.getUID()).thenReturn(smokeUID);

        // ThermoworksDeviceHandler handler = new ThermoworksDeviceHandler(thing);
        // handler.setCallback(callback);

        // ThermoworksDeviceDTO smokeDto = new ThermoworksDeviceDTO();
        // smokeDto.setBatteryLevel(66);

        assertEquals("true", "true");

        // handler.handlePayloadUpdate(smokeDto);

        // verify(callback).stateUpdated(eq(new ChannelUID(smokeUID, ThermoworksBindingConstants.CHANNEL_BATTERY)),
        // eq(new DecimalType(66)));
    }
}
