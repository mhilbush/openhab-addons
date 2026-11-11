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
package org.openhab.binding.thermoworks.internal;

import static org.junit.jupiter.api.Assertions.*;

import java.io.InputStreamReader;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openhab.binding.thermoworks.internal.dto.ThermoworksAccountDTO;
import org.openhab.binding.thermoworks.internal.dto.ThermoworksDeviceDTO;
import org.openhab.binding.thermoworks.internal.dto.ThermoworksProbeDTO;
import org.openhab.binding.thermoworks.internal.dto.ThermoworksResponseDTO;

import com.google.gson.Gson;

/**
 * ThermoworksActualJsonParsingTest
 *
 * @author Mark Hilbush - Initial contribution
 */
public class ThermoworksActualJsonParsingTest {

    private Gson gson;

    @BeforeEach
    public void setUp() {
        gson = new Gson();
    }

    @Test
    public void testParseAccountJson() {
        ClassLoader classLoader = getClass().getClassLoader();
        assertNotNull(classLoader);

        try (InputStreamReader reader = new InputStreamReader(classLoader.getResourceAsStream("account.json"))) {
            assertNotNull(reader, "Unable to find resource file account.json");

            ThermoworksAccountDTO account = gson.fromJson(reader, ThermoworksAccountDTO.class);
            assertNotNull(account, "Failed to parse account.json");

            assertEquals("dh834y7rdh389yd", account.getAccountId(), "Unexpected account ID");
            assertEquals(60, account.getRecommendedPollSeconds(), "Unexpected number of polling seconds");
            assertEquals(4, account.getApiKey().getDeviceIds().size(), "Unexpected number of devices");

            assertTrue(account.getApiKey().getDeviceIds().contains("M100283823"), "Device ID is missing");
            assertTrue(account.getApiKey().getDeviceIds().contains("M102398398"), "Device ID is missing");
            assertTrue(account.getApiKey().getDeviceIds().contains("CC:87:09:BE:42:F5"), "Device ID is missing");
            assertTrue(account.getApiKey().getDeviceIds().contains("F4:c7:4E:87:3C:D1"), "Device ID is missing");

            assertEquals(4, account.getRateLimit().getPerMinute());
            assertEquals(3000, account.getRateLimit().getPerDay());

            assertEquals("default", account.getPlan().getId());
            assertEquals("free", account.getPlan().getApiTier());
        } catch (Exception e) {
            fail("Failed to parse account.json: " + e.getMessage());
        }
    }

    @Test
    public void testParseDevicesJsonForNumberOfDevices() {
        ClassLoader classLoader = getClass().getClassLoader();
        assertNotNull(classLoader);

        try (InputStreamReader reader = new InputStreamReader(classLoader.getResourceAsStream("devices.json"))) {
            assertNotNull(reader, "Unable tio find resource file devices.json");

            ThermoworksResponseDTO response = gson.fromJson(reader, ThermoworksResponseDTO.class);
            assertNotNull(response, "Failed to parse devices.json");

            assertNotNull(response.getDevices(), "Device list is empty");
            assertEquals(4, response.getDevices().size(), "Unexpected number of devices in file");
        } catch (Exception e) {
            fail("Failed parsing devices.json: " + e.getMessage());
        }
    }

    @Test
    public void testParseDevicesJsonForRFXGateway() {
        ClassLoader classLoader = getClass().getClassLoader();
        assertNotNull(classLoader);

        try (InputStreamReader reader = new InputStreamReader(classLoader.getResourceAsStream("devices.json"))) {
            assertNotNull(reader, "Unable tio find resource file devices.json");

            ThermoworksResponseDTO response = gson.fromJson(reader, ThermoworksResponseDTO.class);
            assertNotNull(response, "Failed to parse devices.json");

            ThermoworksDeviceDTO device = response.getDevices().stream()
                    .filter(d -> "CC:87:09:BE:42:F5".equals(d.getSerialNumberRaw())).findFirst().orElse(null);

            assertNotNull(device, "Unable to find RFX Gateway in file");
            assertEquals("My RFX Gateway", device.getName());
            assertEquals("rfx gateway", device.getModel());
            assertEquals(85, device.getBatteryLevel());
            assertEquals("discharging", device.getBatteryState());
            assertEquals("2026-11-04T17:49:40.886Z", device.getLastUpdated());

            assertEquals(1, device.getProbes().size(), "Unexpected number of probes for RFX Gateway, should be 1");

            ThermoworksProbeDTO probe = device.getProbes().get(0);
            assertNotNull(probe, "Probe is missing");
            assertEquals(84.9000015258789, probe.getCurrentTemperatureRaw());
            assertEquals(84.9, probe.getCurrentTemperature());
            assertEquals("F", probe.getTemperatureUnit());
            assertFalse(probe.getIsAlarmTriggered());

        } catch (Exception e) {
            fail("Failed parsing devices.json: " + e.getMessage());
        }
    }
}
