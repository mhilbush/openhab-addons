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
import org.openhab.binding.thermoworks.internal.dto.ThermoworksResponseDTO;

import com.google.gson.Gson;

/**
 *
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
    public void testParseActualAccountJson() {
        ClassLoader classLoader = getClass().getClassLoader();
        assertNotNull(classLoader);

        try (InputStreamReader reader = new InputStreamReader(classLoader.getResourceAsStream("md-account.json"))) {

            assertNotNull(reader, "md-account.json resource not found");
            ThermoworksAccountDTO accountObj = gson.fromJson(reader, ThermoworksAccountDTO.class);
            assertNotNull(accountObj, "Failed to parse md-account.json");
            assertEquals("Pki55GXRYuiJATiP9Lqo", accountObj.getAccountId());
            // assertEquals("Pki55GXRYuiJATiP9Lqo", "Pki55GXRYuiJATiP9Lqo");

        } catch (Exception e) {
            fail("Failed parsing md-account.json: " + e.getMessage());
        }
    }

    @Test
    public void testParseActualDevicesJson() {
        ClassLoader classLoader = getClass().getClassLoader();
        assertNotNull(classLoader);

        try (InputStreamReader reader = new InputStreamReader(classLoader.getResourceAsStream("md-devices.json"))) {

            assertNotNull(reader, "md-devices.json resource not found");
            ThermoworksResponseDTO response = gson.fromJson(reader, ThermoworksResponseDTO.class);
            assertNotNull(response);
            assertNotNull(response.getDevices());
            assertEquals(4, response.getDevices().size());

        } catch (Exception e) {
            fail("Failed parsing md-devices.json: " + e.getMessage());
        }
    }
}
