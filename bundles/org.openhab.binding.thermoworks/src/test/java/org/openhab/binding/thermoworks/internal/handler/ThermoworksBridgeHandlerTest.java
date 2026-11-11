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

import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static org.openhab.binding.thermoworks.internal.ThermoworksBindingConstants.*;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ScheduledExecutorService;

import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.client.api.ContentResponse;
import org.eclipse.jetty.client.api.Request;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.openhab.binding.thermoworks.internal.discovery.ThermoworksDiscoveryService;
import org.openhab.core.io.net.http.HttpClientFactory;
import org.openhab.core.thing.Bridge;
import org.openhab.core.thing.ThingStatus;
import org.openhab.core.thing.ThingStatusDetail;
import org.openhab.core.thing.ThingUID;
import org.openhab.core.thing.binding.ThingHandlerCallback;

/**
 *
 * ThermoworksBridgeHandlerTest
 *
 * @author Mark Hilbush - Initial contribution
 */
@ExtendWith(MockitoExtension.class)
public class ThermoworksBridgeHandlerTest {

    @Mock
    private Bridge bridge;
    @Mock
    private ThingHandlerCallback callback;
    @Mock
    private HttpClientFactory httpClientFactory = mock(HttpClientFactory.class);
    @Mock
    private HttpClient httpClient;
    @Mock
    private Request request;
    @Mock
    private ContentResponse response;
    @Mock
    private ThermoworksDiscoveryService discoveryService;
    @Mock
    private ScheduledExecutorService scheduler;

    private ThermoworksBridgeHandler bridgeHandler;

    @BeforeEach
    public void setUp() throws Exception {
        ThingUID bridgeUID = new ThingUID("thermoworks", "account", "testaccount");
        lenient().when(bridge.getUID()).thenReturn(bridgeUID);

        Map<String, Object> configMap = new HashMap<>();
        configMap.put(CONFIG_API_KEY, "test-api-key");
        configMap.put(CONFIG_REFRESH_INTERVAL_SECONDS, 60);
        lenient().when(bridge.getConfiguration()).thenReturn(new org.openhab.core.config.core.Configuration(configMap));

        bridgeHandler = spy(new ThermoworksBridgeHandler(bridge, httpClient));
        bridgeHandler.setCallback(callback);

        // doReturn(scheduler).when(bridgeHandler).getScheduler();
    }

    @Test
    public void testInitializeMissingApiKey() {
        Map<String, Object> configMap = new HashMap<>();
        configMap.put(CONFIG_API_KEY, "");
        when(bridge.getConfiguration()).thenReturn(new org.openhab.core.config.core.Configuration(configMap));

        bridgeHandler.initialize();

        verify(callback).statusUpdated(eq(bridge), argThat(status -> status.getStatus() == ThingStatus.OFFLINE
                && status.getStatusDetail() == ThingStatusDetail.CONFIGURATION_ERROR));
    }
}
