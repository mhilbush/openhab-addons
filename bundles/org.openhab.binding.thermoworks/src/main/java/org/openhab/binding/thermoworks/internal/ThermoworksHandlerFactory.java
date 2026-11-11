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

import static org.openhab.binding.thermoworks.internal.ThermoworksBindingConstants.*;

import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;

import org.eclipse.jdt.annotation.NonNullByDefault;
import org.eclipse.jdt.annotation.Nullable;
import org.eclipse.jetty.client.HttpClient;
import org.openhab.binding.thermoworks.internal.discovery.ThermoworksDiscoveryService;
import org.openhab.binding.thermoworks.internal.handler.ThermoworksBridgeHandler;
import org.openhab.binding.thermoworks.internal.handler.ThermoworksDeviceHandler;
import org.openhab.core.config.discovery.DiscoveryService;
import org.openhab.core.io.net.http.HttpClientFactory;
import org.openhab.core.thing.Bridge;
import org.openhab.core.thing.Thing;
import org.openhab.core.thing.ThingTypeUID;
import org.openhab.core.thing.ThingUID;
import org.openhab.core.thing.binding.BaseThingHandlerFactory;
import org.openhab.core.thing.binding.ThingHandler;
import org.openhab.core.thing.binding.ThingHandlerFactory;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;

/**
 *
 * ThermoworksHandlerFactory
 *
 * @author Mark Hilbush - Initial contribution
 */
@NonNullByDefault
@Component(service = ThingHandlerFactory.class, immediate = true, configurationPid = "binding.thermoworks")
public class ThermoworksHandlerFactory extends BaseThingHandlerFactory {
    private final Map<ThingUID, ServiceRegistration<?>> discoveryServiceRegs = new HashMap<>();

    private HttpClient httpClient;

    @Activate
    public ThermoworksHandlerFactory(@Reference HttpClientFactory httpClientFactory) {
        this.httpClient = httpClientFactory.getCommonHttpClient();
    }

    @Override
    public boolean supportsThingType(ThingTypeUID thingTypeUID) {
        return SUPPORTED_THING_TYPES.contains(thingTypeUID);
    }

    @Override
    protected @Nullable ThingHandler createHandler(Thing thing) {
        ThingTypeUID thingTypeUID = thing.getThingTypeUID();

        if (THING_TYPE_CLOUD_BRIDGE.equals(thingTypeUID)) {
            ThermoworksBridgeHandler handler = new ThermoworksBridgeHandler((Bridge) thing, httpClient);
            registerDeviceDiscoveryService(handler);
            return handler;
        } else if (THING_TYPE_SIGNALS.equals(thingTypeUID) || THING_TYPE_SMOKE.equals(thingTypeUID)
                || THING_TYPE_RFX_GATEWAY.equals(thingTypeUID) || THING_TYPE_RFX_MEAT_PROBE.equals(thingTypeUID)
                || THING_TYPE_GENERIC.equals(thingTypeUID)) {
            return new ThermoworksDeviceHandler(thing);
        }
        return null;
    }

    @Override
    protected synchronized void removeHandler(ThingHandler thingHandler) {
        if (thingHandler instanceof ThermoworksBridgeHandler) {
            ThingUID thingUID = thingHandler.getThing().getUID();
            unregisterDeviceDiscoveryService(thingUID);
        }
        super.removeHandler(thingHandler);
    }

    private synchronized void registerDeviceDiscoveryService(ThermoworksBridgeHandler bridgeHandler) {
        ThermoworksDiscoveryService discoveryService = new ThermoworksDiscoveryService(bridgeHandler);
        discoveryService.activate(null);
        this.discoveryServiceRegs.put(bridgeHandler.getThing().getUID(),
                bundleContext.registerService(DiscoveryService.class.getName(), discoveryService, new Hashtable<>()));
    }

    private void unregisterDeviceDiscoveryService(ThingUID bridgeUID) {
        ServiceRegistration<?> serviceReg = discoveryServiceRegs.remove(bridgeUID);
        if (serviceReg != null) {
            ThermoworksDiscoveryService discoveryService = (ThermoworksDiscoveryService) bundleContext
                    .getService(serviceReg.getReference());
            serviceReg.unregister();
            if (discoveryService != null) {
                discoveryService.deactivate();
            }
        }
    }
}
