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
package org.openhab.binding.thermoworks.internal.discovery;

import static org.openhab.binding.thermoworks.internal.ThermoworksBindingConstants.*;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import org.eclipse.jdt.annotation.NonNullByDefault;
import org.eclipse.jdt.annotation.Nullable;
import org.openhab.binding.thermoworks.internal.dto.ThermoworksDeviceDTO;
import org.openhab.binding.thermoworks.internal.dto.ThermoworksResponseDTO;
import org.openhab.binding.thermoworks.internal.handler.ThermoworksBridgeHandler;
import org.openhab.core.config.discovery.AbstractDiscoveryService;
import org.openhab.core.config.discovery.DiscoveryResult;
import org.openhab.core.config.discovery.DiscoveryResultBuilder;
import org.openhab.core.thing.ThingUID;
import org.osgi.service.component.annotations.Deactivate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.Gson;

@NonNullByDefault
public class ThermoworksDiscoveryService extends AbstractDiscoveryService {

    private final Logger logger = LoggerFactory.getLogger(ThermoworksDiscoveryService.class);

    private final ThermoworksBridgeHandler bridgeHandler;
    private final Gson gson;

    public ThermoworksDiscoveryService(ThermoworksBridgeHandler bridgeHandler) {
        super(SUPPORTED_THING_TYPES, 10, true);
        this.bridgeHandler = bridgeHandler;
        this.gson = bridgeHandler.getGson();
    }

    @Override
    public void activate(@Nullable Map<String, Object> activationParams) {
        super.activate(activationParams);
        logger.debug("Discovery: ThermoWorks Discovery Service activated.");
    }

    @Deactivate
    public void deactivate() {
        logger.debug("Discovery: ThermoWorks Discovery Service deactivated.");
        removeOlderResults(Instant.now());
    }

    public void discoverDevice(ThingUID bridgeUID, ThermoworksDeviceDTO deviceDto) {
        String serialNumber = deviceDto.getSerialNumber();
        String model = deviceDto.getModel() != null ? deviceDto.getModel().toUpperCase() : "";
        String firmwareVersion = deviceDto.getFirmwareVersion() != null ? deviceDto.getFirmwareVersion() : "Unknown";

        if (serialNumber == null || serialNumber.isEmpty()) {
            logger.warn("Discovery: Device serial number is missing, cannot discover device.");
            return;
        }

        ThingUID deviceUID;
        String labelName;
        if (MODELS_RFX_GATEWAY.contains(model)) {
            deviceUID = new ThingUID(THING_TYPE_RFX_GATEWAY, bridgeUID, serialNumber);
            labelName = "ThermoWorks RFX Gateway (" + deviceDto.getName() + ")";
        } else if (MODELS_RFX_MEAT.contains(model)) {
            deviceUID = new ThingUID(THING_TYPE_RFX_MEAT_PROBE, bridgeUID, serialNumber);
            labelName = "ThermoWorks RFX MEAT Wireless Probe (" + deviceDto.getName() + ")";
        } else if (MODELS_SIGNALS.contains(model)) {
            deviceUID = new ThingUID(THING_TYPE_SIGNALS, bridgeUID, serialNumber);
            labelName = "ThermoWorks Signals (" + deviceDto.getName() + ")";
        } else if (MODELS_SMOKE.contains(model)) {
            deviceUID = new ThingUID(THING_TYPE_SMOKE, bridgeUID, serialNumber);
            labelName = "ThermoWorks Smoke (" + deviceDto.getName() + ")";
        } else {
            deviceUID = new ThingUID(THING_TYPE_GENERIC, bridgeUID, serialNumber);
            labelName = "ThermoWorks Device (" + deviceDto.getName() + ")";
        }

        Map<String, Object> properties = new HashMap<>();
        properties.put(CONFIG_SERIALNUMBER, serialNumber);
        properties.put(PROPERTY_MODEL, model);
        properties.put(PROPERTY_FIRMWARE_VERSION, firmwareVersion);

        DiscoveryResult result = DiscoveryResultBuilder.create(deviceUID).withLabel(labelName)
                .withProperties(properties).withBridge(bridgeUID).withRepresentationProperty("serialNumber").build();

        thingDiscovered(result);
    }

    @Override
    protected void startScan() {
        logger.debug("Discovery: Manual discovery scan requested for ThermoWorks Cloud devices.");
        String devices = bridgeHandler.fetchCloudData(false);
        if (devices != null) {
            ThermoworksResponseDTO response = gson.fromJson(devices, ThermoworksResponseDTO.class);
            if (response == null || response.getDevices() == null)
                return;
            for (ThermoworksDeviceDTO device : response.getDevices()) {
                if (device != null) {
                    discoverDevice(bridgeHandler.getThing().getUID(), device);
                }
            }
        }
    }
}
