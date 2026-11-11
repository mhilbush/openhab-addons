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

import java.util.Set;

import org.eclipse.jdt.annotation.NonNullByDefault;
import org.openhab.core.thing.ThingTypeUID;

/**
 *
 * ThermoworksBindingConstants
 *
 * @author Mark Hilbush - Initial contribution
 *
 */
@NonNullByDefault
public class ThermoworksBindingConstants {

    public static final String BINDING_ID = "thermoworks";

    // Thing Configuration and Properties
    // Bridge
    public static final String CONFIG_REFRESH_INTERVAL_SECONDS = "refreshIntervalSeconds";
    public static final String CONFIG_API_KEY = "apiKey";
    // Devices
    public static final String CONFIG_SERIALNUMBER = "serialNumber";
    public static final String PROPERTY_MODEL = "model";
    public static final String PROPERTY_FIRMWARE_VERSION = "firmwareVersion";

    public static final Set<String> MODELS_RFX_GATEWAY = Set.of("RFX-GATEWAY", "RFX_GATEWAY", "RFX GATEWAY");
    public static final Set<String> MODELS_RFX_MEAT = Set.of("RFX-MEAT", "RFX_MEAT", "RFX MEAT");
    public static final Set<String> MODELS_SIGNALS = Set.of("SIGNALS");
    public static final Set<String> MODELS_SMOKE = Set.of("SMOKE");

    // Thing Types
    public static final ThingTypeUID THING_TYPE_CLOUD_BRIDGE = new ThingTypeUID(BINDING_ID, "account");
    public static final ThingTypeUID THING_TYPE_SIGNALS = new ThingTypeUID(BINDING_ID, "signals");
    public static final ThingTypeUID THING_TYPE_SMOKE = new ThingTypeUID(BINDING_ID, "smoke");
    public static final ThingTypeUID THING_TYPE_RFX_GATEWAY = new ThingTypeUID(BINDING_ID, "rfx-gateway");
    public static final ThingTypeUID THING_TYPE_RFX_MEAT_PROBE = new ThingTypeUID(BINDING_ID, "rfx-meat");
    public static final ThingTypeUID THING_TYPE_GENERIC = new ThingTypeUID(BINDING_ID, "generic");

    public static final Set<ThingTypeUID> SUPPORTED_THING_TYPES = Set.of(THING_TYPE_CLOUD_BRIDGE, THING_TYPE_SIGNALS,
            THING_TYPE_SMOKE, THING_TYPE_RFX_GATEWAY, THING_TYPE_RFX_MEAT_PROBE, THING_TYPE_GENERIC);

    // Channel IDs
    public static final String CHANNEL_BATTERYLEVEL = "battery-level";
    public static final String CHANNEL_BATTERY_STATE = "battery-state";
    public static final String CHANNEL_RSSI = "rssi";
    public static final String CHANNEL_ONLINE = "online";
    public static final String CHANNEL_LAST_UPDATED = "last-updated";

    public static final String CHANNEL_AMBIENT_TEMP = "ambient-temperature";

    public static final String CHANNEL_PROBE_PREFIX = "probe";

    public static final String CHANNEL_PROBE_TEMP_SUFFIX = "-temperature";
    public static final String CHANNEL_PROBE_LABEL_SUFFIX = "-label";
    public static final String CHANNEL_PROBE_ALARM_SUFFIX = "-alarm";

    public static final String CHANNEL_PROBE_ALARM_HIGH_ENABLED_SUFFIX = "-alarm-high-enabled";
    public static final String CHANNEL_PROBE_ALARM_HIGH_TEMP_SUFFIX = "-alarm-high-temperature";
    public static final String CHANNEL_PROBE_ALARM_HIGH_ALARM_SUFFIX = "-alarm-high-alarm";

    public static final String CHANNEL_PROBE_ALARM_LOW_ENABLED_SUFFIX = "-alarm-low-enabled";
    public static final String CHANNEL_PROBE_ALARM_LOW_TEMP_SUFFIX = "-alarm-low-temperature";
    public static final String CHANNEL_PROBE_ALARM_LOW_ALARM_SUFFIX = "-alarm-low-alarm";
}
