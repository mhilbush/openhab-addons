/**
 * Copyright (c) 2010-2024 Contributors to the openHAB project
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
package org.openhab.binding.bhyve.internal.dto;

import com.google.gson.annotations.SerializedName;

/**
 * The {@link EventLowBatteryDTO} is responsible for
 *
 * @author Mark Hilbush - Initial contribution
 */
public class EventLowBatteryDTO {

    @SerializedName("event")
    public String event;

    @SerializedName("device_id")
    public String deviceId;

    @SerializedName("percent_remaining")
    public Integer percentRemaining;

    @SerializedName("timestamp")
    public String timestamp;
}
