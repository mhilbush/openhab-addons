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
package org.openhab.binding.thermoworks.internal.dto;

import java.util.List;

import com.google.gson.annotations.SerializedName;

/**
 *
 * ThermoworksResponseDTO
 *
 * @author Mark Hilbush - Initial contribution
 */
public class ThermoworksResponseDTO {

    @SerializedName("generatedAt")
    private String generatedAt;

    @SerializedName("devices")
    private List<ThermoworksDeviceDTO> devices;

    public String getGeneratedAt() {
        return generatedAt;
    }

    public void setGeneratedAt(String generatedAt) {
        this.generatedAt = generatedAt;
    }

    public List<ThermoworksDeviceDTO> getDevices() {
        return devices;
    }

    public void setDevices(List<ThermoworksDeviceDTO> devices) {
        this.devices = devices;
    }
}
