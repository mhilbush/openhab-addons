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

import org.eclipse.jdt.annotation.NonNull;

import com.google.gson.annotations.SerializedName;

/**
 *
 * ThermoworksDeviceDTO
 *
 * @author Mark Hilbush - Initial contribution
 */
public class ThermoworksDeviceDTO {

    @SerializedName("serial")
    private String serialNumber;

    @SerializedName("label")
    private String name;

    @SerializedName("model")
    private String model;

    @SerializedName("firmware")
    private String firmwareVersion;

    @SerializedName("battery")
    private Integer batteryLevel;

    @SerializedName("batteryState")
    private String batteryState;

    @SerializedName("wifiSignal")
    private Integer wifiSignal;

    @SerializedName("gatewaySignal")
    private Integer gatewaySignal;

    @SerializedName("online")
    private Boolean isOnline;

    @SerializedName("lastSeen")
    private String lastUpdated;

    @SerializedName(value = "channels", alternate = { "probes" })
    private List<ThermoworksProbeDTO> probes;

    public ThermoworksDeviceDTO() {
    }

    public String getSerialNumber() {
        return serialNumber != null ? serialNumber.replace(":", "").toLowerCase() : null;
    }

    public String getSerialNumberRaw() {
        return serialNumber;
    }

    public void setSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getModel() {
        return model;
    }

    public void setModel(String model) {
        this.model = model;
    }

    public String getFirmwareVersion() {
        return firmwareVersion;
    }

    public void setFirmwareVersion(String firmwareVersion) {
        this.firmwareVersion = firmwareVersion;
    }

    public Integer getBatteryLevel() {
        return batteryLevel;
    }

    public void setBatteryLevel(Integer batteryLevel) {
        this.batteryLevel = batteryLevel;
    }

    public String getBatteryState() {
        return batteryState;
    }

    public void setBatteryState(String batteryState) {
        this.batteryState = batteryState;
    }

    public Integer getRssi() {
        if (wifiSignal != null)
            return wifiSignal;
        return gatewaySignal;
    }

    public @NonNull Boolean getIsOnline() {
        return isOnline == null ? Boolean.FALSE : isOnline;
    }

    public void setIsOnline(Boolean isOnline) {
        this.isOnline = isOnline;
    }

    public String getLastUpdated() {
        return lastUpdated;
    }

    public void setLastUpdated(String lastUpdated) {
        this.lastUpdated = lastUpdated;
    }

    public List<ThermoworksProbeDTO> getProbes() {
        return probes;
    }

    public void setProbes(List<ThermoworksProbeDTO> probes) {
        this.probes = probes;
    }
}
